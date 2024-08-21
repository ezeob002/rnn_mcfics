import time
import os
from typing import List, TYPE_CHECKING, Any, Tuple, Optional

from grammar_ics.utils.constants import DEFAULT_MAX_RECV
from grammar_ics.utils import exception
from grammar_ics.coverage import shm
from grammar_ics.utils.server_status import SUT_STATUS
from grammar_ics.utils.helper import critical_signals_nix

if TYPE_CHECKING:
	from grammar_ics.session import Session

class TestCase(object):
	def __init__(self, id: str, session: 'Session', sequence: list):
		self.id = id
		self.session = session
		self.sequence = sequence
		self.needed_restart = False
		self.done = False
		self.last_cov = None

	@property
	def coverage_snapshot(self):
		mem = shm.get()
		mem.acquire()
		self.last_cov = mem.directed_branch_coverage()
		buf = mem.buf
		mem.release()
		return self.last_cov, buf

	def determine_critical_nature(self, err_code):
		if err_code and (err_code in critical_signals_nix or os.WIFSIGNALED(err_code)):
			return True
		return False


	def run(self, new_payload, is_rec=False, s_time=0.00001) -> Tuple[Optional[Exception], bool, Optional[SUT_STATUS]]:
		status = SUT_STATUS.NO_CRASH
		try:
			self.session.restarter.restart(planned=True)
			#time.sleep(s_time)
			self.open_fuzzing_target()
			for payload in self.sequence:
				self.transmit(payload, receive=is_rec)

			if not self.session.restarter.healthy():
				return None, False, SUT_STATUS.CRASH_BEFORE_SEND
			#print("Sending final {}".format(new_payload))
			self.transmit(new_payload, receive=True)
			time.sleep(s_time)
			if not self.session.restarter.healthy():
				self.session.restarter.p.poll()
				code = self.session.restarter.p.returncode
				is_critical = self.determine_crtitical_nature(code)
				if is_critical:
					status = SUT_STATUS.CRASH_AFTER_SEND
				else:
					status = SUT_STATUS.DISCONNECTED

			try:
				self.session.target.close()
			except Exception:
				pass

			self.done = True
			return None, True, status

		except Exception as e:
			return e, False, status
		
	def run_seq(self):
		try:
			self.session.restarter.restart(planned=True)
			self.open_fuzzing_target()
			for payload in self.sequence:
				self.transmit(payload, receive=False)
			if not self.session.restarter.healthy():
				return False
		except:
			return False
		return True

	def open_fuzzing_target(self):
		target = self.session.target
		try:
			target.open()
		except (exception.GICSTargetConnectionFailedError, Exception):
			#print("Trying to redo it")
			for i in range(0, 4):
				try:
					time.sleep(0.000001)
					target.open()
				except Exception:
					if i == 3:
						#print("Got to the final version") 
						raise exception.GICSTargetConnectionFailedError()

	def transmit(self, data: bytes, receive=False, relax=False):
		try:
			#print("Sending {}".format(data))
			self.session.target.send(data)
		except Exception as e:
			if not relax:
				raise e
		if receive:
			try:
				last_recv = self.session.target.recv(DEFAULT_MAX_RECV)
				#print("Receiving {}".format(last_recv))
			except Exception as e:
				raise e

	def __repr__(self):
		return f'{vars(self)}'
