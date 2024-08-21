import os
import time
import toml
from typing import Any
import json
import pickle


from grammar_ics.targets.target import Target
from grammar_ics.utils.state import STATE
from grammar_ics.utils import constants
from grammar_ics.utils.decorators import GICSLogger
from grammar_ics.utils.coverage_log import CoverageReport

#@GICSLogger
class Project(object):

	def __init__(self, project_dir: str):
		super(Project, self).__init__()
		self.project_dir = project_dir
		self.corpus = None
		self.corpus_dir = os.path.join(project_dir, constants.CORPUS_DIR)
		self.model_dir = os.path.join(project_dir, constants.MODEL_DIR)
		self.rnn_dir = os.path.join(project_dir, constants.TRAINED_DIR)
		self.rnn_performance_dir = os.path.join(project_dir, constants.RESULT_DIR)
		self.crash_dir = os.path.join(project_dir, constants.CRASH_DIR, time.strftime("%Y%m%d_%H%M%S_crash"))
		self.unique_crash_dir = os.path.join(self.crash_dir, constants.CRASH_DIR_UNIQUE)
		self.suspect_dir = os.path.join(self.crash_dir, constants.SUSPECT_DIR)
		self.coverage_dir = os.path.join(project_dir, constants.COVERAGE)
		self.debug_dir = os.path.join(project_dir, constants.DEBUG_DIR)
		self.config_file = os.path.join(project_dir, constants.CONFIG_FILE)
		self.state_file = os.path.join(project_dir, constants.STATE_FILE)
		self.run_json = os.path.join(self.debug_dir, 'run.json')
		self.coverage_csv = os.path.join(self.coverage_dir, 'coverage_report.csv')
		self.logfile_name     = None
		self.max_payload_size = 0
		self.payload_filter = None
		self.state = STATE(None,0,0,1)
		self.check_and_create_subfolders()
		self.prepare_report_csv()

	def prepare_report_csv(self):
		CoverageReport.prepare_csv(self.coverage_csv, constants.HEADER)

	def save_state(self):
		open(self.state_file, "w").write(toml.dumps(self.state.convert_state_to_dict()))
		return True

	def check_and_create_subfolders(self):

		if not os.path.exists(self.project_dir):
			#self._logger.warn("Project directory '%s' does not exist." % self.project_dir)
			os.mkdir(self.project_dir)
		if not os.path.exists(self.debug_dir):
			os.mkdir(self.debug_dir)
		hist_debug_file = os.path.join(self.debug_dir, constants.HISTORY)
		if os.path.exists(hist_debug_file):
			#self._logger.debug("Deleting old Debug file: {}".format(hist_debug_file))
			os.remove(hist_debug_file)

		if not os.path.exists(self.coverage_dir):
			os.makedirs(self.coverage_dir,exist_ok = True)

		if not os.path.exists(self.crash_dir):
			os.makedirs(self.crash_dir, exist_ok = True)

		if not os.path.exists(self.corpus_dir):
			os.makedirs(self.corpus_dir, exist_ok = True)

		if not os.path.exists(self.model_dir):
			os.makedirs(self.model_dir, exist_ok = True)

		if not os.path.exists(self.rnn_dir):
			os.makedirs(self.rnn_dir, exist_ok = True)

		if not os.path.exists(self.rnn_performance_dir):
			os.makedirs(self.rnn_performance_dir, exist_ok = True)

		if not os.path.exists(self.unique_crash_dir):
			os.makedirs(self.unique_crash_dir, exist_ok = True)

		if not os.path.exists(self.suspect_dir):
			os.makedirs(self.suspect_dir, exist_ok = True)

		return True


	def write_array(self, data, file_name):
		with open(file_name, 'wb') as f:
			pickle.dump(data, f)

	def read_data(self, file_name):
		with open(file_name, 'rb') as f:
			data = pickle.load(f)
		return data

	def get_file_name_with_time(self,suffix_name):
		return time.strftime("%Y%m%d_%H%M%S_{}".format(suffix_name))