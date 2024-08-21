from grammar_ics.utils.constants import DEFAULT_MAX_RECV


class Target(object):
	"""docstring for Target"""
	def __init__(self, connection): #TODO: double check that connection is an instance of TargetConnection
		super(Target, self).__init__()
		self.target_connection = connection

	def close(self):
		self.target_connection.close()

	def open(self):
		self.target_connection.open()

	def recv(self, max_bytes: int= DEFAULT_MAX_RECV):
		return self.target_connection.recv(max_bytes=max_bytes)

	def recv_all(self, max_bytes: int = DEFAULT_MAX_RECV):
		return self.target_connection.recv_all(max_bytes=max_bytes)

	def send(self, data):
		return self.target_connection.send(data=data)
