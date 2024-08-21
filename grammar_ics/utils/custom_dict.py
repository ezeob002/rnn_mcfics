class TwoWayDict(dict):
	def __init__(self, my_dict):
		dict.__init__(self, my_dict)
		self.rev_dict = {v : k for k,v in my_dict.items()}

	def __setitem__(self, key, value):
		dict.__setitem__(self, key, value)
		self.rev_dict.__setitem__(value, key)

	def __delitem__(self, key):
		dict.__delitem__(self, key)
		self.rev_dict.__delitem__(self[key])