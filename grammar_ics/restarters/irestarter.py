import abc

class IRestarter(object, metaclass=abc.ABCMeta):
	@abc.abstractmethod
	def __init__(self, *args, **kwargs):
		pass

	@staticmethod
	@abc.abstractmethod
	def name() -> str:
		pass

	@staticmethod
	@abc.abstractmethod
	def help():
		pass

	@abc.abstractmethod
	def restart(self, *args, **kwargs) -> str or None:
		pass

	@abc.abstractmethod
	def kill(self):
		pass

	@abc.abstractmethod
	def healthy(self) -> bool:
		pass