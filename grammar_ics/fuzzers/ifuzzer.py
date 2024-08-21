import abc
# from typing import Dict

class IFuzzer(abc.ABC):
	name = 'Implement'
	init_corpus = None

	@staticmethod
	@abc.abstractmethod
	def get_corpus():
		 raise NotImplementedError("Subclasses should implement this!")


	@staticmethod
	@abc.abstractmethod
	def initialize(*args, **kwargs) -> None:
		raise NotImplementedError("Subclasses should implement this!")