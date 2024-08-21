from collections import defaultdict

from grammar_ics.fuzzers import IFuzzer
from grammar_ics.utils.exception import GICSError
from grammar_ics.session import Session
from grammar_ics.utils.process import process_pcap



class RNNFuzzer(IFuzzer):

	mapper = None
	input_al = None
	output_al = None
	init_corpus = None
	training_data = None
	server_port_num = None
	name = 'RNNFuzzer'


	@staticmethod
	def initialize(*args, **kwargs):
		if 'name' in kwargs:
			RNNFuzzer.name = kwargs['name']
		if 'pcap' not in kwargs and 'port' not in kwargs:
			raise GICSError(" Pcap folder or server port number must be passed in as an argument")
		RNNFuzzer.pcap = kwargs['pcap']
		RNNFuzzer.server_port_num = kwargs['Fport']
		RNNFuzzer.training_data, RNNFuzzer.input_al, RNNFuzzer.output_al, RNNFuzzer.mapper = process_pcap(RNNFuzzer.pcap, RNNFuzzer.server_port_num)

	@staticmethod
	def get_training_data():
		return RNNFuzzer.training_data

	@staticmethod
	def get_input_al():
		return RNNFuzzer.input_al

	@staticmethod
	def get_ouput_al():
		return RNNFuzzer.output_al

	@staticmethod
	def get_mapper():
		return RNNFuzzer.mapper

	@staticmethod
	def get_corpus():
		try:
			return list(RNNFuzzer.mapper.keys())
		except:
			return None
