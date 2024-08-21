import os
import argparse
import torch
from numpy import random
import random as stdrandom
from collections import defaultdict

from grammar_ics.targets.target import Target
from grammar_ics.fuzzers.ifuzzer import IFuzzer
from grammar_ics.restarters.irestarter import IRestarter
from grammar_ics.session import Session

from grammar_ics.utils import constants
from grammar_ics.utils.decorators import GICSLogger
# from grammar.fuzzer import FMIFuzzer
from grammar_ics.project import Project
from grammar_ics.RNN_learner import RNNDriver
from grammar_ics.network.tcp_socket_connection import TCPSocketConnection
from grammar_ics.mutation.afl_mutation import AFL_MUTATION
from grammar_ics.mutation.afl_mutation import MutationEingine
from grammar_ics.mutation.base_mutation import Mutation
from grammar_ics.datasets.automata_datasets import AutomatonDataset


logo = """
 Recurrent Neural Network Coverage fuzzing by Uchenna Ezeobi
"""

@GICSLogger
class RNNCF(object):

	def __init__(self):
		self._init_argparser()
		self.args = self._parse_args()
		device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
		input_al, output_al = self.args.fuzz_protocol.get_input_al() ,self.args.fuzz_protocol.get_ouput_al()
		print(input_al)
		print("=========")
		print(output_al)
		data_handler = AutomatonDataset(input_al, output_al, self.args.bsize, device=device)
		input_dim = len(input_al)
		output_dim = len(output_al)
		hidden_dim = self.args.hidden_dim
		layer_dim = self.args.layer_dim
		dropout = self.args.dropout
		activation_fun = self.args.activation_func
		learning_rate=self.args.learning_rate
		weight_decay=self.args.weight_decay
		early_stop=self.args.early_stop
		n_epochs=self.args.epoch
		exp_name = self.args.name
		model_type = self.args.model_type
		training_data = self.args.fuzz_protocol.get_training_data()
		model_params = {'input_dim': input_dim,
						'hidden_dim': hidden_dim,
						'layer_dim': layer_dim,
						'output_dim': output_dim,
						'nonlinearity': activation_fun,
						'dropout_prob': dropout,
						'data_handler': data_handler,
						'device': device}

		self.learner = RNNDriver(data_handler, input_al, output_al, training_data,model_params, 
								 model_type, exp_name, learning_rate, weight_decay, early_stop, n_epochs)
		connection = TCPSocketConnection(
						host=self.args.host,
						port=self.args.port,
						send_timeout=self.args.send_timeout,
						recv_timeout=self.args.recv_timeout
						)
		self.target = Target(
						connection=connection)
		self.project = Project(self.args.project)
		self.mutator = defaultdict(lambda: defaultdict(Mutation))

		# Know what to do with the RNN
		self.session = Session(
						restart_sleep_time=self.args.restart_sleep_time,
						target=self.target,
						restarter=self.restart_module,
						fuzz_protocol=self.args.fuzz_protocol,
						learner=self.learner,
						mutator=self.mutator,
						project=self.project,
						seed=self.args.seed,
						time_budget=self.args.time_budget,
						debug=self.args.debug,
						dump_shm=self.args.dump_shm,
						deterministic=False
		)

	def _init_argparser(self):
		self.parser = argparse.ArgumentParser(
			description=logo,
			formatter_class=argparse.RawTextHelpFormatter
			)
		self.parser.add_argument("-pj", "--project", type=str, help="project to create")
		self.parser.add_argument("-hs", "--host", type=str, help="target host")
		self.parser.add_argument("-p", "--port", type=int, help="fuzzing target port")
		self.parser.add_argument("-fp", "--Fport", type=int, help="file processing target port")
		conn_grp = self.parser.add_argument_group('Connection options')
		conn_grp.add_argument("-st", "--send_timeout", dest="send_timeout", type=float, default=1.0, help="send() timeout")
		conn_grp.add_argument("-rt", "--recv_timeout", dest="recv_timeout", type=float, default=1.0, help="recv() timeout")

		fuzzers = [fuzzer_class.name for fuzzer_class in IFuzzer.__subclasses__()]

		fuzz_grp = self.parser.add_argument_group('Fuzzer options')
		fuzz_grp.add_argument("--fuzzer", dest="fuzz_protocol", help='application layer fuzzer', required=True, choices=fuzzers)
		fuzz_grp.add_argument('--name', dest='name', type=str, help='Name of the protocol you are fuzzing')
		fuzz_grp.add_argument('--debug', action='store_true', help='enable debug.csv')
		fuzz_grp.add_argument('--pcap', dest='pcap', type=str, required=True, help='folder containing the pcap files')
		fuzz_grp.add_argument('--seed', dest='seed', type=int, default=0, help='prng seed')
		fuzz_grp.add_argument('--budget', dest='time_budget', type=float, default=0.0, help='time budget')
		fuzz_grp.add_argument('--shm_id', dest='shm_id', type=str, default="", help='custom shared memory id overwrite')
		fuzz_grp.add_argument('--dump_shm', dest='dump_shm', action='store_true', default=False, help='dump shm after run')

		rnn_model_grp = self.parser.add_argument_group('Recurrent Neural Network options')
		rnn_model_grp.add_argument('--bsize', dest='bsize', type=int, default=32, help='Training Batch size')
		rnn_model_grp.add_argument('--nstep', dest='nstep', type=int, default=1000, help='Random Walk Eq Oracle')
		rnn_model_grp.add_argument('--epoch', dest='epoch', type=int, default=500, help='Training Epoch')
		rnn_model_grp.add_argument('--mt', dest='model_type', type=str, default='gru', help='Model type, options [GRU, LSTM, RNN]')
		rnn_model_grp.add_argument('--af', dest='activation_func', type=str, default='relu', help='Neural Network activation Func')
		rnn_model_grp.add_argument('--hd', dest='hidden_dim', type=int, default=40, help='Hidden dimensions for DL models')
		rnn_model_grp.add_argument('--ld', dest='layer_dim', type=int, default=40, help='Layer dimensions for DL models')
		rnn_model_grp.add_argument('--do', dest='dropout', type=float, default=0.1, help='Dropout unit')
		rnn_model_grp.add_argument('--lr', dest='learning_rate', type=float, default=0.0005, help='Learning Rate')
		rnn_model_grp.add_argument('--wd', dest='weight_decay', type=float, default=1e-6, help='Weight Decay')
		rnn_model_grp.add_argument('--es', dest='early_stop', type=bool, default=False, help='Early Stop')
		#rnn_model_grp.add_argument('--dump_shm', dest='dump_shm', action='store_true', default=False, help='dump shm after run')

		restarters_grp = self.parser.add_argument_group('Restart options')
		restarters_help = 'Restarter Modules:\n'
		for restarter in IRestarter.__subclasses__():
			restarters_help += '  {}: {}\n'.format(restarter.name(), restarter.help())
		restarters_grp.add_argument('--restart', nargs='+', default=[], metavar=('module_name', 'args'),
									help=restarters_help)
		restarters_grp.add_argument("--restart-sleep", dest="restart_sleep_time", type=int, default=5,
									help='Set sleep seconds after a crash before continue (Default 5)')


	def _parse_args(self):
		args = self.parser.parse_args()
		if args.shm_id != "":
			constants.SHM_OVERWRITE = args.shm_id

		random.seed(args.seed)
		stdrandom.seed(args.seed)
		args.fuzz_protocol = [icl for icl in IFuzzer.__subclasses__() if icl.name == args.fuzz_protocol][0]
		args.fuzz_protocol.initialize(**args.__dict__)
		self.restart_module = None
		if len(args.restart) > 0:
			try:
				restart_module = [mod for mod in IRestarter.__subclasses__() if mod.name() == args.restart[0]][0]
				restart_args = args.restart[1:]
				self.restart_module = restart_module(*restart_args)
			except IndexError:
				print(f"The restarter module {args.restart[0]} does not exist!")
				exit(1)
		return args

	def run(self):
		self.session.start()


def main():
	rnn_fuzzer = RNNCF()
	try:
		rnn_fuzzer.run()
	except:
		try:
			rnn_fuzzer.session.restarter.kill()
		except:
			pass

if __name__ == "__main__":
	main()