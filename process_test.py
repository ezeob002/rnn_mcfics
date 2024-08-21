import torch
import torch.optim as optim
from random import shuffle

from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWordEqOracle, RandomWalkEqOracle, StatePrefixEqOracle
from aalpy.utils import load_automaton_from_file



from grammar_ics.models.RNN import get_model, Optimization
from grammar_ics.utils.process import process_pcap


def printable_timestamp(ts, resol):
	ts_sec = ts // resol
	ts_subsec = ts % resol
	ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
	return '{}.{}'.format(ts_sec_str, ts_subsec)

data = "./data"
server_port = 20000
training_data, input_al, output_al, mapper = process_pcap(data, server_port)
#print(mapper)
print(len(training_data), training_data)
