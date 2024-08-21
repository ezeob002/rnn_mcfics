import torch
import torch.optim as optim
from random import shuffle

from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWordEqOracle, RandomWalkEqOracle
from aalpy.utils import load_automaton_from_file, save_automaton_to_file

from grammar_ics.models.RNN import get_model, Optimization
from grammar_ics.state_machine_extraction.util import conformance_test, RNNSul
from grammar_ics.utils.process import process_pcap

g_automata_method = { 'det': 'mealy', 'non_det': 'onfsm','stoch': 'smm'}

class RNNDriver(object):
	def __init__(self, data_handler, input_al, output_al, training_data, model_params, 
		model_type, exp_name, learning_rate=0.0005, weight_decay=1e-6, early_stop=False, n_epochs=500):
		
		self.data_handler = data_handler
		self.input_al = input_al
		self.output_al = output_al
		self.training_data = training_data
		self.model_params = model_params
		self.model_type = model_type
		self.exp_name = exp_name
		self.model = get_model(model_type, model_params)
		self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
		self.learned_model = None
		self.automata_method = 'det'
		self.learning_rate = learning_rate
		self.weight_decay = weight_decay
		self.early_stop = early_stop
		self.n_epochs = n_epochs

	def train(self, model_dir):
		num_training_samples = round(0.7 * len(self.training_data))
		training_data, validation_data = self.training_data[:num_training_samples], self.training_data[num_training_samples:]
		# print(len(training_data), len(validation_data))
		# exit()
		train, val = self.data_handler.create_dataset(training_data), self.data_handler.create_dataset(validation_data)
		optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate, weight_decay=self.weight_decay)
		opt = Optimization(model=self.model, optimizer=optimizer, device=self.device)
		# process_hs_fun = 'flatten_lstm' if self.model_type == 'lstm' else 'flatten'
		opt.train(train, val, n_epochs=self.n_epochs, exp_name=self.exp_name, early_stop=self.early_stop, save=True, load=True,project_dir=model_dir)
	
	def extract_state_machine(self, num_walk=10, max_walk_len=10):
		torch.no_grad()
		self.sul = RNNSul(self.model)
		# eq_oracle = RandomWordEqOracle(self.input_al, self.sul, num_walks=num_walk, max_walk_len=num_walk)
		eq_oracle = RandomWalkEqOracle(self.input_al, self.sul, num_steps=max_walk_len)
		self.learned_model = run_Lstar(self.input_al, self.sul, eq_oracle, 'mealy', cache_and_non_det_check=True, max_learning_rounds=3)

	def visualize(self):
		if self.learned_model is None: return
		self.learned_model.visualize()

	def save_automata(self, file_path):
		if self.learned_model is None: return
		save_automaton_to_file(self.learned_model, file_path)

	def load_automata(self, file_path):
		self.learned_model = load_automaton_from_file(file_path, g_automata_method[self.automata_method])
		return self.learned_model

	def get_states_transition_sequence(self):
		if self.learned_model is None:
			raise Exception("You need a trained model to call this function")
		self.transitions = {self.learned_model.initial_state.state_id: None}
		for state in self.learned_model.states:
			if state is not self.learned_model.initial_state:
				self.transitions[state.state_id] = self.learned_model.get_shortest_path(self.learned_model.initial_state, state)
		return self.transitions