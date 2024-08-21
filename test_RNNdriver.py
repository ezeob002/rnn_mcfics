from grammar_ics.RNN_learner import RNNDriver
from grammar_ics.utils.process import process_pcap
import torch
from grammar_ics.datasets.automata_datasets import AutomatonDataset


data = './data/iec104'
server_port = 2404
batch_size = 32
dir_path = './trained_rnns'
training_data, input_al, output_al, mapper = process_pcap(data, server_port)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

data_handler = AutomatonDataset(input_al, output_al, batch_size, device=device)
model_type = 'gru'
activation_fun = 'relu'  # note that activation_fun value is irrelevant for GRU and LSTM
input_dim = len(input_al)
output_dim = len(output_al)
hidden_dim = 40
layer_dim = 2
dropout = 0.1  # 0.1 if layer_dim > 1 else 0
n_epochs = 500
# optimizer = optim.Adam
learning_rate = 0.0005
weight_decay = 1e-6
early_stop = False  # Stop training if loss is smaller than small threshold for few epochs
exp_name = 'iec104'

model_params = {'input_dim': input_dim,
                'hidden_dim': hidden_dim,
                'layer_dim': layer_dim,
                'output_dim': output_dim,
                'nonlinearity': activation_fun,
                'dropout_prob': dropout,
                'data_handler': data_handler,
                'device': device}
print(len(training_data))
# exit()
driver = RNNDriver(data_handler, input_al, output_al, training_data,model_params, model_type, exp_name)

driver.train(dir_path)
driver.extract_state_machine()
driver.visualize()
result = "my_result"
driver.save_automata(result)
result = "my_result.dot"
automata = driver.load_automata(result)
print(automata)