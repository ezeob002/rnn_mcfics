import nest_asyncio
import pyshark
import os
from collections import defaultdict
from scapy.all import rdpcap

from grammar_ics.utils.custom_dict import TwoWayDict

def process_packet(pkt, server_port):
	"""Assumption that packet has tcp layer, 
	using serverport number to distinguish between response and request"""
	try:
		sor_port = pkt.sport
	except Exception as e:
		print("The source number cannot be retrieved")
		return None, None

	try:
		raw_val = pkt.load
	except:
		print("The raw pkt could not be gotten")
		return None, None

	if sor_port == server_port:
		return raw_val, 'res'
	return raw_val, 'req'




def process_pcap(pcapdir, server_port):
	nest_asyncio.apply()
	training_data, input_al, output_al = [], set(), set()
	mapper = {}
	pcaps_list = os.listdir(pcapdir)
	start = 1
	for fname in pcaps_list:
		if fname.endswith('.pcap'):
			pcap_file = os.path.join(pcapdir, fname)
			print("Working on {}".format(pcap_file))
			pyshark_pcap = pyshark.FileCapture(pcap_file)
			streams = defaultdict(list)
			count = 0
			for pkt in pyshark_pcap:
				if("TCP" in str(pkt.layers)):
					streams[pkt.tcp.stream].append(count)
				count += 1


			pcap = rdpcap(pcap_file)

			for p in pcap:
				try:
					val = p.load
				except:
					continue
				if val not in mapper:
					mapper[val] = str(start)
					start += 1

			for i in streams:
				dataI = []
				dataO = []
				for pktno in streams[i]:
					fcn_msg, pktType = process_packet(pcap[pktno], server_port)
					if fcn_msg is not None:
						fcn_msg = mapper[fcn_msg]
						if (pktType == 'req'):
							input_al.add(fcn_msg)
							dataI.append(fcn_msg)
						elif (pktType == 'res'):
							output_al.add(fcn_msg)
							dataO.append(fcn_msg)
				if(len(dataI)==0 and len(dataO)==0):
					continue
				if(len(dataI) == 0):
					dataI.append("NO_REQUEST")
					input_al.add("NO_REQUEST")
				if (len(dataO) == 0):
					dataO.append("NO_RESPOND")
					output_al.add("NO_RESPOND")

				training_data.append((tuple(dataI), dataO[-1]))

	mapper = TwoWayDict(mapper)
	return training_data, list(input_al), list(output_al), mapper


