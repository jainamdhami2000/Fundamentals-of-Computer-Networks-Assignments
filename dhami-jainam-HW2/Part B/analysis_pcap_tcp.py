import dpkt

SENDER = "130.245.145.12"
RECEIVER = "128.208.2.198"

class Packet:

	def __init__(self, packet):

		self.time_stamp = packet[0]
		self.buffer  = packet[1]
		self.packet_size = len(packet[1])

	isValid = True

	def parse(self):
		try:
			self.src_ip = str(int.from_bytes(self.buffer[26:27], byteorder='big')) + "." + str(int.from_bytes(self.buffer[27:28], byteorder='big')) + "." + str(int.from_bytes(self.buffer[28:29], byteorder='big')) + "." + str(int.from_bytes(self.buffer[29:30], byteorder='big'))
			self.dest_ip = str(int.from_bytes(self.buffer[30:31], byteorder='big')) + "." + str(int.from_bytes(self.buffer[31:32], byteorder='big')) + "." + str(int.from_bytes(self.buffer[32:33], byteorder='big')) + "." + str(int.from_bytes(self.buffer[33:34], byteorder='big'))
			self.src_port = int.from_bytes(self.buffer[34:36], byteorder='big')
			self.dest_port = int.from_bytes(self.buffer[36:38], byteorder='big')
			self.seq_num = int.from_bytes(self.buffer[38:42], byteorder='big')
			self.ack_num = int.from_bytes(self.buffer[42:46], byteorder='big')
			len_head = int.from_bytes(self.buffer[46:47], byteorder='big')
			self.len_head = 4*(len_head>>4)
			flags = int.from_bytes(self.buffer[47:48], byteorder='big')
			self.fin = flags&1
			flags = flags>>1
			self.syn = flags&1
			flags = flags>>1
			self.rst = flags&1
			flags = flags>>1
			self.psh = flags&1
			flags = flags>>1
			self.ack = flags&1
			flags = flags>>1
			self.urg = flags&1
			self.window_size = int.from_bytes(self.buffer[48:50], byteorder='big')
			self.checksum = int.from_bytes(self.buffer[50:52], byteorder='big')
			self.urgent = int.from_bytes(self.buffer[52:54], byteorder='big')
			self.payload = len(self.buffer[34+self.len_head:])
			self.mss = int.from_bytes(self.buffer[56:58], byteorder='big')
		except:
			self.isValid = False

def PCAP_File_Reader(pcap):
	packet_list = []
	packet_bytes = pcap.readpkts()
	for packet_byte in packet_bytes:
		pkt = Packet(packet_byte)
		pkt.parse()
		if pkt.isValid:	
			packet_list.append(pkt) #Filtering out packets which have all the fields and a proper length
	return packet_list

def index_after_threeway_handshake(flow):
	index = 0
	for packet in flow:
		index += 1
		if packet.syn == 0 and packet.ack == 1:
			break
	return index

def Flow_Initializer(packet_list):
	flows = []
	# Create Flowings / Connections
	for packet in packet_list:
		if packet.syn == 1 and packet.ack == 0:
			flow = {
					"src_port" : packet.src_port,
					"dest_port" : packet.dest_port,
					"packets" : []
				}
			flows.append(flow)
	for packet in packet_list:
		for flow in flows:
			if (((packet.src_port == flow["src_port"]) and (packet.dest_port == flow["dest_port"])) or ((packet.src_port == flow["dest_port"]) and (packet.dest_port == flow["src_port"]))):
				flow["packets"].append(packet)
	return flows

def LossCalculation(flow_packets):
	sequence_dict = {}
	dict_ack = {}
	for packet in flow_packets:
		if packet.src_ip == SENDER and packet.dest_ip == RECEIVER:
			sequence_dict[packet.seq_num] = sequence_dict.get(packet.seq_num,0) + 1
		elif packet.src_ip == RECEIVER and packet.dest_ip == SENDER:
			dict_ack[packet.ack_num] = dict_ack.get(packet.ack_num,0) + 1
	loss = 0
	Triple_Duplicate_ack = 0
	for key in sequence_dict.keys():
		if key in sequence_dict:
			loss += sequence_dict[key]-1
			if key in dict_ack and dict_ack[key]>2:
				Triple_Duplicate_ack += sequence_dict[key]-1
			else:
				Triple_Duplicate_ack += 0
	loss -= 1
	return loss, Triple_Duplicate_ack

def Congestion_Window(flow_packets):
	i = index_after_threeway_handshake(flow_packets)
	RTT = flow_packets[1].time_stamp - flow_packets[0].time_stamp
	cwnd = []
	send = True
	count = 0
	for packet in flow_packets[i:]:
		if packet.src_ip == SENDER and packet.dest_ip == RECEIVER and send==True:
			endtimestamp = packet.time_stamp + RTT
			count+=packet.packet_size
			send=False
		if packet.src_ip == SENDER and packet.dest_ip == RECEIVER:
			if endtimestamp>packet.time_stamp:
				count+=packet.packet_size
			else:
				cwnd.append(count)
				count=0
				send=True
		if len(cwnd)==10:
			break
	rate_growth = [round(cwnd[i+1]/cwnd[i], 4) for i in range(0,min(9, len(cwnd)-1))]
	return cwnd, rate_growth

def main():
	pcap_file = open('assignment2.pcap' , 'rb')
	pcap = dpkt.pcap.Reader(pcap_file)
	packet_list = PCAP_File_Reader(pcap)

	flows = Flow_Initializer(packet_list)
	print("Part B 1 ")
	for i, flow in enumerate(flows):
		#Congestion Window
		cwnd, rate_growth = Congestion_Window(flow["packets"])
		print(f"In Flow {i+1} ({flow['src_port']} -> {flow['dest_port']})")
		print(f"The First 10 Congestion Window are: {cwnd}")
		print(f"The Growth Rate of Congestion window is: {rate_growth}\n")
	
	print("\n-----------------------------------------------------------------------")
	
	print("Part B 2 ")

	for flow in flows:
	#Retransmissions , Triple Ack Loss
		loss, Triple_Duplicate_ack = LossCalculation(flow["packets"])
		print(f"In Flow {i+1} ({flow['src_port']} -> {flow['dest_port']}), the total duplicate packets retransmitted is {loss}")
		print(f"The number of packets retransmitted due to Triple Duplicate Ack is {Triple_Duplicate_ack}")
		print(f"the number of times a retransmission occurred due to timeout is {loss-Triple_Duplicate_ack}\n")
	
if __name__ == '__main__':
	main()