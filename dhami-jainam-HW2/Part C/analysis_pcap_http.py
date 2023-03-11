import dpkt, struct

def getField(buf, fmt, pos, endpos):
	if(len(buf) > pos):
		return str(struct.unpack(fmt, buf[pos:endpos])[0])

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
			self.payload = self.buffer[34+self.len_head:]
			self.mss = int.from_bytes(self.buffer[56:58], byteorder='big')
			self.len_payload = len(self.payload)
			self.request = str(getField(self.buffer, ">s", 66, 67)) + str(getField(self.buffer, ">s", 67, 68)) + str(getField(self.buffer, ">s", 68, 69))
			self.response = str(getField(self.buffer, ">s", 66, 67)) + str(getField(self.buffer, ">s", 67, 68)) + str(getField(self.buffer, ">s", 68, 69)) + str(getField(self.buffer, ">s", 69, 70))
		except:
			self.isValid = False

class HTTP_Reassembler:

	def __init__(self, packet):  
		start = str(packet.payload).find('HTTP')
		end1 = str(packet.payload).find('Connection')
		end2 = str(packet.payload).find('close')
		end  = end1 if end1 > end2 else end2
		self.request = str(packet.payload)[start:end+5]
		self.segment_tcp = []

def PCAP_File_Reader(pcap):
	packet_list = []
	packet_bytes = pcap.readpkts()
	for packet_byte in packet_bytes:
		pkt = Packet(packet_byte)
		pkt.parse()
		if pkt.isValid:	
			packet_list.append(pkt)
	return packet_list

def Flow_Initializer(packet_list):
	#Create Flows / Connections
	flows = []
	tcp_connections = 0
	count_packet = 0
	total_payload = 0
	for packet in packet_list:
		count_packet+=1
		total_payload+=packet.packet_size
		if packet.syn == 1 and packet.ack == 0:
			tcp_connections += 1
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
	return tcp_connections, count_packet, total_payload, flows

def http_reassemble(flow):
	get_packets = []
	for packet in flow:       # finding all the get packets
		if packet.request == "b'G'b'E'b'T'":
			get_packets.append(packet)

	http_packets = []
	for packet in flow:       # finding all the http packets
		if packet.response == "b'H'b'T'b'T'b'P'":
			http_packets.append(packet)
	
	packet_dict = {}
	for packet in flow:
		seq = packet.seq_num
		packet_dict[seq] = packet  
	#REASSEMBLING ALL GET PACKETS
	reassembles = []
	for get in get_packets:
		reassemble = HTTP_Reassembler(get)
		seq_next = get.ack_num    
		packet_next = packet_dict.get(seq_next)
		while packet_next:
			reassemble.segment_tcp.append((packet_next.src_port, packet_next.dest_port, packet_next.seq_num, packet_next.ack_num))
			len_payload = packet_next.len_payload
			seq_next = seq_next + len_payload
			packet_next = packet_dict.get(seq_next)
			if packet_next.fin == 1:
				break
		reassembles.append(reassemble)

	for reassemble in reassembles:
		print(f"Request  {reassemble.request}\n")
		print('The TCP segments for the above request ')
		print('Source Port    Destination Port    Sequence Number    Acknowledgement Number')
		for segment in reassemble.segment_tcp:
			print(f"{segment[0]}           {segment[1]}               {segment[2]}         {segment[3]}")
		print()
	
	#REASSEMBLING ALL HTTP PACKETS
	reassembles = []
	for http in http_packets:
		reassemble = HTTP_Reassembler(http)
		seq_next = http.ack_num     # start from the ack of http request
		packet_next = packet_dict.get(seq_next)
		while packet_next:
			reassemble.segment_tcp.append((packet_next.src_port, packet_next.dest_port, packet_next.seq_num, packet_next.ack_num))
			len_payload = packet_next.len_payload
			seq_next = seq_next + len_payload
			packet_next = packet_dict.get(seq_next)
			if packet_next.fin == 1:
				break
		reassembles.append(reassemble)
		
	for reassemble in reassembles:
		print("Response  ",reassemble.request)

def main():
	print("Part C 1")
	pcap = dpkt.pcap.Reader(open('http_1080.pcap', 'rb'))
	packet_list = PCAP_File_Reader(pcap)
	tcp_connections, count_packet, total_payload, flows = Flow_Initializer(packet_list)
	for i, flow in enumerate(flows):
		print(f"FLOW {i+1}")
		http_reassemble(flow['packets'])
		print()
	print("----------------------------------------------------------------------------------------------------")
	
	print("Part C 2")
	files = ['http_1080.pcap', 'tcp_1081.pcap', 'tcp_1082.pcap']
	file_data = []
	time_taken = []
	for i, file in enumerate(files):
		pcap_file = open(file , 'rb')
		pcap = dpkt.pcap.Reader(pcap_file)
		packet_list = PCAP_File_Reader(pcap)
		tcp_connections, count_packet, total_payload, flows = Flow_Initializer(packet_list)
		time_taken.append(packet_list[-1].time_stamp-packet_list[0].time_stamp)
		file_data.append({'file_name':file,
						'tcpconnections': tcp_connections,
						'count_packet': count_packet,
						'total_payload': total_payload})
		print(f"For file name {file}")
		print(f"The total number of TCP connections/flows are {tcp_connections}")
		if i==0:
			print('The number of connections for post 1080 is same as the number of GET requests. Hence we can say that the protocol used here is HTTP/1.0. This can also be checked in the output.txt file where we can see HTTP/1.0 in the response section.\n')
		elif i==1:
			print("Here we see that the number of (for port 1081) have decreased to 6, implying that it must be using HTTP/1.1 using which we can reduce the number of persistent connections by doing parallelization of requests, which depends on the browser used (Usually the number of parallel connections is 6 which is true in case of most of the browsers).\n")
		else:
			print("Here we see the number of connections (for port 1082) as 1, implying that the protocol used is HTTP/2.0 which has the capability to send all the objects using 1 connection by using pipelining.")
	print("----------------------------------------------------------------------------------------------------")
	
	print("Part C 3")
	httpconnections = ['1.0', '1.1', '2.0']
	for i, file in enumerate(file_data):
		print(f"For file name {file['file_name']}, HTTP/{httpconnections[i]} is used")
		print(f"The total time taken is {round(time_taken[i], 6)} s")
		print(f"The total packets transferred are {file['count_packet']}")
		print(f"The raw data size is {file['total_payload']} Bytes\n")

if __name__ == '__main__':
	main()