import dpkt, math
from collections import Counter

SENDER = "130.245.145.12"
RECEIVER = "128.208.2.198"
ALPHA = 0.125

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

def Print_First_Two_Transactions(flows):
	for k, flow in enumerate(flows):   
		i = index_after_threeway_handshake(flow['packets'])
		j=0
		sender = []
		receiver = []
		conn = f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}"

		while(j<2):
			if f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}" == conn:
				conn = f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}"
				sender.append([flow['packets'][i].seq_num, flow['packets'][i].ack_num, flow['packets'][i].window_size])
				j+=1
			i+=1
		while conn == f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}":
			i+=1
			continue
		j=0
		conn = f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}"
		while j<2:
			if f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}" == conn:
				conn = f"SRC_IP : {flow['packets'][i].src_ip} DEST_IP : {flow['packets'][i].dest_ip}"
				receiver.append([flow['packets'][i].seq_num,flow['packets'][i].ack_num, flow['packets'][i].window_size])
				j+=1
			i+=1
		
		print("\n-----------------------------------------------------------------------")
		print(f"\nFlow {k+1} : {flow['src_port']} --> {flow['dest_port']}")

		print('\nTrnsaction 1')
		print(f"\nSender to receiver (SRC_IP : {flow['packets'][i].src_ip} -> DEST_IP : {flow['packets'][i].dest_ip})")
		print(f"The Sequence Number is {sender[0][0]} \nACK Number is {sender[0][1]} \nReceive Window Size is {sender[0][2]}")
		print(f"\nReceiver to Sender (SRC_IP : {flow['packets'][i].src_ip} -> DEST_IP : {flow['packets'][i].dest_ip})")
		print(f"The Sequence Number is {receiver[0][0]} \nACK Number is {receiver[0][1]} \nReceive Window Size is {receiver[0][2]}")

		print('\nTrnsaction 2')
		print(f"\nSender to receiver (SRC_IP : {flow['packets'][i].src_ip} -> DEST_IP : {flow['packets'][i].dest_ip})")
		print(f"The Sequence Number is {sender[1][0]} \nACK Number is {sender[1][1]} \nReceive Window Size is {sender[1][2]}")

		print(f"\nReceiver to Sender (SRC_IP : {flow['packets'][i].src_ip} -> DEST_IP : {flow['packets'][i].dest_ip})")
		print(f"The Sequence Number is {receiver[1][0]} \nACK Number is {receiver[1][1]} \nReceive Window Size is {receiver[1][2]}")

#Throughput
def Throughput_Calculation(flow_packets):
	total = 0
	start = float("inf")
	end = float("-inf")
	for i,packet in enumerate(flow_packets):
		if packet.src_ip == SENDER:
			total += packet.packet_size
			start = min(start , packet.time_stamp)
			end = max(end , packet.time_stamp)
	return total/(end-start)

def Flow_Initializer(packet_list):
	flows = []
	#Create Flows / Connections
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

#RTT : Round trip Time
def RTTCalculation(flow_packets):
	sequence_dict = {}
	ack_dict = {}
	payload = []
	## PUT COUNTER HERE
	for packet in flow_packets:
		payload.append(packet.payload)
	assumedpayload = max(Counter(payload))
	for packet in flow_packets[2:]:
		if packet.seq_num not in sequence_dict and packet.src_ip == SENDER and packet.dest_ip == RECEIVER:
			sequence_dict[packet.seq_num] = packet.time_stamp
		elif packet.ack_num not in ack_dict and packet.src_ip == RECEIVER and packet.dest_ip == SENDER:
			ack_dict[packet.ack_num] = packet.time_stamp
	prev_rtt = flow_packets[1].time_stamp - flow_packets[0].time_stamp
	for seq_num, seqtime in sequence_dict.items():
		acknum = seq_num + assumedpayload
		if acknum in ack_dict:
			est_rtt = ack_dict[acknum] - seqtime 
			est_rtt = (ALPHA * est_rtt) + (1 - ALPHA) * prev_rtt
			prev_rtt = est_rtt
	return est_rtt

#Loss
def LossRate_Calculation(flow_packets):
	sent_num = 0
	demonimator = 0
	counter_sequence = {}
	for packet in flow_packets:
			sequence = packet.seq_num
			if packet.src_ip == SENDER and packet.dest_ip == RECEIVER:
				demonimator+=1
				sent_num+=1
			if  packet.src_ip == SENDER and packet.dest_ip == RECEIVER and counter_sequence.get(sequence):
				counter_sequence[sequence] = counter_sequence[sequence] + 1
			else:
				counter_sequence[sequence] = 1
	send_total = 0
	for count in counter_sequence.values():
		send_total += count
	lost_packet_num = send_total - len(counter_sequence) - 1 
	loss_rate = lost_packet_num/demonimator
	return lost_packet_num, sent_num, loss_rate

def main():
	pcap_file = open('assignment2.pcap' , 'rb')
	pcap = dpkt.pcap.Reader(pcap_file)
	packet_list = PCAP_File_Reader(pcap)
	flows = Flow_Initializer(packet_list)
	print("Part A 1\n")
	print(f'The Number of Flows initiated by the Sender is {len(flows)}. And the respective flows and the total number of packets in each flow are: ')
	for flow in flows:
		print(f"{flow['src_port']} -> {flow['dest_port']} Number of packets: {len(flow['packets'])}")
	print("\nPart A 2(a)")
	Print_First_Two_Transactions(flows)
	print("\n-----------------------------------------------------------------------")

	print("Part A 2(b) ")
	for i, flow in enumerate(flows):
		# Finding the throughput for each flow
		throughput = Throughput_Calculation(flow["packets"])
		print(f"The Throughput for Flow {i+1} ({flow['src_port']} -> {flow['dest_port']}) is {round(throughput,6)} ({round(throughput/1000000, 6)} MBps)") 
	print("\n-----------------------------------------------------------------------")

	print("Part A 2(c) ")
	loss_rate_list = []
	for i, flow in enumerate(flows):
		#Find loss rate
		retransmission, sent_num, loss_rate = LossRate_Calculation(flow["packets"])
		loss_rate_list.append(loss_rate)
		print(f"In Flow {i+1} ({flow['src_port']} -> {flow['dest_port']}), the number of packets lost is {retransmission}")
		print(f'the total number of packets sent by the sender is {sent_num}')
		print(f'The loss rate is {round(loss_rate, 7)}\n')
	print("-----------------------------------------------------------------------")
	mss_list = []
	for packet in packet_list:
		mss_list.append(packet.mss)
	mss = min(Counter(mss_list))
	print("Part A 2(d) ")
	for i, flow in enumerate(flows):
		#Average RTT
		avg_RTT = RTTCalculation(flow["packets"])
		print(f"In Flow {i+1} ({flow['src_port']} -> {flow['dest_port']}), the average RTT is {round(avg_RTT, 6)} s")
		try:
			theoretical_throughput = (math.sqrt(3/2)*mss)/(avg_RTT*math.sqrt(loss_rate_list[i]))
			print(f"The Theoretical throughput for the above Flow is {round(theoretical_throughput, 6)} ({round(theoretical_throughput/1000000, 6)} MBps)\n")
		except ZeroDivisionError as ze:
			print('The Theoretical throughput for the above Flow is infinity')
		except Exception as e:
			print(e)

if __name__ == '__main__':
	main()