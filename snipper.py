import socket, sys
from struct import *
import time
import datetime

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b
last_try = ""
while True:
	packet = s.recvfrom(65565)
	packet = packet[0]

	ip_header = packet[0:20]

	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF
	iph_length = ihl * 4
	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);

	#print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

	#print ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)	

	tcp_header = packet[iph_length:iph_length+20]
	
	tcph = unpack('!HHLLBBHHH' , tcp_header)
	
	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4
	
	#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
	if(source_port==22):
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		if(last_try!=st):
			last_try = st
			print "Someone tried to access your PC!!!"
			print "Activing Hacker identification process"
			print "Logging data"
			
			
			log = '['+st+'] '+str(s_addr)+'\t'+str(eth_addr(packet[6:12]))+'\n'
			#print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12])
			print log
			print 
			f = open("log.txt", "a")
			f.write(log)
			f.close()	

	h_size = iph_length + tcph_length * 4
	data_size = len(packet) - h_size
	
	#get data from the packet
	data = packet[h_size:]
	
	#print 'Data : ' + data
	#print
