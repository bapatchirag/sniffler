#Packet sniffer in python
#For Linux

import socket
import protoparse

# receive a packet
def main():
    #create an INET, raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = protoparse.ethernet_head(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],eth[2]))
        
main()