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
        
        # Ethernet Frame
        eth = protoparse.ethernet_head(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],eth[2]))
        
        # IP Packet
        if eth[2] == 8:
            ipv4 = protoparse.ipv4_head(eth[3])
            print('\n\t - IPv4 Packet:')
            print('\t\t - IP Version: {}, Header Length: {}, TTL: {},'.format(ipv4[0], ipv4[1], ipv4[2]))
            print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
        
main()