#Packet sniffer in python
#For Linux

import socket
import protoparse

filter_to_protocol = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "eth": 0
}

def filters():
    return input("Enter filters: ").split(" ")

# receive a packet
def main():
    filter_names = filters()
    protocols = [filter_to_protocol[x] for x in filter_names if x in filter_to_protocol]
    
    #create an INET, raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = [0 for x in range(14)]
        
        # Ethernet Frame
        if 0 in protocols:
            eth = protoparse.ethernet_head(raw_data)
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],eth[2]))
        
        # IP Packet
        if eth[2] == 8:
            ipv4 = protoparse.ipv4_head(eth[3])
            print('\n\t - IPv4 Packet:')
            print('\t\t - IP Version: {}, Header Length: {}, TTL: {},'.format(ipv4[0], ipv4[1], ipv4[2]))
            print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
            
            # TCP Packet
            if ipv4[3] == 6 and ipv4[3] in protocols:
                tcp = protoparse.tcp_head(ipv4[6])
                print('\n\t\t - TCP Segment:')
                print('\t\t\t - Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('\t\t\t - Sequence Number: {}, Acknowledgement Number: {}'.format(tcp[2], tcp[3]))
                print('\t\t\t - Flags:')
                for flag in tcp[4]:
                    print('\t\t\t\t - {}: {}'.format(flag[5:], tcp[4][flag]))
                print('\t\t\t - Data: {}'.format(str(tcp[5])))
                
            # UDP Packet
            elif ipv4[3] == 17 and ipv4[3] in protocols:
                udp = protoparse.udp_head(ipv4[6])
                print('\n\t\t - UDP Segment:')
                print('\t\t\t - Source Port: {}, Destination Port: {}'.format(udp[0], udp[1]))
                print('\t\t\t - Data: {}'.format(udp[2]))
        
main()