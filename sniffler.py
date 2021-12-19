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

def display_ipv4_packet(ip_data):
    print('\n\t - IPv4 Packet:')
    print('\t\t - IP Version: {}, Header Length: {}, TTL: {},'.format(ip_data[0], ip_data[1], ip_data[2]))
    print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ip_data[3], ip_data[4], ip_data[5]))

def display_tcp_packet(tcp_data):
    print('\n\t - TCP Packet:')
    print('\t\t - Source Port: {}, Destination Port: {}'.format(tcp_data[0], tcp_data[1]))
    print('\t\t - Sequence Number: {}, Acknowledgement Number: {}'.format(tcp_data[2], tcp_data[3]))
    print('\t\t - Flags:')
    for flag in tcp_data[4]:
        print('\t\t\t - {}: {}'.format(flag[5:], tcp_data[4][flag]))
    print('\t\t - Data: {}'.format(tcp_data[5]))
    
def display_udp_packet(udp_data):
    print('\n\t\t - UDP Segment:')
    print('\t\t\t - Source Port: {}, Destination Port: {}'.format(udp_data[0], udp_data[1]))
    print('\t\t\t - Data: {}'.format(udp_data[2]))
    

# receive a packet
def main(filters):
    protocols = [filter_to_protocol[x] for x in filters if x in filter_to_protocol]
    
    #create an INET, raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        
        # Ethernet frame
        eth = protoparse.ethernet_head(raw_data)
        if 0 in protocols or len(protocols) == 0:            
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],eth[2]))
        
        # IP Packet
        if eth[2] == 8:
            ipv4 = protoparse.ipv4_head(eth[3])
            
            # TCP Packet
            if ipv4[3] == 6 and (ipv4[3] in protocols or len(protocols) == 0):
                display_ipv4_packet(ip_data=ipv4)
                tcp = protoparse.tcp_head(ipv4[6])
                display_tcp_packet(tcp_data=tcp)
                
            # UDP Packet
            elif ipv4[3] == 17 and (ipv4[3] in protocols or len(protocols) == 0):
                display_ipv4_packet(ip_data=ipv4)
                udp = protoparse.udp_head(ipv4[6])
                display_udp_packet(udp_data=udp)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(prog='sniffler', description='Packet sniffer in python', allow_abbrev=False)
    parser.add_argument('-f', '--filter', nargs='*', action='store', dest='filter', help='Filter to apply to the sniffer', required=False)
    args = vars(parser.parse_args())
    
    main(args['filter'])