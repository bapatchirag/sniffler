#Packet sniffer in python
#For Linux

import socket
import protoparse

# Protocol number to protocol name mapping
protocol_to_filter = {
    6: "tcp",
    17: "udp",
    1: "icmp",
    0: "eth"
}

# "Packet" definition - may be frame, actual packet or segment
class Packet:
    def __init__(self, proto:str, packsize:int, sa:str, da:str, sp:int|None=None, dp:int|None=None, used:bool=False, flags:dict=None, data:str|None=None):
        self.proto = proto
        self.packsize = packsize
        self.sa = sa
        self.da = da
        self.sp = sp
        self.dp = dp
        self.used = used
        self.flags = flags
        self.data = data
        
    def isUsed(self):
        return self.used
    
    def display(self, tab:int=0):
        print("\n" + "\t"*tab + " - " + self.proto + " packet")
        print("\t"*(tab+1) + " - Size: {}".format(self.packsize))
        print("\t"*(tab+1) + " - Source address: {}, Destination address: {}".format(self.sa, self.da))
        if self.sp is not None:
            print("\t"*(tab+1) + " - Source port: {}, Destination port: {}".format(self.sp, self.dp))
        if self.flags is not None:
            print("\t"*(tab+1) + " - Flags")
            for flag in self.flags:
                print("\t"*(tab+2) + " - {}: {}".format(flag, self.flags[flag]))
        if self.data is not None:
            print("\t"*(tab+1) + " - Data: {}".format(self.data))

# Packet List behaviour
class PacketList:
    def __init__(self):
        self.packet_list = []
    
    def delUsed(self):
        for packet in self.packet_list:
            if packet.isUsed():
                self.packet_list.remove(packet)

# receive a packet
def sniffle(filters, callfile):
    if filters is None:
        filters = []

    #create an INET, raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        
        # Ethernet frame
        eth = protoparse.ethernet_head(raw_data)
        eth_frame = Packet(proto="eth", packsize=eth[4], sa=eth[1], da=eth[0])
        if eth_frame.proto in filters or len(filters) == 0:
            eth_frame.display(tab=0)
        
        # IP Packet
        if eth[2] == 8:
            ipv4 = protoparse.ipv4_head(eth[3])
            
            # TCP Packet
            if protocol_to_filter[ipv4[1]] == "tcp" and ("tcp" in filters or len(filters) == 0):
                tcp = protoparse.tcp_head(ipv4[4])
                tcp_segment = Packet(proto="tcp", packsize=len(tcp[3]), sa=ipv4[2], da=ipv4[3], sp=tcp[0], dp=tcp[1], data=tcp[3], flags=tcp[2])
                tcp_segment.display(tab=1)
                
            # UDP Packet
            elif protocol_to_filter[ipv4[1]] == "udp" and ("udp" in filters or len(filters) == 0):
                udp = protoparse.udp_head(ipv4[4])
                udp_segment = Packet(proto="udp", packsize=len(udp[2]), sa=ipv4[2], da=ipv4[3], sp=udp[0], dp=udp[1], data=udp[2])
                udp_segment.display(tab=1)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(prog='sniffler', description='Packet sniffer in python', allow_abbrev=False)
    parser.add_argument('-f', '--filter', nargs='*', action='store', dest='filter', help='Filter to apply to the sniffer', required=False)
    args = vars(parser.parse_args())
    
    sniffle(args['filter'], callfile="sniffler")