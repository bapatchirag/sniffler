# Parse incoming packets

import struct
import sys
import socket

# Convert raw mac address to readable mac address
def get_mac_addr(raw_addr):
    return raw_addr.hex(":")

# Convert raw ip address to readable ip address
def get_ip_addr(raw_addr):
    return ".".join(map(str, raw_addr))

# Parse ethernet frame
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    
    return dest_mac, src_mac, proto, data, len(raw_data)

# Parse ipv4 packet
def ipv4_head(eth_data):
    eth_open_byte = eth_data[0]
    ip_version = eth_open_byte >> 4
    header_len = (eth_open_byte & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', eth_data[:20])
    tl_data = eth_data[header_len:]
    
    return header_len, proto, get_ip_addr(src), get_ip_addr(target), tl_data

# Parse tcp packet
def tcp_head(ip_data):
    src_port, dest_port, seq, ack, offset_res, flags = struct.unpack('! H H L L B B', ip_data[:14])
    offset = (offset_res >> 4) * 4
    flag_vals = {
        "URG": (flags & 32) >> 5,
        "ACK": (flags & 16) >> 4,
        "PSH": (flags & 8) >> 3,
        "RST": (flags & 4) >> 2,
        "SYN": (flags & 2) >> 1,
        "FIN": flags & 1
    }
    data = ip_data[offset:]
    
    return src_port, dest_port, flag_vals, data

# Parse udp packet
def udp_head(ip_data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', ip_data[:8])
    data = ip_data[8:]
    
    return src_port, dest_port, data