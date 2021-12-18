# Parse incoming packets

import struct
import sys
import socket

def get_mac_addr(raw_addr):
    return raw_addr.hex(":")

def get_ip_addr(raw_addr):
    return ".".join(map(str, raw_addr))

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    
    return dest_mac, src_mac, proto, data

def ipv4_head(eth_data):
    eth_open_byte = eth_data[0]
    ip_version = eth_open_byte >> 4
    header_len = (eth_open_byte & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', eth_data[:20])
    tl_data = eth_data[header_len:]
    
    return ip_version, header_len, ttl, proto, get_ip_addr(src), get_ip_addr(target), tl_data
