# Add functionalities

from PyQt5.QtWidgets import QMessageBox, QTableWidget, QTableWidgetItem, QHBoxLayout, QCheckBox, QLineEdit
from PyQt5.QtCore import Qt
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sniffler import sniffle, packet_buffer
import threading

# Analysis display message box
def analysis_box(title="Test", text="Button works!"):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowTitle(title)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()
    
# Create table item from Packet in packet_buffer
def create_table_item(packet):
    return [packet.sa, packet.sp, packet.da, packet.dp, packet.proto]

# Table behaviour    
class PacketTable:
    def __init__(self):
        self.packet_table = QTableWidget()
        self.packet_info = {"tcp": 0, "udp": 0, "icmp": 0, "eth": 0}
        
        # Set columns
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels([
            "Source Address",
            "Source Port",
            "Destination Address",
            "Destination Port",
            "Protocol"
        ])

    # Add a single packet to the table
    def add_packet_to_table(self, packet):
        table_item = create_table_item(packet)
        self.packet_info[table_item[4]] += 1
        row_count = self.packet_table.rowCount()
        self.packet_table.setRowCount(row_count + 1)
        
        cur_col = 0
        for item in table_item:
            qt_item = QTableWidgetItem(str(item))
            qt_item.setFlags(qt_item.flags() ^ Qt.ItemIsEditable)
            self.packet_table.setItem(row_count, cur_col, qt_item)
            cur_col += 1
    
    # Create layout for table       
    def table_layout(self):
        table_ui = QHBoxLayout()
        table_ui.addWidget(self.packet_table)
        
        return table_ui

# Filter behaviour
class FilterList:
    def __init__(self):
        self.proto = {
            "tcp": QCheckBox("TCP"),
            "udp": QCheckBox("UDP"),
            "eth": QCheckBox("Ethernet"),
            "icmp": QCheckBox("ICMP")
        }
        self.addr_port = {
            "sa": QLineEdit(),
            "da": QLineEdit(),
            "sp": QLineEdit(),
            "dp": QLineEdit()
        }
        self.selected_filters = {"proto": [], "sa": [], "da": [], "sp": [], "dp": []}
    
    def set_selected(self):     
        self.selected_filters["proto"] = [protocol for protocol in self.proto if self.proto[protocol].isChecked()]
        self.selected_filters["sa"] = [self.addr_port["sa"].text()] if self.addr_port["sa"].text() != "" else []
        self.selected_filters["da"] = [self.addr_port["da"].text()] if self.addr_port["da"].text() != "" else []
        self.selected_filters["sp"] = [self.addr_port["sp"].text()] if self.addr_port["sp"].text() != "" else []
        self.selected_filters["dp"] = [self.addr_port["dp"].text()] if self.addr_port["dp"].text() != "" else []
        
    def get_selected(self):
        return self.selected_filters

# Sniffing behaviour
class Gsniff(threading.Thread):
    def __init__(self, table, filter_list):
        self.packet_table = table
        self.filters = filter_list.get_selected()
        self.event_sniff = threading.Event()
        self.event_analysis = threading.Event()
        self.thread_sniff = threading.Thread(target=sniffle, args=(self.filters, "gsniffler"))
        self.thread_control = threading.Thread(target=self.add_packets)
        self.thread_analysis = threading.Thread(target=self.do_analysis)
        self.thread_sniff.daemon = True
        self.thread_control.daemon = True
        self.thread_analysis.daemon = True
    
    # Add packets to table
    def add_packets(self):
        while self.event_sniff.is_set():
            for packet in packet_buffer.packet_list:
                self.packet_table.add_packet_to_table(packet)
                packet.used = True
            packet_buffer.delUsed()

    # Callback to start sniffing packets
    def start_sniffing(self):
        self.event_sniff.set()
        if not self.thread_sniff.is_alive():
            self.thread_sniff.start()
            self.thread_control.start()

    # Callback to stop sniffing packets
    def stop_sniffing(self):
        if self.event_sniff.is_set():
            self.event_sniff.clear()
            self.thread_control.join()
            self.event_analysis.set()

    # Callback to start analysis
    def start_analysis(self):
        if self.event_analysis.is_set():
            self.event_analysis.clear()
            self.thread_analysis.start()

    # Callback to open analysis window
    def do_analysis(self):
        text = ""
        for protocol in self.packet_table.packet_info:
            text += protocol.upper() + " count: " + str(self.packet_table.packet_info[protocol]) + "\n"
        analysis_box(title="Analysis", text=text)