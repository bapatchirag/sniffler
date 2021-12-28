# Add functionalities

from PyQt5.QtWidgets import QMessageBox, QTableWidget, QTableWidgetItem, QHBoxLayout
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sniffler import sniffle, packet_buffer
import threading

# Testing alert box
def alert_box(title="Test", text="Button works!"):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowTitle(title)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()
    
# Callback to apply filters
def apply_filters():
    alert_box()
    
# Create table item from Packet in packet_buffer
def create_table_item(packet):
    return [packet.sa, packet.da, packet.sp, packet.dp, packet.proto]
    
class PacketTable:
    def __init__(self):
        self.packet_table = QTableWidget()
        
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
        row_count = self.packet_table.rowCount()
        self.packet_table.setRowCount(row_count + 1)
        
        cur_col = 0
        for item in table_item:
            self.packet_table.setItem(row_count, cur_col, QTableWidgetItem(str(item)))
            cur_col += 1
            
    def table_layout(self):
        table_ui = QHBoxLayout()
        table_ui.addWidget(self.packet_table)
        
        return table_ui

class Gsniff(threading.Thread):
    def __init__(self, table):
        self.packet_table = table
        self.event_sniff = threading.Event()
        self.thread_sniff = threading.Thread(target=sniffle, args=(None, "gsniffler"))
        self.thread_control = threading.Thread(target=self.add_packets)
        self.thread_sniff.setDaemon(True)
        self.thread_control.setDaemon(True)

    def add_packets(self):
        while self.event_sniff.is_set():
            for packet in packet_buffer.packet_list:
                self.packet_table.add_packet_to_table(packet)
                packet.used = True
            packet_buffer.delUsed()

    # Callback to start sniffing packets
    def start_sniffing(self):
        self.event_sniff.set()
        self.thread_sniff.start()
        self.thread_control.start()

    # Callback to stop sniffing packets
    def stop_sniffing(self):
        if self.event_sniff.is_set():
            self.event_sniff.clear()

    # Callback to open analysis window
    def do_analysis(self):
        alert_box()