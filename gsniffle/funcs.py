# Add functionalities

from PyQt5.QtWidgets import QMessageBox
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

class Gsniff(threading.Thread):
    def __init__(self):
        self.event_sniff = threading.Event()
        self.thread_sniff = threading.Thread(target=sniffle, args=(None, "gsniffler"))
        self.thread_control = threading.Thread(target=self.add_events)

    def add_events(self):
        pass

    # Callback to start sniffing packets
    def start_sniffing(self):
        self.event_sniff.set()
        self.thread_sniff.start()
        self.thread_control.start()
        # alert_box()

    # Callback to stop sniffing packets
    def stop_sniffing(self):
        if self.event_sniff.is_set():
            self.event_sniff.clear()
        # alert_box()

    # Callback to open analysis window
    def do_analysis():
        alert_box()