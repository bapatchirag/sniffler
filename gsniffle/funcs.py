# Add functionalities

from PyQt5.QtWidgets import QMessageBox

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

# Callback to start sniffing packets
def start_sniffing():
    alert_box()

# Callback to stop sniffing packets
def stop_sniffing():
    alert_box()

# Callback to open analysis window
def do_analysis():
    alert_box()