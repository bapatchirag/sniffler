# GUI interface for sniffler

from PyQt5.QtWidgets import QApplication
from gsniffle.ui import create_window

app = QApplication([])
window = create_window()
window.setWindowTitle("GSniffler")
window.show()

# Start application
app.exec_()

# TODO Start piping data from sniffler to gsniffler

# TODO Integrate filters with gsniffler

# TODO Integrate analysis for packets (counts only, mostly) + Status bar actions