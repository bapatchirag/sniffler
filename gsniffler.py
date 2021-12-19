# GUI interface for sniffler

# TODO Complete UI

from PyQt5.QtWidgets import QApplication
from gsniffle.ui import createWindow

app = QApplication([])
window = createWindow()
window.setWindowTitle("GSniffler")
window.show()

# Start application
app.exec_()

# TODO Start piping data from sniffler to gsniffler

# TODO Integrate filters with gsniffler

# TODO Integrate analysis for packets (counts only, mostly) + Status bar actions