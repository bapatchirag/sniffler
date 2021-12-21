# GUI interface for sniffler

from PyQt5.QtWidgets import QApplication
from gsniffle.ui import create_window

app = QApplication([])
window = create_window()
window.setWindowTitle("GSniffler")
window.show()

# Start application
app.exec_()