# GUI interface for sniffler

from PyQt5.QtWidgets import QApplication
from gsniffle.ui import MainFrame

app = QApplication([])
window = MainFrame().create_window()
window.setWindowTitle("GSniffler")
window.show()

# Start application
app.exec_()