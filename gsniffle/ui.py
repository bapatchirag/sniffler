# Generate UI for gsniffler

from PyQt5.QtCore import Qt, QRect
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QWidget, QLabel, QGridLayout, QHBoxLayout, QLineEdit, QCheckBox, QPushButton, QVBoxLayout, QFrame, QTableWidget, QTableWidgetItem
from .funcs import Gsniff, PacketTable, FilterList

class MainFrame():
    def __init__(self):
        self.pt = PacketTable()
        self.filters = FilterList()
        self.actions = Gsniff(self.pt, self.filters)
        self.window = QWidget()
        self.complete = QVBoxLayout()
    
    # Generate a horizontal line
    def make_line(self):
        line = QFrame()
        line.setGeometry(QRect(60, 110, 751, 20))
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        
        return line

    # Generate filter UI
    def filter_layout(self):
        # Create filter layout
        filters = QGridLayout()

        # Filter labels
        filter_label = QLabel("Filters")
        bold = QFont()
        bold.setBold(True)
        filter_label.setFont(bold)

        # Protocol filters
        protocol_hbox = QHBoxLayout()
        for cbox in self.filters.proto.values():
            cbox.setChecked(True)
            protocol_hbox.addWidget(cbox)

        # Source IP filter
        src_ip_hbox = QHBoxLayout()
        source_ip_label = QLabel("Source Addr.")
        src_ip_hbox.addWidget(source_ip_label)
        src_ip_hbox.addWidget(self.filters.addr_port["sa"])

        # Destination IP filter
        dest_ip_hbox = QHBoxLayout()
        dest_ip_label = QLabel("Dest. Addr.")
        dest_ip_hbox.addWidget(dest_ip_label)
        dest_ip_hbox.addWidget(self.filters.addr_port["da"])

        # Source port filter
        src_port_hbox = QHBoxLayout()
        source_port_label = QLabel("Source Port")
        src_port_hbox.addWidget(source_port_label)
        src_port_hbox.addWidget(self.filters.addr_port["sp"])

        # Destination port filter
        dest_port_hbox = QHBoxLayout()
        dest_port_label = QLabel("Dest. Port")
        dest_port_hbox.addWidget(dest_port_label)
        dest_port_hbox.addWidget(self.filters.addr_port["dp"])
        
        # Apply filter button
        apply_filter_button = QPushButton("Apply")
        apply_filter_button.clicked.connect(lambda: self.filters.set_selected())

        # Add filters to layout
        filters.addWidget(filter_label, 0, 0, 1, 1, Qt.AlignCenter)
        filters.addLayout(protocol_hbox, 0, 1)
        filters.addLayout(src_ip_hbox, 1, 0)
        filters.addLayout(dest_ip_hbox, 1, 1)
        filters.addLayout(src_port_hbox, 2, 0)
        filters.addLayout(dest_port_hbox, 2, 1)
        filters.addWidget(apply_filter_button, 3, 0, 1, 2, Qt.AlignCenter)
        
        return filters

    # Generate actions UI
    def actions_layout(self):
        # Create actions layout
        actions_ui = QHBoxLayout()
        
        # Actions label
        actions_label = QLabel("Actions")
        bold = QFont()
        bold.setBold(True)
        actions_label.setFont(bold)
        
        # Start button
        start_button = QPushButton("Start")
        start_button.clicked.connect(self.actions.start_sniffing)
        
        # Stop button
        stop_button = QPushButton("Stop")
        stop_button.clicked.connect(self.actions.stop_sniffing)
        
        # Analyze button
        analyze_button = QPushButton("Analyze")
        analyze_button.clicked.connect(self.actions.start_analysis)
        
        # Add actions to layout
        actions_ui.addWidget(actions_label, 0, Qt.AlignCenter)
        actions_ui.addWidget(start_button, 0, Qt.AlignCenter)
        actions_ui.addWidget(stop_button, 0, Qt.AlignCenter)
        actions_ui.addWidget(analyze_button, 0, Qt.AlignCenter)
        
        return actions_ui

    # Generate status bar UI
    def status_bar_layout(self):
        # Create status bar layout
        status = QHBoxLayout()
        
        # Status label
        status_label = QLabel("Status")
        bold = QFont()
        bold.setBold(True)
        status_label.setFont(bold)
        
        # Status text
        status_text = QLabel("Idle")
        
        # Add status to layout
        status.addWidget(status_label, 0, Qt.AlignCenter)
        status.addWidget(status_text, 0, Qt.AlignCenter)
        
        return status

    # Generate main UI
    def create_window(self):
        # Add filters to complete layout
        self.complete.addLayout(self.filter_layout())
        self.complete.addWidget(self.make_line())
        
        # Add actions to complete layout
        self.complete.addLayout(self.actions_layout())
        self.complete.addWidget(self.make_line())
        
        # Add table to complete layout
        
        self.complete.addLayout(self.pt.table_layout())
        self.complete.addWidget(self.make_line())
        
        # Add status to complete layout
        self.complete.addLayout(self.status_bar_layout())
        self.complete.addWidget(self.make_line())

        # Add layout to window
        self.window.setLayout(self.complete)
        
        return self.window