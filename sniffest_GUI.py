from PyQt6.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QLineEdit, QPushButton, QLabel, QVBoxLayout, QWidget, QHBoxLayout, QComboBox,QDialog
from PyQt6.QtGui import QPixmap, QColor
from PyQt6.QtCore import Qt, QRect, QTimer
import random 
from datetime import datetime, timedelta


class DetailDialog(QDialog):
    def __init__(self, network_layer_packet=None,transport_layer_packet=None,application_layer_packet=None):
        super().__init__()
        self.setWindowTitle("Detalii Pachet")
        self.setGeometry(100, 100, 400, 300)
        
        # Network layer
        # if network_layer_packet:
        #     network_layer_layout.addWidget(QLabel("IP Version: " + str(network_layer_packet["IP Version"])))
        #     network_layer_layout.addWidget(QLabel("Internet Protocol: " + str(network_layer_packet["Internet Protocol"])))
        #     network_layer_layout.addWidget(QLabel("Source IP: " + str(network_layer_packet["Source IP"])))
        #     network_layer_layout.addWidget(QLabel("Destination IP: " + str(network_layer_packet["Destination IP"])))
        
        # # Transport layer
        # if transport_layer_packet:
        #     network_layer_layout.addWidget(QLabel("Transport Protocol: " + str(transport_layer_packet["Transport Protocol"])))
        #     network_layer_layout.addWidget(QLabel("Source Port: " + str(transport_layer_packet["Source Port"])))
        
        network_layer_layout = QVBoxLayout()
        
        network_title = QLabel("________________________________Network Layer Information________________________________")
        network_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        network_layer_layout.addWidget(network_title)
        network_layer_layout = self.__add_values_from_packet(network_layer_layout, network_layer_packet)
        
        main_layout = QVBoxLayout()
        main_layout.addLayout(network_layer_layout)
        
        # Transport layer
        transport_layer_layout = QVBoxLayout()
        
        transport_title = QLabel("________________________________Transport Layer Information________________________________")
        transport_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        transport_layer_layout.addWidget(transport_title)
        transport_layer_layout = self.__add_values_from_packet(transport_layer_layout, transport_layer_packet)
        
        main_layout.addLayout(transport_layer_layout)
        
        # Application layer
        application_layer_layout = QVBoxLayout()
        
        application_title = QLabel("________________________________Application Layer Information________________________________")
        application_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        application_layer_layout.addWidget(application_title)
        application_layer_layout = self.__add_values_from_packet(application_layer_layout, application_layer_packet)
        
        main_layout.addLayout(network_layer_layout)
        main_layout.addLayout(transport_layer_layout)
        main_layout.addLayout(application_layer_layout)
        
        self.setLayout(main_layout)
    
    def __add_values_from_packet(self,layout, packet):
        if packet is None:
            return layout
    
        for key, value in packet.items():
            label = QLabel(f"{key}: {value}")
            layout.addWidget(label)
        
        return layout

class SnifferApp(QMainWindow):
    EXPIRE_TIME = timedelta(seconds=10)  # Expire time 30 seconds

    def __init__(self):
        super().__init__()
        self.setWindowTitle("HTTP Sniffer")
        self.setGeometry(0, 0, 1080, 700)
        
        # Central widget
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        
        # Main vertical layout
        main_layout = QVBoxLayout(central_widget)
        
        # Header layout (for logo and title)
        header_layout = QHBoxLayout()

        # Logo
        logo_label = QLabel(self)
        logo_pixmap = QPixmap("imgs/icons8-sniffer-64_white.png")
        logo_label.setPixmap(logo_pixmap)
        logo_label.setFixedSize(64, 64)
        header_layout.addWidget(logo_label)
        
        # Button Exit
        exit_button = QPushButton("Exit", self)
        exit_button.clicked.connect(self.close)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(exit_button)
        button_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
    
        
        # Title
        title_label = QLabel("Sniffest HTTP", self)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: white; font-size: 30px; font-weight: bold;")
        header_layout.addWidget(title_label)
        
        # Add header layout to main layout with alignment
        main_layout.addLayout(header_layout)
        main_layout.addLayout(button_layout)
        main_layout.setAlignment(header_layout, Qt.AlignmentFlag.AlignCenter)
        
        # Filters
        filter_layout = QHBoxLayout()
        main_layout.addLayout(filter_layout)
        
        # Table
        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "HTTP Method","Details"])
        main_layout.addWidget(self.table)
        
        self.filters = []
        self.all_packets = []  # Store all packets
        
        for column in ["Source IP", "Destination IP", "Protocol", "HTTP Method"]:
            filter_combo = QComboBox(self)
            filter_combo.addItem("None")
            filter_combo.setPlaceholderText(f"Filter by {column}")
            filter_combo.currentTextChanged.connect(self.apply_filters)
            filter_layout.addWidget(filter_combo)
            self.filters.append(filter_combo)
        
        
        # Timer for real-time updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_data)
        self.timer.start(1000)  # Update every 1000 ms (1 second)
        
        # Timer for clean expired packets
        self.cleanup_timer = QTimer(self)
        self.cleanup_timer.timeout.connect(self.cleanup_expired_packets)
        self.cleanup_timer.start(5000)  # clean at every 5 seconds


    def update_table(self):
        """Update the table based on filtered packets."""
        self.table.setRowCount(0)  # Clear the table
        for packet in self.all_packets:
            if self.packet_matches_filters(packet):
                row = self.table.rowCount()
                self.table.insertRow(row)
                for col, value in enumerate(packet.values()):
                    item = QTableWidgetItem(str(value))
                    if col == 0:
                        item.setBackground(QColor("lightblue"))
                    elif col == 1:
                        item.setBackground(QColor("lightgreen"))
                    self.table.setItem(row, col, item)
                # Add details button
                details_button = QPushButton("Detalii")
                details_button.clicked.connect(lambda _, p=packet: self.show_details(p))
                self.table.setCellWidget(row, 4, details_button)

    def packet_matches_filters(self, packet):
        """Check if a packet matches the selected filters."""
        columns = ["src_ip", "dst_ip", "protocol", "http_method"]
        for col, filter_combo in enumerate(self.filters):
            selected_value = filter_combo.currentText()
            if selected_value != "None" and selected_value != str(packet[columns[col]]):
                return False
        return True

    def load_data(self, packets):
        """Load new packets and update filters with new values."""
        for packet in packets:
            self.all_packets.append(packet)
            
            # Iterato through the packets columns
            columns = ["src_ip", "dst_ip", "protocol", "http_method"]
            for col, key in enumerate(columns):
                value = packet[key]
                # Add to the corresponding filter only if the value does not already exist
                filter_combo = self.filters[col]
                if str(value) not in [filter_combo.itemText(i) for i in range(filter_combo.count())]:
                    filter_combo.addItem(str(value))
        self.update_table()  # Refresh the table with new packets

    def update_filter_options(self):
        """Update filter options based on unique values in the packets."""
        columns = ["src_ip", "dst_ip", "protocol", "http_method"]
        for col, key in enumerate(columns):
            unique_values = set(packet[key] for packet in self.all_packets)
            filter_combo = self.filters[col]
            
            # Save the current selection
            current_selection = filter_combo.currentText()
            filter_combo.blockSignals(True)  # Prevent signals from being triggered

            filter_combo.clear()
            filter_combo.addItem("None")  # Add the default option
            filter_combo.addItems(sorted(unique_values))
            
            # Reselect the current option
            index = filter_combo.findText(current_selection)
            if index != -1:
                filter_combo.setCurrentIndex(index)
            filter_combo.blockSignals(False)

    def apply_filters(self):
        self.update_table()
    def show_details(self, packet):
        """Display details"""
        dialog = DetailDialog(packet)
        dialog.exec()
    def update_data(self):
        # This is where you would call your sniffer_app to get new data
        # For demonstration, we'll just add a random packet
        new_packet = {
            "src_ip": f"192.168.0.{random.randint(1, 255)}",
            "dst_ip": f"93.184.216.{random.randint(1, 255)}",
            "protocol": random.choice(["HTTP", "HTTPS"]),
            "http_method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "timestamp": datetime.now(),
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            "payload": "Sample payload data" 
        }
        self.load_data([new_packet])
    
    def cleanup_expired_packets(self):
        """Delete expired packets from the list."""
        current_time = datetime.now()
        initial_packet_count = len(self.all_packets)

        # Filter packets that are not expired
        self.all_packets = [
            packet for packet in self.all_packets 
            if current_time - packet["timestamp"] <= self.EXPIRE_TIME
        ]

        if len(self.all_packets) != initial_packet_count:
            # If the number of packets has changed, update the filter options
            self.update_filter_options()

            # Refresh the table , since some packets may have been removed
            self.update_table()


# Initialize the application
def run():
    app = QApplication([])
    window = SnifferApp()
    window.show()
    app.exec()

