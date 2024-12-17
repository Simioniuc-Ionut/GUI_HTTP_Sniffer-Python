# 1. Import QApplication and all the required widgets
from PyQt6.QtWidgets import QApplication, QLabel, QWidget , QMainWindow
from PyQt6.QtCore import Qt

# 3. Create your application's GUI
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt6 Example")
        label = QLabel("Hello, PyQt6!")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setCentralWidget(label)

app = QApplication([])
window = MainWindow()
window.show()
app.exec()

