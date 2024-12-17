import sys
from PyQt6.QtCore import Qt, QRect, QTimer

from PyQt6.QtWidgets import (
    QApplication,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QLabel
)

app = QApplication([])
window = QWidget()
window.setWindowTitle("QVBoxLayout")

title1 = QLabel("Layer1")
title1.setAlignment(Qt.AlignmentFlag.AlignCenter)

layout1 = QVBoxLayout()
layout1.addWidget(title1)
layout1.addWidget(QPushButton("Top"))
layout1.addWidget(QPushButton("Center"))
layout1.addWidget(QPushButton("Bottom"))

title2 = QLabel("Layer2")
title2.setAlignment(Qt.AlignmentFlag.AlignCenter)

layout2 = QVBoxLayout()
layout2.addWidget(title2)
layout2.addWidget(QPushButton("Top"))
layout2.addWidget(QPushButton("Center"))
layout2.addWidget(QPushButton("Bottom"))

title3 = QLabel("Layer3")
title3.setAlignment(Qt.AlignmentFlag.AlignCenter)

layout3 = QVBoxLayout()
layout3.addWidget(title3)
layout3.addWidget(QPushButton("Top"))
layout3.addWidget(QPushButton("Center"))
layout3.addWidget(QPushButton("Bottom"))



# Main layout
main_layout = QVBoxLayout(window)
main_layout.addLayout(layout1)
main_layout.addLayout(layout2)
main_layout.addLayout(layout3)


window.setLayout(main_layout)
window.show()
sys.exit(app.exec())