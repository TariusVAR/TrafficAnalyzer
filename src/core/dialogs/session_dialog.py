from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QMessageBox
)

class SessionSelectDialog(QDialog):
    def __init__(self, sessions, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Выбор сессии")
        self.selected_session = None
        self.to_delete = False

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Выберите сессию:"))
        self.combo = QComboBox()
        self.combo.addItems(sessions)
        layout.addWidget(self.combo)

        button_layout = QHBoxLayout()
        self.load_btn = QPushButton("Загрузить")
        self.delete_btn = QPushButton("Удалить выбранную")
        self.cancel_btn = QPushButton("Отмена")

        button_layout.addWidget(self.load_btn)
        button_layout.addWidget(self.delete_btn)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.load_btn.clicked.connect(self.load_session)
        self.delete_btn.clicked.connect(self.delete_session)
        self.cancel_btn.clicked.connect(self.reject)

    def load_session(self):
        self.selected_session = self.combo.currentText()
        self.accept()

    def delete_session(self):
        self.selected_session = self.combo.currentText()
        self.to_delete = True
        self.accept()
