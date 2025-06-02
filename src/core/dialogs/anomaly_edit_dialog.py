from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QListWidget, QLineEdit, QLabel, QMessageBox
)

from src.database.db_interface import DBInterface

class AnomalyEditDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = DBInterface()
        self.setWindowTitle("Редактирование разрешённых IP и портов")
        self.resize(400, 300)

        self.ip_list = QListWidget()
        self.port_list = QListWidget()

        self.ip_input = QLineEdit()
        self.port_input = QLineEdit()

        self.init_ui()
        self.load_rules()

    def init_ui(self):
        layout = QVBoxLayout(self)


        ip_layout = QVBoxLayout()
        ip_layout.addWidget(QLabel("Разрешённые IP-адреса"))
        ip_layout.addWidget(self.ip_list)

        ip_input_layout = QHBoxLayout()
        ip_input_layout.addWidget(self.ip_input)
        add_ip_btn = QPushButton("Добавить IP")
        add_ip_btn.clicked.connect(self.add_ip)
        ip_input_layout.addWidget(add_ip_btn)
        ip_layout.addLayout(ip_input_layout)

        remove_ip_btn = QPushButton("Удалить выбранный IP")
        remove_ip_btn.clicked.connect(self.remove_selected_ip)
        ip_layout.addWidget(remove_ip_btn)


        port_layout = QVBoxLayout()
        port_layout.addWidget(QLabel("Разрешённые порты"))
        port_layout.addWidget(self.port_list)

        port_input_layout = QHBoxLayout()
        port_input_layout.addWidget(self.port_input)
        add_port_btn = QPushButton("Добавить порт")
        add_port_btn.clicked.connect(self.add_port)
        port_input_layout.addWidget(add_port_btn)
        port_layout.addLayout(port_input_layout)

        remove_port_btn = QPushButton("Удалить выбранный порт")
        remove_port_btn.clicked.connect(self.remove_selected_port)
        port_layout.addWidget(remove_port_btn)


        main_layout = QHBoxLayout()
        main_layout.addLayout(ip_layout)
        main_layout.addLayout(port_layout)

        layout.addLayout(main_layout)
        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def load_rules(self):
        self.ip_list.clear()
        self.port_list.clear()
        rules = self.db.get_all_rules()
        for _, rule_type, value in rules:
            if rule_type == "ip":
                self.ip_list.addItem(value)
            elif rule_type == "port":
                self.port_list.addItem(value)

    def add_ip(self):
        ip = self.ip_input.text().strip()
        if not ip:
            return
        try:
            parts = ip.split('.')
            if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
                raise ValueError
            self.db.add_allowed_rule('ip', ip)
            self.ip_input.clear()
            self.load_rules()
        except Exception:
            QMessageBox.warning(self, "Ошибка", "Некорректный IP-адрес.")

    def add_port(self):
        port = self.port_input.text().strip()
        if not port.isdigit():
            QMessageBox.warning(self, "Ошибка", "Порт должен быть числом.")
            return
        port_int = int(port)
        if not (0 < port_int < 65536):
            QMessageBox.warning(self, "Ошибка", "Недопустимый номер порта.")
            return
        self.db.add_allowed_rule('port', port_int)
        self.port_input.clear()
        self.load_rules()

    def remove_selected_ip(self):
        item = self.ip_list.currentItem()
        if item:
            self.db.remove_allowed_rule('ip', item.text())
            self.load_rules()

    def remove_selected_port(self):
        item = self.port_list.currentItem()
        if item:
            self.db.remove_allowed_rule('port', item.text())
            self.load_rules()

    def accept(self):
        super().accept()