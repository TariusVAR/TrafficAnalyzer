import re
import bcrypt
from PyQt5.QtWidgets import QMainWindow, QMessageBox
from PyQt5.uic import loadUi
from src.database.db_interface import DBInterface


class AuthWindow(QMainWindow):
    def __init__(self, on_auth_success):
        super().__init__()
        loadUi("src/gui/authorisation.ui", self)
        self.on_auth_success = on_auth_success

        self.db = DBInterface()

        self.pushButtonLogin.clicked.connect(self.login)
        self.pushButtonRegistration.clicked.connect(self.register)
        self.pushButtonCancelAuth.clicked.connect(self.close)

    def validate_credentials(self, username, password):
        if len(username) < 3 or not re.match(r'^\w+$', username):
            return False, "Логин должен содержать только буквы, цифры и подчёркивания (от 3 символов)"

        if len(password) < 8:
            return False, "Пароль должен быть не менее 8 символов"
        if not re.search(r'[A-Za-z]', password):
            return False, "Пароль должен содержать хотя бы одну букву"
        if not re.search(r'\d', password):
            return False, "Пароль должен содержать хотя бы одну цифру"

        return True, None

    def login(self):
        username = self.textEditLogin.toPlainText().strip()
        password = self.textEditPassword.toPlainText().strip()

        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Введите логин и пароль")
            return

        valid, message = self.validate_credentials(username, password)
        if not valid:
            QMessageBox.warning(self, "Ошибка", message)
            return

        user = self.db.get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode(), user[1].encode()):
            user_id = user[0]
            self.on_auth_success(user_id, username)
            QMessageBox.information(self, "Успешно", f"Добро пожаловать, {username}")
            self.close()
        else:
            QMessageBox.critical(self, "Ошибка", "Неверный логин или пароль")

    def register(self):
        username = self.textEditLogin.toPlainText().strip()
        password = self.textEditPassword.toPlainText().strip()

        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Введите логин и пароль")
            return

        valid, message = self.validate_credentials(username, password)
        if not valid:
            QMessageBox.warning(self, "Ошибка", message)
            return

        success, error = self.db.register_user(username, password)
        if success:
            QMessageBox.information(self, "Готово", "Регистрация прошла успешно")
        else:
            QMessageBox.warning(self, "Ошибка", error or "Не удалось зарегистрироваться")
