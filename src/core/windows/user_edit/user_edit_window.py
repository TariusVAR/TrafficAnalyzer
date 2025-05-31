from PyQt5.QtWidgets import QMainWindow, QMessageBox
from PyQt5.uic import loadUi
from src.database.db_interface import DBInterface

class UserEditWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi("src/gui/user_edit.ui", self)

        self.db = DBInterface()
        self.load_users()

        self.comboBoxUserChoice.currentIndexChanged.connect(self.on_user_selected)
        self.btnSaveUserChanges.clicked.connect(self.save_changes)
        self.btnDeleteUser.clicked.connect(self.delete_user)
        self.btnExit.clicked.connect(self.close)

    def load_users(self):
        users = self.db.get_all_users()
        self.comboBoxUserChoice.clear()
        for user in users:
            self.comboBoxUserChoice.addItem(user['username'], user['id'])

        self.comboBoxUserRole.clear()
        self.comboBoxUserRole.addItems(["admin", "user"])

    def on_user_selected(self, index):
        user_id = self.comboBoxUserChoice.itemData(index)
        role = self.db.get_user_role(user_id)
        role_index = self.comboBoxUserRole.findText(role)
        if role_index != -1:
            self.comboBoxUserRole.setCurrentIndex(role_index)

    def save_changes(self):
        user_id = self.comboBoxUserChoice.currentData()
        new_role = self.comboBoxUserRole.currentText()
        success = self.db.update_user_role(user_id, new_role)

        if success:
            QMessageBox.information(self, "Успех", "Роль пользователя обновлена.")
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось обновить роль пользователя.")

    def delete_user(self):
        user_id = self.comboBoxUserChoice.currentData()
        confirm = QMessageBox.question(
            self,
            "Подтверждение удаления",
            "Вы уверены, что хотите удалить этого пользователя?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            success = self.db.delete_user(user_id)

            if success:
                QMessageBox.information(self, "Удалено", "Пользователь успешно удалён.")
                self.load_users()
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось удалить пользователя.")
