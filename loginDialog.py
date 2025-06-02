from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QDialogButtonBox, QLabel, QLineEdit,
                             QVBoxLayout)


class LoginDialog(QDialog):

    def __init__(self, parent=None):
        super(LoginDialog, self).__init__(parent)
        self.setWindowTitle('登录账号')

        layout = QVBoxLayout(self)

        self.label1 = QLabel(self)
        self.label1.setText('账号')

        self.label2 = QLabel(self)
        self.label2.setText('密码')

        self.account = QLineEdit(self)
        self.account.setEchoMode(QLineEdit.Normal)

        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)

        layout.addWidget(self.label1)
        layout.addWidget(self.account)
        layout.addWidget(self.label2)
        layout.addWidget(self.password)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
