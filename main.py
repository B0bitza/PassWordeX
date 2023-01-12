import sys
from PyQt5 import QtCore, QtGui, QtWidgets, uic

app = QtWidgets.QApplication(sys.argv)

welcomeWidget = uic.loadUi("PaginaStart.ui")
welcomeWidget.show()

sys.exit(app.exec_())
