from PyQt5 import QtWidgets, QtGui
import os

class PDFButton(QtWidgets.QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.clicked.connect(self.open_pdf)

    def open_pdf(self):
        #pdf path to pdf file from this folder
        pdf_path = os.path.join(os.path.dirname(__file__), 'raport.pdf')
        os.startfile(pdf_path)

if __name__ == '__main__':
    app = QtWidgets.QApplication([])
    button = PDFButton()
    button.show()
    app.exec_()
