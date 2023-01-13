from PyQt5.QtWidgets import QToolBar, QAbstractButton, QApplication
from PyQt5.QtCore import QTimer, QObject, pyqtSlot, QEvent


class KPToolBar(QToolBar):
    def __init__(self, title, parent=None):
        super().__init__(title, parent)
        self.init()

    def init(self):
        self.m_expandButton = self.findChild(QAbstractButton, "qt_toolbar_ext_button")
        self.m_expandTimer = QTimer()
        self.m_expandTimer.setSingleShot(True)
        self.m_expandTimer.timeout.connect(self.setExpanded)

    def isExpanded(self):
        return not self.canExpand() or (self.canExpand() and self.m_expandButton.isChecked())

    def canExpand(self):
        return self.m_expandButton and self.m_expandButton.isVisible()

    @pyqtSlot(bool)
    def setExpanded(self, state):
        if self.canExpand():
            self.layout().setExpanded(state)
        else:
            QApplication.instance().warning("Toolbar: Cannot invoke setExpanded!")

    def event(self, event):
        if event.type() == QEvent.Leave:
            self.m_expandTimer.start(2000)
            return True
        elif event.type() == QEvent.Enter:
            self.m_expandTimer.stop()
            return True
        else:
            return super().event(event)
