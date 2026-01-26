import sys
import asyncio
import struct
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton)
from PyQt6.QtCore import QThread, pyqtSignal, QObject

# --- [기존 SECS2, HSMSHeader, HSMSProtocol 클래스는 v1.2.2와 동일하므로 생략 가능하나 통합본에 포함] ---

class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    def __init__(self, name, host, port):
        super().__init__()
        self.name, self.host, self.port = name, host, port
        self.transport = None
        self.is_selected = False
        self._pending_tx = {}
        self._sys_byte = 0
        # HSMS 표준 파라미터 초기화
        self.T3, self.T5, self.T6, self.T7, self.T8 = 45.0, 10.0, 5.0, 10.0, 5.0

    async def connect_loop(self):
        while True:
            try:
                self.status_changed.emit(self.name, "CONNECTING")
                loop = asyncio.get_running_loop()
                # T5 타임아웃을 적용한 접속 시도
                self.transport, _ = await asyncio.wait_for(
                    loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), 
                    timeout=self.T5)
                
                # Select Procedure (T6 적용)
                resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.T6)
                if resp.s_type == 2:
                    self.is_selected = True
                    self.status_changed.emit(self.name, "SELECTED")
                    while self.is_selected: await asyncio.sleep(1)
            except Exception as e:
                self.is_selected = False
                self.status_changed.emit(self.name, "RETRYING")
                await asyncio.sleep(5)

    async def _send_raw(self, header, payload=b'', timeout=45.0):
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        future = asyncio.get_running_loop().create_future()
        self._pending_tx[self._sys_byte] = future
        msg = header.pack() + payload
        if self.transport:
            self.transport.write(struct.pack(">I", len(msg)) + msg)
        return await asyncio.wait_for(future, timeout)

# --- 4. 메인 GUI 창 (환경 설정 UI 포함) ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.setWindowTitle("HSMS Multi-Session Master v1.3.0")
        self.resize(1100, 700)
        
        main_layout = QHBoxLayout()
        
        # 왼쪽: 설정 패널
        config_box = QGroupBox("Connection & HSMS Parameters")
        config_layout = QFormLayout()
        self.edit_name = QLineEdit("EQP_01")
        self.edit_host = QLineEdit("127.0.0.1")
        self.edit_port = QLineEdit("5000")
        self.edit_t3 = QLineEdit("45")
        self.edit_t6 = QLineEdit("5")
        self.btn_add = QPushButton("Apply / Add Session")
        self.btn_add.clicked.connect(self.on_add_session)
        
        config_layout.addRow("Session Name:", self.edit_name)
        config_layout.addRow("Host IP:", self.edit_host)
        config_layout.addRow("Port:", self.edit_port)
        config_layout.addRow("T3 (Reply):", self.edit_t3)
        config_layout.addRow("T6 (Control):", self.edit_t6)
        config_layout.addRow(self.btn_add)
        config_box.setLayout(config_layout)
        config_box.setFixedWidth(300)

        # 오른쪽: 모니터링 패널
        view_layout = QVBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Address", "Status", "T3", "T6"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        
        view_layout.addWidget(QLabel("### Active Sessions"))
        view_layout.addWidget(self.table)
        view_layout.addWidget(QLabel("### Communication Log"))
        view_layout.addWidget(self.log_view)

        main_layout.addWidget(config_box)
        main_layout.addLayout(view_layout)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def on_add_session(self):
        name = self.edit_name.text()
        host = self.edit_host.text()
        port = int(self.edit_port.text())
        t3 = float(self.edit_t3.text())
        t6 = float(self.edit_t6.text())
        
        # 세션 추가 또는 업데이트 로직
        if name not in self.manager.sessions:
            self.add_row(name, host, port, t3, t6)
            self.manager.add_session(name, host, port)
        
        session = self.manager.sessions[name]
        session.T3, session.T6 = t3, t6
        self.log_view.append(f"[System] Config Updated: {name} (T3:{t3}s, T6:{t6}s)")

    def add_row(self, name, host, port, t3, t6):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(name))
        self.table.setItem(row, 1, QTableWidgetItem(f"{host}:{port}"))
        self.table.setItem(row, 2, QTableWidgetItem("IDLE"))
        self.table.setItem(row, 3, QTableWidgetItem(str(t3)))
        self.table.setItem(row, 4, QTableWidgetItem(str(t6)))

    def update_ui(self, name, status):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name:
                self.table.item(i, 2).setText(status)
        self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] {name}: {status}")

# --- [HSMSManager, HSMSProtocol, HSMSWorker 클래스는 이전 v1.2.2와 동일] ---
# (코드 중복 방지를 위해 로직은 위 소스코드와 통합하여 실행하세요)

def main():
    app = QApplication(sys.argv)
    manager = HSMSManager()
    monitor = HSMSMonitorApp(manager)
    
    # GUI 상에서 "Apply" 버튼을 누르기 전 기본 세션 로드 가능
    monitor.add_row("EQP_TEST", "127.0.0.1", 5000, 45.0, 5.0)
    manager.add_session("EQP_TEST", "127.0.0.1", 5000)

    worker = HSMSWorker(manager)
    worker.status_signal.connect(monitor.update_ui)
    worker.start()
    
    monitor.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()