import sys
import asyncio
import struct
import json
import logging
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton)
from PyQt6.QtCore import QThread, pyqtSignal, QObject

# --- [1. SECS-II 기초 인코더] ---
class SECS2:
    LIST, ASCII, I4 = 0x00, 0x10, 0x70
    @staticmethod
    def encode_item(item_type, data):
        if item_type == SECS2.ASCII:
            encoded = data.encode('ascii')
            return struct.pack("BB", item_type | 1, len(encoded)) + encoded
        elif item_type == SECS2.I4:
            return struct.pack("BB i", item_type | 1, 4, data)
        elif item_type == SECS2.LIST:
            combined = b''.join(data)
            return struct.pack("BB", item_type | 1, len(data)) + combined
        return b''

# --- [2. HSMS 헤더 구조체] ---
class HSMSHeader:
    def __init__(self, stream=0, function=0, s_type=0, system_bytes=0):
        self.stream, self.function, self.s_type = stream, function, s_type
        self.system_bytes = system_bytes
    def pack(self):
        return struct.pack(">HBBBBI", 0, self.stream, self.function, 0, self.s_type, self.system_bytes)
    @classmethod
    def unpack(cls, data):
        h = struct.unpack(">HBBBBI", data)
        return cls(stream=h[1], function=h[2], s_type=h[4], system_bytes=h[5])

# --- [3. 개별 접속 인스턴스 및 자동 재접속] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    def __init__(self, name, host, port, params=None):
        super().__init__()
        self.name, self.host, self.port = name, host, port
        self.transport = None
        self.is_selected = False
        self._pending_tx = {}
        self._sys_byte = 0
        p = params or {}
        self.T3 = float(p.get('T3', 45.0))
        self.T5 = float(p.get('T5', 10.0))
        self.T6 = float(p.get('T6', 5.0))

    async def connect_loop(self):
        while True:
            try:
                self.status_changed.emit(self.name, "CONNECTING")
                loop = asyncio.get_running_loop()
                # T5: Connect Timeout 적용
                self.transport, _ = await asyncio.wait_for(
                    loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=self.T5)
                
                # Select.req (T6 적용)
                resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.T6)
                if resp.s_type == 2:
                    self.is_selected = True
                    self.status_changed.emit(self.name, "SELECTED")
                    while self.is_selected: await asyncio.sleep(1)
            except Exception:
                self.is_selected = False
                self.status_changed.emit(self.name, "RETRYING(5s)")
                await asyncio.sleep(5)

    async def _send_raw(self, header, payload=b'', timeout=45.0):
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        future = asyncio.get_running_loop().create_future()
        self._pending_tx[self._sys_byte] = future
        if self.transport:
            msg = header.pack() + payload
            self.transport.write(struct.pack(">I", len(msg)) + msg)
        return await asyncio.wait_for(future, timeout)

# --- [4. 프로토콜 핸들러] ---
class HSMSProtocol(asyncio.Protocol):
    def __init__(self, instance):
        self.instance = instance
        self.buf = bytearray()
    def data_received(self, data):
        self.buf.extend(data)
        while len(self.buf) >= 4:
            length = struct.unpack(">I", self.buf[:4])[0]
            if len(self.buf) < 4 + length: break
            raw = self.buf[4:4+length]
            self.buf = self.buf[4+length:]
            header = HSMSHeader.unpack(raw[:10])
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, raw[10:]))

# --- [5. 세션 매니저 (에러 원인 해결을 위해 상단 배치)] ---
class HSMSManager:
    def __init__(self):
        self.sessions = {}
    def add_session(self, name, host, port, params=None):
        self.sessions[name] = HSMSInstance(name, host, port, params)

# --- [6. 백그라운드 비동기 워커] ---
class HSMSWorker(QThread):
    status_signal = pyqtSignal(str, str)
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for s in self.manager.sessions.values():
            s.status_changed.connect(self.status_signal.emit)
        tasks = [s.connect_loop() for s in self.manager.sessions.values()]
        loop.run_until_complete(asyncio.gather(*tasks))

# --- [7. 메인 GUI 모니터링 및 설정 창] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.config_path = "hsms_config.json"
        self.init_ui()
        self.load_config_file()

    def init_ui(self):
        self.setWindowTitle("HSMS Multi-Session Master v1.3.2")
        self.resize(1100, 650)
        main_layout = QHBoxLayout()
        
        # 좌측 설정 패널
        left_panel = QGroupBox("Configuration")
        form = QFormLayout()
        self.ui_name = QLineEdit("EQP_01")
        self.ui_host = QLineEdit("127.0.0.1")
        self.ui_port = QLineEdit("5000")
        self.ui_t3 = QLineEdit("45")
        self.ui_t6 = QLineEdit("5")
        btn_apply = QPushButton("Apply & Save Config")
        btn_apply.clicked.connect(self.save_and_apply)
        
        form.addRow("Name:", self.ui_name)
        form.addRow("IP Address:", self.ui_host)
        form.addRow("Port:", self.ui_port)
        form.addRow("T3 Timeout:", self.ui_t3)
        form.addRow("T6 Timeout:", self.ui_t6)
        form.addRow(btn_apply)
        left_panel.setLayout(form)
        left_panel.setFixedWidth(280)

        # 우측 모니터링 패널
        right_panel = QVBoxLayout()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Name", "Address", "Status", "Params"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background-color: #1e1e1e; color: #00ff00;")

        right_panel.addWidget(QLabel("### Connection Dashboard"))
        right_panel.addWidget(self.table)
        right_panel.addWidget(QLabel("### System Activity Log"))
        right_panel.addWidget(self.log_view)

        main_layout.addWidget(left_panel)
        main_layout.addLayout(right_panel)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def save_and_apply(self):
        name = self.ui_name.text()
        config = {
            "host": self.ui_host.text(),
            "port": int(self.ui_port.text()),
            "T3": float(self.ui_t3.text()),
            "T6": float(self.ui_t6.text())
        }
        # 여기에 실제 JSON 파일 쓰기 로직 추가 가능
        self.add_session_to_ui(name, config)
        self.log_view.append(f"[System] Config applied for {name}")

    def add_session_to_ui(self, name, cfg):
        if name not in self.manager.sessions:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(name))
            self.table.setItem(row, 1, QTableWidgetItem(f"{cfg['host']}:{cfg['port']}"))
            self.table.setItem(row, 2, QTableWidgetItem("IDLE"))
            self.table.setItem(row, 3, QTableWidgetItem(f"T3:{cfg['T3']} T6:{cfg['T6']}"))
            self.manager.add_session(name, cfg['host'], cfg['port'], cfg)

    def update_status_ui(self, name, status):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name:
                self.table.item(i, 2).setText(status)
        self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] {name}: {status}")

    def load_config_file(self):
        # 초기 기본값 로드 예시
        default_cfg = {"host": "127.0.0.1", "port": 5000, "T3": 45.0, "T6": 5.0}
        self.add_session_to_ui("EQP_INIT", default_cfg)

# --- [8. 메인 진입점] ---
def main():
    app = QApplication(sys.argv)
    manager = HSMSManager()
    monitor = HSMSMonitorApp(manager)
    
    worker = HSMSWorker(manager)
    worker.status_signal.connect(monitor.update_status_ui)
    worker.start()
    
    monitor.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

