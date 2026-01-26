import sys
import asyncio
import struct
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton, QComboBox)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, pyqtSlot

# --- [HSMS 기초 구조체 및 프로토콜은 이전 버전과 동일하므로 생략 없이 포함] ---
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

# --- [HSMS 개별 인스턴스: 개별 시작/중지 로직 추가] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    def __init__(self, name, host, port, params=None):
        super().__init__()
        self.name, self.host, self.port = name, host, port
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0}
        self.transport = None
        self.running = False
        self._pending_tx = {}
        self._sys_byte = 0

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                self.status_changed.emit(self.name, "CONNECTING")
                loop = asyncio.get_running_loop()
                self.transport, _ = await asyncio.wait_for(
                    loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), 
                    timeout=self.params['T5'])
                
                resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.params['T6'])
                if resp.s_type == 2:
                    self.status_changed.emit(self.name, "SELECTED")
                    while self.running and not self.transport.is_closing():
                        await asyncio.sleep(1)
            except Exception:
                if self.running:
                    self.status_changed.emit(self.name, "RETRYING(5s)")
                    await asyncio.sleep(5)
        
        if self.transport:
            self.transport.close()
        self.status_changed.emit(self.name, "STOPPED")

    async def _send_raw(self, header, payload=b'', timeout=45.0):
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        future = asyncio.get_running_loop().create_future()
        self._pending_tx[self._sys_byte] = future
        if self.transport:
            msg = header.pack() + payload
            self.transport.write(struct.pack(">I", len(msg)) + msg)
        return await asyncio.wait_for(future, timeout)

# --- [통합 GUI 매니저] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sessions = {}
        self.tasks = {}
        self.loop = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HSMS Multi-Node Controller v1.5.0")
        self.resize(1200, 700)
        
        main_layout = QHBoxLayout()
        
        # --- 왼쪽: 설정 및 제어 패널 ---
        left_panel = QVBoxLayout()
        config_group = QGroupBox("Node Configuration")
        form = QFormLayout()
        
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        
        self.in_name = QLineEdit()
        self.in_host = QLineEdit("127.0.0.1")
        self.in_port = QLineEdit("5000")
        self.in_t3 = QLineEdit("45")
        self.in_t6 = QLineEdit("5")
        
        btn_apply = QPushButton("Apply & Update Node")
        btn_apply.clicked.connect(self.apply_node_config)
        
        form.addRow("Select Node:", self.combo_nodes)
        form.addRow("Node Name:", self.in_name)
        form.addRow("Host IP:", self.in_host)
        form.addRow("Port:", self.in_port)
        form.addRow("T3 Timeout:", self.in_t3)
        form.addRow("T6 Timeout:", self.in_t6)
        form.addRow(btn_apply)
        config_group.setLayout(form)
        
        control_group = QGroupBox("Communication Control")
        ctrl_layout = QHBoxLayout()
        self.btn_start = QPushButton("START")
        self.btn_stop = QPushButton("STOP")
        self.btn_start.clicked.connect(self.start_comm)
        self.btn_stop.clicked.connect(self.stop_comm)
        self.btn_start.setStyleSheet("background-color: #2ecc71; color: white; font-weight: bold;")
        self.btn_stop.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold;")
        ctrl_layout.addWidget(self.btn_start)
        ctrl_layout.addWidget(self.btn_stop)
        control_group.setLayout(ctrl_layout)
        
        left_panel.addWidget(config_group)
        left_panel.addWidget(control_group)
        left_panel.addStretch()

        # --- 오른쪽: 그리드 및 로그 ---
        right_panel = QVBoxLayout()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Name", "Address", "Status", "T3", "T6", "Last Update"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        
        right_panel.addWidget(QLabel("### Multi-Node Monitoring Grid"))
        right_panel.addWidget(self.table)
        right_panel.addWidget(QLabel("### System Event Logs"))
        right_panel.addWidget(self.log_view)
        
        main_layout.addLayout(left_panel, 1)
        main_layout.addLayout(right_panel, 3)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    # --- 제어 로직 ---
    def on_node_selected(self, index):
        if index == 0: # New Node
            self.in_name.setText("")
            self.in_name.setReadOnly(False)
        else:
            name = self.combo_nodes.currentText()
            inst = self.sessions[name]
            self.in_name.setText(name)
            self.in_name.setReadOnly(True)
            self.in_host.setText(inst.host)
            self.in_port.setText(str(inst.port))
            self.in_t3.setText(str(inst.params['T3']))
            self.in_t6.setText(str(inst.params['T6']))

    def apply_node_config(self):
        name = self.in_name.text()
        if not name: return
        
        params = {'T3': float(self.in_t3.text()), 'T5': 10.0, 'T6': float(self.in_t6.text())}
        
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), params)
            inst.status_changed.connect(self.update_grid_status)
            self.sessions[name] = inst
            self.combo_nodes.addItem(name)
            self.add_grid_row(name, inst)
        else:
            inst = self.sessions[name]
            inst.host = self.in_host.text()
            inst.port = int(self.in_port.text())
            inst.params = params
            self.update_grid_row(name, inst)
            
        self.log_view.append(f"[System] Node '{name}' configuration updated.")

    def add_grid_row(self, name, inst):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(name))
        self.table.setItem(row, 1, QTableWidgetItem(f"{inst.host}:{inst.port}"))
        self.table.setItem(row, 2, QTableWidgetItem("IDLE"))
        self.table.setItem(row, 3, QTableWidgetItem(str(inst.params['T3'])))
        self.table.setItem(row, 4, QTableWidgetItem(str(inst.params['T6'])))
        self.table.setItem(row, 5, QTableWidgetItem("-"))

    def update_grid_row(self, name, inst):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name:
                self.table.item(i, 1).setText(f"{inst.host}:{inst.port}")
                self.table.item(i, 3).setText(str(inst.params['T3']))
                self.table.item(i, 4).setText(str(inst.params['T6']))

    def update_grid_status(self, name, status):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name:
                self.table.item(i, 2).setText(status)
                self.table.item(i, 5).setText(datetime.now().strftime("%H:%M:%S"))
        self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] {name}: {status}")

    def start_comm(self):
        name = self.in_name.text()
        if name in self.sessions and not self.sessions[name].running:
            self.tasks[name] = asyncio.run_coroutine_threadsafe(self.sessions[name].run_task(), self.loop)
            self.log_view.append(f"[Control] Starting communication for {name}...")

    def stop_comm(self):
        name = self.in_name.text()
        if name in self.sessions:
            self.sessions[name].running = False
            self.log_view.append(f"[Control] Stopping communication for {name}...")

# --- [비동기 루프 스레드] ---
class AsyncLoopThread(QThread):
    def __init__(self):
        super().__init__()
        self.loop = None
    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # 비동기 루프를 별도 스레드에서 상시 실행
    async_thread = AsyncLoopThread()
    async_thread.start()
    
    # 0.1초 정도 대기하여 루프가 생성되도록 함
    import time
    while async_thread.loop is None: time.sleep(0.1)
    
    window = HSMSMonitorApp()
    window.loop = async_thread.loop
    window.show()
    
    sys.exit(app.exec())
