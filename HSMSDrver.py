import sys
import asyncio
import struct
import socket
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton, QComboBox, QRadioButton, QButtonGroup)
from PyQt6.QtCore import QThread, pyqtSignal, QObject

# --- [HSMS Header & Protocol] ---
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
    def connection_lost(self, exc):
        self.instance.is_selected = False

# --- [HSMS Instance: Active/Passive Logic] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0}
        self.transport = None
        self.server = None
        self.running = False
        self._pending_tx = {}
        self._sys_byte = 0

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                if self.mode == "Active":
                    self.status_changed.emit(self.name, "ACT_CONNECTING")
                    loop = asyncio.get_running_loop()
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=self.params['T5'])
                else: # Passive Mode
                    self.status_changed.emit(self.name, "PAS_LISTENING")
                    loop = asyncio.get_running_loop()
                    self.server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with self.server:
                        await self.server.serve_forever()

                # Select Procedure (Common)
                if self.mode == "Active":
                    resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and not self.transport.is_closing(): await asyncio.sleep(1)
            except Exception as e:
                if self.running:
                    self.status_changed.emit(self.name, "RETRYING(5s)")
                    await asyncio.sleep(5)
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

# --- [Main GUI App] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, loop):
        super().__init__()
        self.sessions = {}
        self.loop = loop
        self.init_ui()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return f"{socket.gethostname()} ({ip})"
        except: return "Unknown"

    def init_ui(self):
        self.setWindowTitle("HSMS Master v1.6.0 (Active/Passive)")
        self.resize(1200, 750)
        main_layout = QHBoxLayout()
        
        # --- 왼쪽 패널 ---
        left_panel = QVBoxLayout()
        
        # 1. Network Info
        net_group = QGroupBox("Local Network Information")
        net_layout = QVBoxLayout()
        self.lbl_net = QLabel(f"PC: {self.get_local_ip()}")
        self.lbl_net.setStyleSheet("font-weight: bold; color: #3498db;")
        net_layout.addWidget(self.lbl_net)
        net_group.setLayout(net_layout)
        
        # 2. Configuration
        config_group = QGroupBox("Node Configuration")
        form = QFormLayout()
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        
        # Mode Selection
        mode_layout = QHBoxLayout()
        self.rb_active = QRadioButton("Active")
        self.rb_passive = QRadioButton("Passive")
        self.rb_active.setChecked(True)
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.rb_active)
        self.mode_group.addButton(self.rb_passive)
        mode_layout.addWidget(self.rb_active)
        mode_layout.addWidget(self.rb_passive)
        
        btn_apply = QPushButton("Apply Configuration")
        btn_apply.clicked.connect(self.apply_node)
        
        form.addRow("Select Node:", self.combo_nodes)
        form.addRow("Mode:", mode_layout)
        form.addRow("Name:", self.in_name)
        form.addRow("Target IP:", self.in_host)
        form.addRow("Port:", self.in_port)
        form.addRow(btn_apply)
        config_group.setLayout(form)
        
        # 3. Control
        ctrl_group = QGroupBox("Communication Control")
        cl = QHBoxLayout()
        self.btn_start, self.btn_stop = QPushButton("START"), QPushButton("STOP")
        self.btn_start.clicked.connect(self.start_comm)
        self.btn_stop.clicked.connect(self.stop_comm)
        cl.addWidget(self.btn_start)
        cl.addWidget(self.btn_stop)
        ctrl_group.setLayout(cl)
        
        left_panel.addWidget(net_group)
        left_panel.addWidget(config_group)
        left_panel.addWidget(ctrl_group)
        left_panel.addStretch()

        # --- 오른쪽 패널 ---
        right_panel = QVBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Mode", "Address", "Status", "Update Time"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background: #1e1e1e; color: #00ff00; font-family: Consolas;")
        
        right_panel.addWidget(QLabel("### Multi-Node Real-time Grid"))
        right_panel.addWidget(self.table)
        right_panel.addWidget(self.log_view)
        
        main_layout.addLayout(left_panel, 1)
        main_layout.addLayout(right_panel, 3)
        self.setCentralWidget(QWidget())
        self.centralWidget().setLayout(main_layout)

    def on_node_selected(self, index):
        if index == 0: self.in_name.setText(""); self.in_name.setReadOnly(False)
        else:
            name = self.combo_nodes.currentText()
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_name.setReadOnly(True)
            self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            if inst.mode == "Active": self.rb_active.setChecked(True)
            else: self.rb_passive.setChecked(True)

    def apply_node(self):
        name = self.in_name.text()
        mode = "Active" if self.rb_active.isChecked() else "Passive"
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), mode)
            inst.status_changed.connect(self.update_grid)
            self.sessions[name] = inst
            self.combo_nodes.addItem(name)
            self.table.insertRow(self.table.rowCount())
        self.update_grid(name, "CONFIG_UPDATED")

    def update_grid(self, name, status):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0) and self.table.item(i, 0).text() == name:
                inst = self.sessions[name]
                self.table.setItem(i, 0, QTableWidgetItem(name))
                self.table.setItem(i, 1, QTableWidgetItem(inst.mode))
                self.table.setItem(i, 2, QTableWidgetItem(f"{inst.host}:{inst.port}"))
                self.table.setItem(i, 3, QTableWidgetItem(status))
                self.table.setItem(i, 4, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] {name} ({self.sessions[name].mode}): {status}")

    def start_comm(self):
        name = self.in_name.text()
        if name in self.sessions and not self.sessions[name].running:
            asyncio.run_coroutine_threadsafe(self.sessions[name].run_task(), self.loop)

    def stop_comm(self):
        name = self.in_name.text()
        if name in self.sessions: self.sessions[name].running = False

# --- [Worker Thread] ---
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
    thread = AsyncLoopThread()
    thread.start()
    while not thread.loop: pass
    win = HSMSMonitorApp(thread.loop)
    win.show()
    sys.exit(app.exec())

