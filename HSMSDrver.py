import sys
import asyncio
import struct
import socket
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton, QComboBox, 
                             QRadioButton, QButtonGroup, QGridLayout)
from PyQt6.QtCore import QThread, pyqtSignal, QObject

# --- [1. HSMS Header & Decoder] ---
class HSMSHeader:
    def __init__(self, stream=0, function=0, s_type=0, system_bytes=0):
        self.stream, self.function, self.s_type = stream, function, s_type
        self.system_bytes = system_bytes

    def pack(self):
        # 10-byte HSMS Header: SessionID(2), S, F, PType(0), SType, SystemBytes(4)
        return struct.pack(">HBBBBI", 0, self.stream, self.function, 0, self.s_type, self.system_bytes)

    @classmethod
    def unpack(cls, data):
        h = struct.unpack(">HBBBBI", data)
        return cls(stream=h[1], function=h[2], s_type=h[4], system_bytes=h[5])

    def get_desc(self):
        stype_map = {0: "Data", 1: "Select.req", 2: "Select.rsp", 5: "Linktest.req", 6: "Linktest.rsp"}
        desc = stype_map.get(self.s_type, f"Type:{self.s_type}")
        if self.s_type == 0:
            return f"S{self.stream}F{self.function}"
        return desc

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
            
            # 로그 출력용 시그널 전송
            self.instance.log_signal.emit(f"RECV | {header.get_desc()} | SysByte: {header.system_bytes}")
            
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, raw[10:]))

# --- [2. HSMS Instance with Full T-Params] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    log_signal = pyqtSignal(str)

    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0, 'T7': 10.0, 'T8': 5.0}
        self.transport = None
        self.server = None
        self.running = False
        self._pending_tx = {}
        self._sys_byte = 0

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                loop = asyncio.get_running_loop()
                if self.mode == "Active":
                    self.status_changed.emit(self.name, "ACT_CONNECTING")
                    # T5: Connect Timeout 적용
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), 
                        timeout=self.params['T5'])
                    
                    # T6: Select Response Timeout 적용
                    self.log_signal.emit(f"SEND | Select.req")
                    resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and not self.transport.is_closing():
                            await asyncio.sleep(1)
                else: # Passive Mode
                    self.status_changed.emit(self.name, f"PAS_LISTENING({self.port})")
                    self.server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with self.server:
                        await self.server.serve_forever()
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
        raise ConnectionError("No transport")

# --- [3. Main GUI App] ---
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
            return f"{socket.gethostname()} ({ip})"
        except: return "Unknown"

    def init_ui(self):
        self.setWindowTitle("HSMS Master v1.8.0 - Full T-Parameter Control")
        self.resize(1300, 850)
        main_layout = QHBoxLayout()
        
        # --- Left Panel ---
        left_panel = QVBoxLayout()
        
        net_group = QGroupBox("Local Information")
        net_layout = QVBoxLayout()
        self.lbl_net = QLabel(f"PC: {self.get_local_ip()}")
        self.lbl_net.setStyleSheet("font-weight: bold; color: #2980b9;")
        net_layout.addWidget(self.lbl_net)
        net_group.setLayout(net_layout)
        
        config_group = QGroupBox("Node Configuration")
        form = QFormLayout()
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- Add New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        
        mode_layout = QHBoxLayout()
        self.rb_active = QRadioButton("Active")
        self.rb_passive = QRadioButton("Passive")
        self.rb_active.setChecked(True)
        mode_layout.addWidget(self.rb_active); mode_layout.addWidget(self.rb_passive)
        
        # T-Parameters Grid
        t_param_group = QGroupBox("HSMS Timeouts (sec)")
        t_grid = QGridLayout()
        self.in_t3, self.in_t5 = QLineEdit("45"), QLineEdit("10")
        self.in_t6, self.in_t7 = QLineEdit("5"), QLineEdit("10")
        self.in_t8 = QLineEdit("5")
        t_grid.addWidget(QLabel("T3 (Reply):"), 0, 0); t_grid.addWidget(self.in_t3, 0, 1)
        t_grid.addWidget(QLabel("T5 (Conn):"), 0, 2); t_grid.addWidget(self.in_t5, 0, 3)
        t_grid.addWidget(QLabel("T6 (Ctrl):"), 1, 0); t_grid.addWidget(self.in_t6, 1, 1)
        t_grid.addWidget(QLabel("T7 (Sel):"), 1, 2); t_grid.addWidget(self.in_t7, 1, 3)
        t_grid.addWidget(QLabel("T8 (Net):"), 2, 0); t_grid.addWidget(self.in_t8, 2, 1)
        t_param_group.setLayout(t_grid)
        
        btn_apply = QPushButton("Apply Configuration")
        btn_apply.setStyleSheet("background-color: #34495e; color: white; font-weight: bold; padding: 10px;")
        btn_apply.clicked.connect(self.apply_node)
        
        form.addRow("Select Node:", self.combo_nodes)
        form.addRow("Mode:", mode_layout)
        form.addRow("Node Name:", self.in_name)
        form.addRow("Target IP:", self.in_host)
        form.addRow("Port (Local/Remote):", self.in_port)
        
        left_panel.addWidget(net_group)
        left_panel.addLayout(form)
        left_panel.addWidget(t_param_group)
        left_panel.addWidget(btn_apply)
        
        ctrl_group = QGroupBox("Comm Control")
        cl = QHBoxLayout()
        self.btn_start, self.btn_stop = QPushButton("START"), QPushButton("STOP")
        self.btn_start.clicked.connect(self.start_comm)
        self.btn_stop.clicked.connect(self.stop_comm)
        self.btn_start.setStyleSheet("background-color: #27ae60; color: white;")
        self.btn_stop.setStyleSheet("background-color: #c0392b; color: white;")
        cl.addWidget(self.btn_start); cl.addWidget(self.btn_stop)
        ctrl_group.setLayout(cl)
        left_panel.addWidget(ctrl_group)
        left_panel.addStretch()

        # --- Right Panel ---
        right_panel = QVBoxLayout()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Name", "Mode", "Port", "Status", "T-Params", "Last Update"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background: #000000; color: #00FF41; font-family: Consolas; font-size: 10pt;")
        
        right_panel.addWidget(QLabel("### Multi-Node Status Grid"))
        right_panel.addWidget(self.table)
        right_panel.addWidget(QLabel("### Real-time HSMS Message Log (SxFy)"))
        right_panel.addWidget(self.log_view)
        
        main_layout.addLayout(left_panel, 1)
        main_layout.addLayout(right_panel, 3)
        self.setCentralWidget(QWidget()); self.centralWidget().setLayout(main_layout)

    def on_node_selected(self, index):
        if index == 0: self.in_name.setText(""); self.in_name.setReadOnly(False)
        else:
            name = self.combo_nodes.currentText()
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_name.setReadOnly(True)
            self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            self.rb_active.setChecked(inst.mode == "Active")
            self.rb_passive.setChecked(inst.mode == "Passive")
            p = inst.params
            self.in_t3.setText(str(p['T3'])); self.in_t5.setText(str(p['T5']))
            self.in_t6.setText(str(p['T6'])); self.in_t7.setText(str(p['T7']))
            self.in_t8.setText(str(p['T8']))

    def apply_node(self):
        name = self.in_name.text()
        mode = "Active" if self.rb_active.isChecked() else "Passive"
        params = {
            'T3': float(self.in_t3.text()), 'T5': float(self.in_t5.text()),
            'T6': float(self.in_t6.text()), 'T7': float(self.in_t7.text()),
            'T8': float(self.in_t8.text())
        }
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), mode, params)
            inst.status_changed.connect(self.update_grid)
            inst.log_signal.connect(lambda msg: self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {name} > {msg}"))
            self.sessions[name] = inst
            self.combo_nodes.addItem(name)
            self.table.insertRow(self.table.rowCount())
        else:
            self.sessions[name].mode = mode
            self.sessions[name].params = params
        self.update_grid(name, "READY")

    def update_grid(self, name, status):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0) and self.table.item(i, 0).text() == name:
                inst = self.sessions[name]
                p = inst.params
                self.table.setItem(i, 0, QTableWidgetItem(name))
                self.table.setItem(i, 1, QTableWidgetItem(inst.mode))
                self.table.setItem(i, 2, QTableWidgetItem(str(inst.port)))
                self.table.setItem(i, 3, QTableWidgetItem(status))
                self.table.setItem(i, 4, QTableWidgetItem(f"T3:{p['T3']} T5:{p['T5']} T6:{p['T6']}"))
                self.table.setItem(i, 5, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))

    def start_comm(self):
        name = self.in_name.text()
        if name in self.sessions and not self.sessions[name].running:
            asyncio.run_coroutine_threadsafe(self.sessions[name].run_task(), self.loop)

    def stop_comm(self):
        name = self.in_name.text()
        if name in self.sessions: self.sessions[name].running = False

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
    thread = AsyncLoopThread(); thread.start()
    while not thread.loop: pass
    win = HSMSMonitorApp(thread.loop); win.show()
    sys.exit(app.exec())

