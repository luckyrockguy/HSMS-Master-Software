import sys
import asyncio
import struct
import socket
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton, QComboBox, 
                             QRadioButton, QButtonGroup, QGridLayout)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt

# --- [1. HSMS Header & Decoder] ---
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

    def get_desc(self):
        stype_map = {0: "Data", 1: "Select.req", 2: "Select.rsp", 5: "Linktest.req", 6: "Linktest.rsp"}
        desc = stype_map.get(self.s_type, f"Type:{self.s_type}")
        return f"S{self.stream}F{self.function}" if self.s_type == 0 else desc

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
            self.instance.log_signal.emit(f"RECV | {header.get_desc()} | SysByte: {header.system_bytes}")
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, raw[10:]))

# --- [2. HSMS Instance] ---
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
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=self.params['T5'])
                    
                    self.log_signal.emit(f"SEND | Select.req")
                    resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and self.transport and not self.transport.is_closing():
                            await asyncio.sleep(1)
                else:
                    self.status_changed.emit(self.name, f"PAS_LISTENING({self.port})")
                    self.server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with self.server:
                        await self.server.serve_forever()
            except Exception:
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
        raise ConnectionError("Disconnected")

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
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return f"{socket.gethostname()} ({ip})"
        except: return "Unknown"

    def init_ui(self):
        self.setWindowTitle("HSMS Master v1.8.5 - Real-time Update Fixed")
        self.resize(1200, 800)
        main_layout = QHBoxLayout()
        
        # --- Left Panel ---
        left_panel = QVBoxLayout()
        
        net_info = QGroupBox("Local Network")
        net_l = QVBoxLayout()
        self.lbl_net = QLabel(f"PC: {self.get_local_ip()}")
        net_l.addWidget(self.lbl_net)
        net_info.setLayout(net_l)
        
        cfg_info = QGroupBox("Node Configuration")
        form = QFormLayout()
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- Add New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        
        m_layout = QHBoxLayout()
        self.rb_act, self.rb_pas = QRadioButton("Active"), QRadioButton("Passive")
        self.rb_act.setChecked(True)
        m_layout.addWidget(self.rb_act); m_layout.addWidget(self.rb_pas)

        # T-Params
        t_group = QGroupBox("Timeouts")
        t_grid = QGridLayout()
        self.in_t3, self.in_t5, self.in_t6 = QLineEdit("45"), QLineEdit("10"), QLineEdit("5")
        t_grid.addWidget(QLabel("T3:"),0,0); t_grid.addWidget(self.in_t3,0,1)
        t_grid.addWidget(QLabel("T5:"),0,2); t_grid.addWidget(self.in_t5,0,3)
        t_grid.addWidget(QLabel("T6:"),1,0); t_grid.addWidget(self.in_t6,1,1)
        t_group.setLayout(t_grid)

        btn_apply = QPushButton("Apply Configuration")
        btn_apply.clicked.connect(self.apply_node)
        
        form.addRow("Select:", self.combo_nodes)
        form.addRow("Mode:", m_layout)
        form.addRow("Name:", self.in_name)
        form.addRow("IP:", self.in_host)
        form.addRow("Port:", self.in_port)
        
        ctrl_group = QGroupBox("Control")
        cl = QHBoxLayout()
        self.btn_start, self.btn_stop = QPushButton("START"), QPushButton("STOP")
        self.btn_start.clicked.connect(self.start_comm)
        self.btn_stop.clicked.connect(self.stop_comm)
        cl.addWidget(self.btn_start); cl.addWidget(self.btn_stop)
        ctrl_group.setLayout(cl)

        left_panel.addWidget(net_info); left_panel.addLayout(form)
        left_panel.addWidget(t_group); left_panel.addWidget(btn_apply)
        left_panel.addWidget(ctrl_group); left_panel.addStretch()

        # --- Right Panel (Grid) ---
        right_panel = QVBoxLayout()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Name", "Mode", "Address", "Status", "T-Params", "Time"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background: #000; color: #0F0; font-family: Consolas;")
        
        right_panel.addWidget(QLabel("### Node Status Grid"))
        right_panel.addWidget(self.table)
        right_panel.addWidget(QLabel("### Communication Log"))
        right_panel.addWidget(self.log_view)
        
        main_layout.addLayout(left_panel, 1); main_layout.addLayout(right_panel, 3)
        self.setCentralWidget(QWidget()); self.centralWidget().setLayout(main_layout)

    def on_node_selected(self, index):
        if index == 0: self.in_name.setText(""); self.in_name.setReadOnly(False)
        else:
            name = self.combo_nodes.currentText()
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_name.setReadOnly(True)
            self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            self.rb_act.setChecked(inst.mode == "Active")
            self.rb_pas.setChecked(inst.mode == "Passive")

    def apply_node(self):
        name = self.in_name.text()
        if not name: return
        mode = "Active" if self.rb_act.isChecked() else "Passive"
        params = {'T3': float(self.in_t3.text()), 'T5': float(self.in_t5.text()), 'T6': float(self.in_t6.text())}
        
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), mode, params)
            inst.status_changed.connect(self.update_grid_status)
            inst.log_signal.connect(lambda msg: self.log_view.append(f"[{name}] {msg}"))
            self.sessions[name] = inst
            self.combo_nodes.addItem(name)
            
            # 행 추가 및 모든 셀에 초기 Item 생성 (매우 중요)
            row = self.table.rowCount()
            self.table.insertRow(row)
            for col in range(6):
                self.table.setItem(row, col, QTableWidgetItem(""))
        else:
            self.sessions[name].mode = mode
            self.sessions[name].host = self.in_host.text()
            self.sessions[name].port = int(self.in_port.text())
            self.sessions[name].params = params
        
        self.update_grid_status(name, "READY")

    # 실시간 상태 업데이트 알고리즘
    def update_grid_status(self, name, status):
        for i in range(self.table.rowCount()):
            name_item = self.table.item(i, 0)
            if name_item and name_item.text() == name:
                inst = self.sessions[name]
                # 각 셀의 텍스트 갱신
                self.table.item(i, 0).setText(name)
                self.table.item(i, 1).setText(inst.mode)
                self.table.item(i, 2).setText(f"{inst.host}:{inst.port}")
                self.table.item(i, 3).setText(status)
                self.table.item(i, 4).setText(f"T3:{inst.params['T3']}, T6:{inst.params['T6']}")
                self.table.item(i, 5).setText(datetime.now().strftime("%H:%M:%S"))
                break

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

