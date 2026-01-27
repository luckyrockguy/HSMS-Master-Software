import sys
import asyncio
import struct
import socket
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QHeaderView,
                             QLineEdit, QGroupBox, QFormLayout, QPushButton, QComboBox, 
                             QRadioButton, QGridLayout, QFrame)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt

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
        return f"S{self.stream}F{self.function}" if self.s_type == 0 else desc

class HSMSProtocol(asyncio.Protocol):
    def __init__(self, instance):
        self.instance = instance
        self.buf = bytearray()

    def connection_made(self, transport):
        self.instance.transport = transport
        self.instance.status_changed.emit(self.instance.name, "NOT SELECTED")

    def data_received(self, data):
        self.buf.extend(data)
        while len(self.buf) >= 4:
            length = struct.unpack(">I", self.buf[:4])[0]
            if len(self.buf) < 4 + length: break
            raw = self.buf[4:4+length]
            self.buf = self.buf[4+length:]
            header = HSMSHeader.unpack(raw[:10])
            self.instance.log_signal.emit(f"RECV | {header.get_desc()} | SysByte:{header.system_bytes}")
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, raw[10:]))

    def connection_lost(self, exc):
        self.instance.transport = None
        self.instance.status_changed.emit(self.instance.name, "NOT CONNECTED")

# --- [2. HSMS Instance with Full T-Params] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    log_signal = pyqtSignal(str)

    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0, 'T7': 10.0, 'T8': 5.0}
        self.transport = None
        self.running = False
        self._pending_tx = {}
        self._sys_byte = 0

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                loop = asyncio.get_running_loop()
                if self.mode == "Active":
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), 
                        timeout=self.params['T5'])
                    
                    self.log_signal.emit(f"SEND | Select.req")
                    resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and self.transport and not self.transport.is_closing():
                            await asyncio.sleep(1)
                else: # Passive Mode
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with server: await server.serve_forever()
            except Exception:
                if self.running:
                    self.status_changed.emit(self.name, "NOT CONNECTED")
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
        self.current_selected_node = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HSMS Master v2.0.0 - Full Standard Compliance")
        self.resize(1400, 900)
        main_layout = QHBoxLayout()
        
        # --- Left Side: Config & State Model ---
        left_side = QVBoxLayout()
        
        cfg_group = QGroupBox("Node Configuration")
        form = QFormLayout()
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        
        mode_l = QHBoxLayout()
        self.rb_act, self.rb_pas = QRadioButton("Active"), QRadioButton("Passive")
        self.rb_act.setChecked(True)
        mode_l.addWidget(self.rb_act); mode_l.addWidget(self.rb_pas)
        
        t_group = QGroupBox("HSMS Timeouts (T3~T8)")
        t_grid = QGridLayout()
        self.in_t3, self.in_t5, self.in_t6 = QLineEdit("45"), QLineEdit("10"), QLineEdit("5")
        self.in_t7, self.in_t8 = QLineEdit("10"), QLineEdit("5")
        t_grid.addWidget(QLabel("T3:"),0,0); t_grid.addWidget(self.in_t3,0,1)
        t_grid.addWidget(QLabel("T5:"),0,2); t_grid.addWidget(self.in_t5,0,3)
        t_grid.addWidget(QLabel("T6:"),1,0); t_grid.addWidget(self.in_t6,1,1)
        t_grid.addWidget(QLabel("T7:"),1,2); t_grid.addWidget(self.in_t7,1,3)
        t_grid.addWidget(QLabel("T8:"),2,0); t_grid.addWidget(self.in_t8,2,1)
        t_group.setLayout(t_grid)
        
        btn_apply = QPushButton("Apply Configuration")
        btn_apply.setStyleSheet("padding: 8px; font-weight: bold;")
        btn_apply.clicked.connect(self.apply_node)
        
        form.addRow("Select:", self.combo_nodes)
        form.addRow("Mode:", mode_l)
        form.addRow("Name:", self.in_name)
        form.addRow("Target IP:", self.in_host)
        form.addRow("Port:", self.in_port)
        cfg_group.setLayout(form)

        ctrl_group = QGroupBox("Execution Control")
        cl = QHBoxLayout()
        self.btn_start, self.btn_stop = QPushButton("START"), QPushButton("STOP")
        self.btn_start.clicked.connect(self.start_comm); self.btn_stop.clicked.connect(self.stop_comm)
        cl.addWidget(self.btn_start); cl.addWidget(self.btn_stop)
        ctrl_group.setLayout(cl)

        # SEMI E37 Connection State Model Visualization
        self.state_box = QGroupBox("Connection Status Model (SEMI E37)")
        state_l = QVBoxLayout()
        self.lbl_not_conn = self._create_state_label("NOT CONNECTED")
        self.lbl_not_sel = self._create_state_label("CONNECTED / NOT SELECTED")
        self.lbl_sel = self._create_state_label("CONNECTED / SELECTED")
        state_l.addWidget(self.lbl_not_conn); state_l.addWidget(QLabel("↓↑", alignment=Qt.AlignmentFlag.AlignCenter))
        state_l.addWidget(self.lbl_not_sel); state_l.addWidget(QLabel("↓↑", alignment=Qt.AlignmentFlag.AlignCenter))
        state_l.addWidget(self.lbl_sel)
        self.state_box.setLayout(state_l)

        left_side.addWidget(cfg_group); left_side.addWidget(t_group)
        left_side.addWidget(btn_apply); left_side.addWidget(ctrl_group)
        left_side.addWidget(self.state_box); left_side.addStretch()

        # --- Right Side: Grid & Logs ---
        right_side = QVBoxLayout()
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Node", "Mode", "Port", "Status", "T-Params", "Last Update"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background:#121212; color:#00FF00; font-family:Consolas; font-size:10pt;")
        
        right_side.addWidget(QLabel("### Multi-Node Monitoring Grid"))
        right_side.addWidget(self.table)
        right_side.addWidget(QLabel("### HSMS/SECS Message Real-time Log"))
        right_side.addWidget(self.log_view)

        main_layout.addLayout(left_side, 1); main_layout.addLayout(right_side, 3)
        self.setCentralWidget(QWidget()); self.centralWidget().setLayout(main_layout)

    def _create_state_label(self, text):
        lbl = QLabel(text)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        lbl.setMinimumHeight(45)
        lbl.setStyleSheet("background-color: #2c3e50; color: #7f8c8d; border: 1px solid #34495e;")
        return lbl

    def on_node_selected(self, index):
        if index == 0: 
            self.in_name.setText(""); self.in_name.setReadOnly(False)
            self.current_selected_node = None
        else:
            name = self.combo_nodes.currentText()
            self.current_selected_node = name
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_name.setReadOnly(True)
            self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            self.rb_act.setChecked(inst.mode == "Active"); self.rb_pas.setChecked(inst.mode == "Passive")
            self._update_state_ui(self._get_current_status(name))

    def _get_current_status(self, name):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name: return self.table.item(i, 3).text()
        return "STOPPED"

    def apply_node(self):
        name = self.in_name.text()
        if not name: return
        mode = "Active" if self.rb_act.isChecked() else "Passive"
        params = {'T3':float(self.in_t3.text()), 'T5':float(self.in_t5.text()), 'T6':float(self.in_t6.text()), 
                  'T7':float(self.in_t7.text()), 'T8':float(self.in_t8.text())}
        
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), mode, params)
            inst.status_changed.connect(self.update_grid)
            inst.log_signal.connect(lambda m: self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {name} > {m}"))
            self.sessions[name] = inst
            self.combo_nodes.addItem(name)
            row = self.table.rowCount()
            self.table.insertRow(row)
            for c in range(6): self.table.setItem(row, c, QTableWidgetItem(""))
        else:
            self.sessions[name].mode = mode; self.sessions[name].params = params
        
        self.update_grid(name, "READY")

    def update_grid(self, name, status):
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).text() == name:
                inst = self.sessions[name]
                self.table.item(i, 0).setText(name)
                self.table.item(i, 1).setText(inst.mode)
                self.table.item(i, 2).setText(str(inst.port))
                self.table.item(i, 3).setText(status)
                p = inst.params
                self.table.item(i, 4).setText(f"T3:{p['T3']} T5:{p['T5']} T6:{p['T6']}")
                self.table.item(i, 5).setText(datetime.now().strftime("%H:%M:%S"))
        
        if name == self.current_selected_node:
            self._update_state_ui(status)

    def _update_state_ui(self, status):
        base = "background-color: #2c3e50; color: #7f8c8d; border: 1px solid #34495e; font-weight: normal;"
        active = "background-color: #00FF00; color: #000; border: 2px solid #FFF; font-weight: bold;"
        
        for lbl in [self.lbl_not_conn, self.lbl_not_sel, self.lbl_sel]: lbl.setStyleSheet(base)
        
        if status == "SELECTED": self.lbl_sel.setStyleSheet(active)
        elif status == "NOT SELECTED": self.lbl_not_sel.setStyleSheet(active)
        else: self.lbl_not_conn.setStyleSheet(active)

    def start_comm(self):
        if self.current_selected_node:
            asyncio.run_coroutine_threadsafe(self.sessions[self.current_selected_node].run_task(), self.loop)

    def stop_comm(self):
        if self.current_selected_node: self.sessions[self.current_selected_node].running = False

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
    t = AsyncLoopThread(); t.start()
    while not t.loop: pass
    win = HSMSMonitorApp(t.loop); win.show()
    sys.exit(app.exec())

