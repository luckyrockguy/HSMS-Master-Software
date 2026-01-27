[import sys
import asyncio
import struct
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTextEdit, QLabel, QLineEdit, QGroupBox, QFormLayout, 
                             QPushButton, QComboBox, QRadioButton, QGridLayout, QFrame)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt

# --- [1. HSMS Header & Logic] ---
class HSMSHeader:
    def __init__(self, stream=0, function=0, s_type=0, system_bytes=0):
        self.stream = stream
        self.function = function
        self.s_type = s_type # 0:Data, 1:Select.req, 2:Select.rsp, 5:Linktest.req, 6:Linktest.rsp
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

    def connection_made(self, transport):
        self.instance.transport = transport
        self.instance.status_changed.emit(self.instance.name, "NOT SELECTED")
        self.instance.log_signal.emit(f"SYSTEM | Connection Established")

    def data_received(self, data):
        self.buf.extend(data)
        while len(self.buf) >= 4:
            length = struct.unpack(">I", self.buf[:4])[0]
            if len(self.buf) < 4 + length: break
            raw = self.buf[4:4+length]
            self.buf = self.buf[4+length:]
            header = HSMSHeader.unpack(raw[:10])
            payload = raw[10:]
            
            # --- Passive Mode: Handling Select.req ---
            if header.s_type == 1: # Select.req
                self.instance.log_signal.emit(f"RECV | Select.req (Passive Mode)")
                rsp = HSMSHeader(s_type=2, system_bytes=header.system_bytes)
                self.instance.send_control_message(rsp)
                self.instance.status_changed.emit(self.instance.name, "SELECTED")
            
            # --- Handling Data or Responses ---
            desc = f"S{header.stream}F{header.function}" if header.s_type == 0 else f"Type:{header.s_type}"
            self.instance.log_signal.emit(f"RECV | {desc} | Sys:{header.system_bytes}")
            
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, payload))

    def connection_lost(self, exc):
        self.instance.transport = None
        self.instance.status_changed.emit(self.instance.name, "NOT CONNECTED")
        self.instance.log_signal.emit(f"SYSTEM | Connection Lost")

# --- [2. HSMS Instance] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    log_signal = pyqtSignal(str)

    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0}
        self.transport = None
        self.running = False
        self._pending_tx = {}
        self._sys_byte = 0
        self.current_state = "NOT CONNECTED"

    def send_control_message(self, header):
        if self.transport:
            msg = header.pack()
            self.transport.write(struct.pack(">I", len(msg)) + msg)
            self.log_signal.emit(f"SEND | Type:{header.s_type} (Control)")

    async def send_data_message(self, s, f, payload=b''):
        header = HSMSHeader(stream=s, function=f, s_type=0)
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        
        if self.transport:
            full_msg = header.pack() + payload
            self.transport.write(struct.pack(">I", len(full_msg)) + full_msg)
            self.log_signal.emit(f"SEND | S{s}F{f} | Sys:{self._sys_byte}")
        else:
            self.log_signal.emit("ERROR | Not Connected")

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                loop = asyncio.get_running_loop()
                if self.mode == "Active":
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=self.params['T5'])
                    
                    # Active: Send Select.req
                    resp, _ = await self._send_with_wait(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and self.transport and not self.transport.is_closing():
                            await asyncio.sleep(0.5)
                else: # Passive Mode
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with server: 
                        self.log_signal.emit(f"SYSTEM | Passive Listening on {self.port}...")
                        await server.serve_forever()
            except Exception as e:
                if self.running:
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    await asyncio.sleep(5)
        self.status_changed.emit(self.name, "STOPPED")

    async def _send_with_wait(self, header, timeout=10.0):
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        future = asyncio.get_running_loop().create_future()
        self._pending_tx[self._sys_byte] = future
        msg = header.pack()
        self.transport.write(struct.pack(">I", len(msg)) + msg)
        return await asyncio.wait_for(future, timeout)

# --- [3. Main UI] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, loop):
        super().__init__()
        self.sessions = {}
        self.loop = loop
        self.current_node_name = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HSMS Messenger v2.2.0")
        self.resize(1100, 800)
        
        main_layout = QHBoxLayout()
        
        # --- Left Panel: Settings ---
        left_panel = QVBoxLayout()
        
        cfg_box = QGroupBox("Node Setting")
        f_lay = QFormLayout()
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        self.rb_act, self.rb_pas = QRadioButton("Active"), QRadioButton("Passive")
        self.rb_act.setChecked(True)
        mode_h = QHBoxLayout(); mode_h.addWidget(self.rb_act); mode_h.addWidget(self.rb_pas)
        
        f_lay.addRow("Select:", self.combo_nodes)
        f_lay.addRow("Name:", self.in_name)
        f_lay.addRow("Mode:", mode_h)
        f_lay.addRow("IP/Port:", self.in_host); f_lay.addRow("", self.in_port)
        cfg_box.setLayout(f_lay)

        # Status Model UI (Left Bottom)
        self.state_box = QGroupBox("SEMI E37 Connection State")
        st_lay = QVBoxLayout()
        self.st_nc = self._st_lbl("NOT CONNECTED")
        self.st_ns = self._st_lbl("CONNECTED / NOT SELECTED")
        self.st_sl = self._st_lbl("CONNECTED / SELECTED")
        st_lay.addWidget(self.st_nc); st_lay.addWidget(QLabel("↓↑", alignment=Qt.AlignmentFlag.AlignCenter))
        st_lay.addWidget(self.st_ns); st_lay.addWidget(QLabel("↓↑", alignment=Qt.AlignmentFlag.AlignCenter))
        st_lay.addWidget(self.st_sl)
        self.state_box.setLayout(st_lay)

        btn_apply = QPushButton("Apply & Save Node")
        btn_apply.clicked.connect(self.apply_node)
        btn_start = QPushButton("START COMMUNICATION"); btn_start.setStyleSheet("background:#2980b9; color:white; font-weight:bold;")
        btn_start.clicked.connect(self.start_comm)
        
        left_panel.addWidget(cfg_box); left_panel.addWidget(btn_apply)
        left_panel.addWidget(btn_start); left_panel.addWidget(self.state_box)
        left_panel.addStretch()

        # --- Right Panel: Messenger & Logs ---
        right_panel = QVBoxLayout()
        
        # Send Message Area
        send_group = QGroupBox("Message Transmission")
        s_lay = QGridLayout()
        self.in_stream = QLineEdit("1"); self.in_stream.setPlaceholderText("S")
        self.in_func = QLineEdit("1"); self.in_func.setPlaceholderText("F")
        self.in_payload = QLineEdit(); self.in_payload.setPlaceholderText("Payload (Hex string or Text)")
        btn_send = QPushButton("SEND MESSAGE"); btn_send.setStyleSheet("background:#27ae60; color:white; height:40px; font-weight:bold;")
        btn_send.clicked.connect(self.send_message_action)
        
        s_lay.addWidget(QLabel("Stream:"), 0, 0); s_lay.addWidget(self.in_stream, 0, 1)
        s_lay.addWidget(QLabel("Function:"), 0, 2); s_lay.addWidget(self.in_func, 0, 3)
        s_lay.addWidget(QLabel("Payload:"), 1, 0); s_lay.addWidget(self.in_payload, 1, 1, 1, 3)
        s_lay.addWidget(btn_send, 2, 0, 1, 4)
        send_group.setLayout(s_lay)

        # Log View
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background:#000; color:#0f0; font-family:Consolas; font-size:10pt;")
        
        right_panel.addWidget(send_group)
        right_panel.addWidget(QLabel("### Communication Logs"))
        right_panel.addWidget(self.log_view)

        main_layout.addLayout(left_panel, 1)
        main_layout.addLayout(right_panel, 2)
        self.setCentralWidget(QWidget()); self.centralWidget().setLayout(main_layout)

    def _st_lbl(self, txt):
        l = QLabel(txt); l.setAlignment(Qt.AlignmentFlag.AlignCenter); l.setMinimumHeight(45)
        l.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        l.setStyleSheet("background:#34495e; color:#7f8c8d; border:1px solid #2c3e50;")
        return l

    def on_node_selected(self, idx):
        if idx > 0:
            name = self.combo_nodes.currentText()
            self.current_node_name = name
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            self.rb_act.setChecked(inst.mode == "Active"); self.rb_pas.setChecked(inst.mode == "Passive")
            self.update_state_ui(name, inst.current_state)

    def apply_node(self):
        name = self.in_name.text()
        if not name: return
        mode = "Active" if self.rb_act.isChecked() else "Passive"
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), mode)
            inst.status_changed.connect(self.update_state_ui)
            inst.log_signal.connect(lambda m: self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] {m}"))
            self.sessions[name] = inst
            self.combo_nodes.addItem(name)
        self.log_view.append(f"SYSTEM | Node '{name}' Configured.")

    def update_state_ui(self, name, status):
        if name in self.sessions: self.sessions[name].current_state = status
        if name != self.current_node_name: return
        
        off, on = "background:#34495e; color:#7f8c8d;", "background:#2ecc71; color:#000; font-weight:bold; border:2px solid white;"
        self.st_nc.setStyleSheet(off); self.st_ns.setStyleSheet(off); self.st_sl.setStyleSheet(off)
        if status == "SELECTED": self.st_sl.setStyleSheet(on)
        elif status == "NOT SELECTED": self.st_ns.setStyleSheet(on)
        else: self.st_nc.setStyleSheet(on)

    def send_message_action(self):
        if not self.current_node_name: return
        s = int(self.in_stream.text()); f = int(self.in_func.text())
        asyncio.run_coroutine_threadsafe(self.sessions[self.current_node_name].send_data_message(s, f), self.loop)

    def start_comm(self):
        if self.current_node_name:
            asyncio.run_coroutine_threadsafe(self.sessions[self.current_node_name].run_task(), self.loop)

class AsyncLoopThread(QThread):
    def __init__(self):
        super().__init__()
        self.loop = None
    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop); self.loop.run_forever()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    t = AsyncLoopThread(); t.start()
    while not t.loop: pass
    win = HSMSMonitorApp(t.loop); win.show()
    sys.exit(app.exec())
