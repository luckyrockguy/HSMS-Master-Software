import sys
import asyncio
import struct
import traceback
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTextEdit, QLabel, QLineEdit, QGroupBox, QFormLayout, 
                             QPushButton, QComboBox, QRadioButton, QGridLayout, QFrame, 
                             QSizePolicy)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt

# --- [1. HSMS Header & SECS-II Parser] ---
class HSMSHeader:
    def __init__(self, stream=0, function=0, s_type=0, system_bytes=0):
        self.stream = stream
        self.function = function
        self.s_type = s_type 
        self.system_bytes = system_bytes

    def pack(self):
        return struct.pack(">HBBBBI", 0, self.stream, self.function, 0, self.s_type, self.system_bytes)

    @classmethod
    def unpack(cls, data):
        h = struct.unpack(">HBBBBI", data)
        return cls(stream=h[1], function=h[2], s_type=h[4], system_bytes=h[5])

class SECSParser:
    """SEMI E5 SECS-II Data Item Parser with Hex + ASCII View"""
    FORMAT_CODES = {
        0: "L", 8: "B", 9: "BOOL", 16: "A", 20: "I8", 21: "I1", 22: "I2", 24: "I4",
        28: "F8", 32: "U8", 33: "U1", 34: "U2", 36: "U4", 44: "F4"
    }

    @staticmethod
    def to_readable_str(data):
        """바이너리 데이터를 가독성 있는 문자열로 변환 (제어문자는 . 처리)"""
        return "".join([chr(b) if 32 <= b <= 126 else "." for b in data])

    @classmethod
    def parse(cls, data):
        if not data: return "Empty", 0
        try:
            format_byte = data[0]
            fmt_code = (format_byte & 0xFC) >> 2
            len_bytes_cnt = format_byte & 0x03
            
            ptr = 1
            length = 0
            if len_bytes_cnt == 1:
                length = data[ptr]; ptr += 1
            elif len_bytes_cnt == 2:
                length = struct.unpack(">H", data[ptr:ptr+2])[0]; ptr += 2
            elif len_bytes_cnt == 3:
                length = struct.unpack(">I", b'\x00' + data[ptr:ptr+3])[0]; ptr += 3

            fmt_name = cls.FORMAT_CODES.get(fmt_code, f"Unk({fmt_code})")
            
            if fmt_name == "L":
                items = []
                sub_data = data[ptr:]
                offset = 0
                for _ in range(length):
                    item, consumed = cls.parse(sub_data[offset:])
                    items.append(item)
                    offset += consumed
                return f"L[{length}] {items}", ptr + offset
            
            val_data = data[ptr:ptr+length]
            
            # 주석 기호(*) 처리 (ASCII 타입인 경우)
            raw_hex = val_data.hex(' ').upper()
            raw_ascii = cls.to_readable_str(val_data)
            
            if fmt_name == "A":
                if '*' in raw_ascii:
                    raw_ascii = raw_ascii.split('*')[0].strip()
            
            return f"{fmt_name}: '{raw_hex} [{raw_ascii}]'", ptr + length
        except Exception:
            # 파싱 실패 시 전체 데이터를 Hex [ASCII] 덤프로 출력
            return f"DUMP: '{data.hex(' ').upper()} [{cls.to_readable_str(data)}]'", len(data)

# --- [2. HSMS Instance & Protocol Logic] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    log_signal = pyqtSignal(str)

    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0, 'T7': 10.0, 'T8': 5.0}
        self.transport, self.server = None, None
        self.running, self._sys_byte = False, 0
        self._pending_tx = {}
        self.current_state = "NOT CONNECTED"

    def handle_secs_message(self, header, payload):
        body_str, _ = SECSParser.parse(payload)
        msg = f"RECV | S{header.stream}F{header.function} | {body_str}"
        self.log_signal.emit(msg)

    def send_control_message(self, header):
        if self.transport:
            msg = header.pack()
            self.transport.write(struct.pack(">I", len(msg)) + msg)
            self.log_signal.emit(f"SEND | Control Type:{header.s_type}")

    async def send_data_message(self, s, f, payload_text=""):
        header = HSMSHeader(stream=s, function=f, s_type=0)
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        
        filtered_lines = []
        for line in payload_text.splitlines():
            clean_line = line.split('*')[0].strip()
            if clean_line: filtered_lines.append(clean_line)
        
        final_payload_text = "\n".join(filtered_lines)
        payload = final_payload_text.encode('utf-8')

        if self.transport:
            full = header.pack() + payload
            self.transport.write(struct.pack(">I", len(full)) + full)
            self.log_signal.emit(f"SEND | S{s}F{f} | Body: {final_payload_text}")
        else:
            self.log_signal.emit("ERROR | Not Connected")

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                loop = asyncio.get_running_loop()
                if self.mode == "Active":
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=self.params['T5'])
                    resp, _ = await self._send_with_wait(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and self.transport and not self.transport.is_closing(): await asyncio.sleep(0.5)
                else: 
                    self.server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with self.server: await self.server.serve_forever()
            except Exception:
                if self.running:
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    await asyncio.sleep(self.params['T5'])

    async def _send_with_wait(self, header, timeout=10.0):
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        f = asyncio.get_running_loop().create_future()
        self._pending_tx[self._sys_byte] = f
        msg = header.pack()
        if self.transport:
            self.transport.write(struct.pack(">I", len(msg)) + msg)
            return await asyncio.wait_for(f, timeout)
        raise Exception("Lost Transport")

    def stop(self):
        self.running = False
        if self.transport: self.transport.close()
        if self.server: self.server.close()

class HSMSProtocol(asyncio.Protocol):
    def __init__(self, instance):
        self.instance, self.buf = instance, bytearray()

    def data_received(self, data):
        self.buf.extend(data)
        while len(self.buf) >= 4:
            length = struct.unpack(">I", self.buf[:4])[0]
            if len(self.buf) < 4 + length: break
            raw = self.buf[4:4+length]
            self.buf = self.buf[4+length:]
            header = HSMSHeader.unpack(raw[:10])
            payload = raw[10:]
            if header.s_type == 0:
                self.instance.handle_secs_message(header, payload)
            elif header.s_type == 1: 
                self.instance.send_control_message(HSMSHeader(s_type=2, system_bytes=header.system_bytes))
                self.instance.status_changed.emit(self.instance.name, "SELECTED")
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, payload))

    def connection_made(self, transport): self.instance.transport = transport
    def connection_lost(self, exc): self.instance.transport = None; self.instance.status_changed.emit(self.instance.name, "NOT CONNECTED")

# --- [3. Main UI Application] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, loop):
        super().__init__()
        self.sessions = {}
        self.loop = loop
        self.current_node_name = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HSMS Master v2.5.3 - Hex/ASCII Viewer")
        self.resize(1100, 850)
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        
        left_panel = QVBoxLayout()
        cfg_box = QGroupBox("Node Config")
        f_lay = QFormLayout()
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        self.rb_act, self.rb_pas = QRadioButton("Active"), QRadioButton("Passive")
        self.rb_act.setChecked(True)
        mode_h = QHBoxLayout(); mode_h.addWidget(self.rb_act); mode_h.addWidget(self.rb_pas)
        f_lay.addRow("Select:", self.combo_nodes); f_lay.addRow("Name:", self.in_name)
        f_lay.addRow("Mode:", mode_h); f_lay.addRow("IP/Port:", self.in_host); f_lay.addRow("", self.in_port)
        cfg_box.setLayout(f_lay)

        t_box = QGroupBox("T-Parameters")
        t_lay = QGridLayout()
        self.t_inputs = {k: QLineEdit(str(v)) for k, v in {'T3':45, 'T5':10, 'T6':5, 'T7':10, 'T8':5}.items()}
        for i, (k, w) in enumerate(self.t_inputs.items()):
            t_lay.addWidget(QLabel(f"{k}:"), i//2, (i%2)*2)
            t_lay.addWidget(w, i//2, (i%2)*2+1)
        t_box.setLayout(t_lay)

        btn_apply = QPushButton("Apply Config"); btn_apply.clicked.connect(self.apply_node)
        btn_start = QPushButton("START"); btn_start.setStyleSheet("background:#2980b9; color:white; font-weight:bold;")
        btn_start.clicked.connect(self.start_comm)
        btn_stop = QPushButton("STOP"); btn_stop.setStyleSheet("background:#c0392b; color:white; font-weight:bold;")
        btn_stop.clicked.connect(self.stop_comm)

        self.st_nc, self.st_ns, self.st_sl = self._st_lbl("NOT CONNECTED"), self._st_lbl("NOT SELECTED"), self._st_lbl("SELECTED")
        left_panel.addWidget(cfg_box); left_panel.addWidget(t_box); left_panel.addWidget(btn_apply)
        left_panel.addWidget(btn_start); left_panel.addWidget(btn_stop); left_panel.addWidget(self.st_nc)
        left_panel.addWidget(self.st_ns); left_panel.addWidget(self.st_sl); left_panel.addStretch()

        right_panel = QVBoxLayout()
        send_group = QGroupBox("Message Transmission")
        send_group.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed) 
        s_lay = QVBoxLayout()
        h_lay = QHBoxLayout()
        self.in_s, self.in_f = QLineEdit("1"), QLineEdit("1")
        h_lay.addWidget(QLabel("S:")); h_lay.addWidget(self.in_s); h_lay.addWidget(QLabel("F:")); h_lay.addWidget(self.in_f)
        self.in_payload = QTextEdit(); self.in_payload.setFixedHeight(120)
        btn_send = QPushButton("SEND MESSAGE"); btn_send.setStyleSheet("background:#27ae60; color:white; font-weight:bold; height:35px;")
        btn_send.clicked.connect(self.send_message_action)
        s_lay.addLayout(h_lay); s_lay.addWidget(self.in_payload); s_lay.addWidget(btn_send)
        send_group.setLayout(s_lay)

        log_group = QGroupBox("Communication Logs")
        l_lay = QVBoxLayout()
        self.log_view = QTextEdit(); self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background:#121212; color:#00ff00; font-family:Consolas; font-size:10pt;")
        l_lay.addWidget(self.log_view)
        log_group.setLayout(l_lay)

        right_panel.addWidget(send_group); right_panel.addWidget(log_group, stretch=1) 
        main_layout.addLayout(left_panel, 1); main_layout.addLayout(right_panel, 3)
        self.setCentralWidget(main_widget)

    def _st_lbl(self, txt):
        l = QLabel(txt); l.setAlignment(Qt.AlignmentFlag.AlignCenter); l.setMinimumHeight(40)
        l.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain); l.setStyleSheet("background:#34495e; color:#7f8c8d;")
        return l

    def apply_node(self):
        try:
            name = self.in_name.text()
            if not name: return
            mode = "Active" if self.rb_act.isChecked() else "Passive"
            params = {k: float(w.text()) for k, w in self.t_inputs.items()}
            if name not in self.sessions:
                inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), mode, params)
                inst.status_changed.connect(self.update_state_ui)
                inst.log_signal.connect(lambda m: self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] [{name}] {m}"))
                self.sessions[name] = inst
                self.combo_nodes.addItem(name)
            else: 
                self.sessions[name].mode = mode
                self.sessions[name].params = params
            self.log_view.append(f"UI | Node '{name}' Configured.")
        except Exception as e: self.log_view.append(f"UI ERROR | {e}")

    def on_node_selected(self, idx):
        if idx <= 0: return
        try:
            name = self.combo_nodes.currentText()
            self.current_node_name = name
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            self.rb_act.setChecked(inst.mode == "Active")
            self.rb_pas.setChecked(inst.mode == "Passive")
            for k, v in inst.params.items(): self.t_inputs[k].setText(str(v))
            self.update_state_ui(name, inst.current_state)
        except Exception as e: self.log_view.append(f"UI ERROR | {e}")

    def update_state_ui(self, name, status):
        if name in self.sessions: self.sessions[name].current_state = status
        if name != self.current_node_name: return
        off, on = "background:#34495e; color:#7f8c8d;", "background:#2ecc71; color:#000; font-weight:bold;"
        self.st_nc.setStyleSheet(off); self.st_ns.setStyleSheet(off); self.st_sl.setStyleSheet(off)
        if status == "SELECTED": self.st_sl.setStyleSheet(on)
        elif status == "NOT SELECTED": self.st_ns.setStyleSheet(on)
        else: self.st_nc.setStyleSheet(on)

    def send_message_action(self):
        if self.current_node_name:
            try:
                s, f = int(self.in_s.text()), int(self.in_f.text())
                asyncio.run_coroutine_threadsafe(self.sessions[self.current_node_name].send_data_message(s, f, self.in_payload.toPlainText()), self.loop)
            except Exception as e: self.log_view.append(f"UI ERROR | {e}")

    def start_comm(self):
        if self.current_node_name: asyncio.run_coroutine_threadsafe(self.sessions[self.current_node_name].run_task(), self.loop)

    def stop_comm(self):
        if self.current_node_name: self.sessions[self.current_node_name].stop()

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

