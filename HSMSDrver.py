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

# --- [HSMS Protocol & Header] ---
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
        return f"S{self.stream}F{self.function}" if self.s_type == 0 else stype_map.get(self.s_type, "Unknown")

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
            self.instance.log_signal.emit(f"RECV | {header.get_desc()} | Sys:{header.system_bytes}")
            if header.system_bytes in self.instance._pending_tx:
                self.instance._pending_tx.pop(header.system_bytes).set_result((header, raw[10:]))
    def connection_lost(self, exc):
        self.instance.transport = None
        self.instance.status_changed.emit(self.instance.name, "NOT CONNECTED")

# --- [HSMS Instance] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    log_signal = pyqtSignal(str)

    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3':45, 'T5':10, 'T6':5, 'T7':10, 'T8':5}
        self.transport, self.running = None, False
        self._pending_tx, self._sys_byte = {}, 0

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                loop = asyncio.get_running_loop()
                if self.mode == "Active":
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    self.transport, _ = await asyncio.wait_for(
                        loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=self.params['T5'])
                    resp, _ = await self._send_raw(HSMSHeader(s_type=1), timeout=self.params['T6'])
                    if resp.s_type == 2:
                        self.status_changed.emit(self.name, "SELECTED")
                        while self.running and self.transport and not self.transport.is_closing(): await asyncio.sleep(1)
                else:
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with server: await server.serve_forever()
            except:
                if self.running:
                    self.status_changed.emit(self.name, "NOT CONNECTED")
                    await asyncio.sleep(5)
        self.status_changed.emit(self.name, "STOPPED")

    async def _send_raw(self, header, payload=b'', timeout=10.0):
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        f = asyncio.get_running_loop().create_future()
        self._pending_tx[self._sys_byte] = f
        if self.transport:
            self.transport.write(struct.pack(">I", 10+len(payload)) + header.pack() + payload)
            return await asyncio.wait_for(f, timeout)
        raise ConnectionError()

# --- [Main App] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, loop):
        super().__init__()
        self.sessions = {}
        self.row_map = {}  # 핵심: 노드 이름을 키로 행 인덱스 저장
        self.loop = loop
        self.current_node = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HSMS Master v2.1.0 (Fixed Real-time Update)")
        self.resize(1300, 850)
        main_l = QHBoxLayout()
        left_l = QVBoxLayout()

        # Config Panel
        cfg_box = QGroupBox("Node Config")
        f_lay = QFormLayout()
        self.cb_node = QComboBox()
        self.cb_node.addItem("--- New Node ---")
        self.cb_node.currentIndexChanged.connect(self.on_node_sel)
        self.in_name, self.in_host, self.in_port = QLineEdit(), QLineEdit("127.0.0.1"), QLineEdit("5000")
        f_lay.addRow("Select:", self.cb_node)
        f_lay.addRow("Name:", self.in_name)
        f_lay.addRow("IP:", self.in_host)
        f_lay.addRow("Port:", self.in_port)
        cfg_box.setLayout(f_lay)

        # State Model (E37)
        self.state_box = QGroupBox("SEMI E37 Status Model")
        s_lay = QVBoxLayout()
        self.st_nc = self._st_lbl("NOT CONNECTED")
        self.st_ns = self._st_lbl("CONNECTED / NOT SELECTED")
        self.st_sl = self._st_lbl("CONNECTED / SELECTED")
        s_lay.addWidget(self.st_nc); s_lay.addWidget(QLabel("↓↑", alignment=Qt.AlignmentFlag.AlignCenter))
        s_lay.addWidget(self.st_ns); s_lay.addWidget(QLabel("↓↑", alignment=Qt.AlignmentFlag.AlignCenter))
        s_lay.addWidget(self.st_sl)
        self.state_box.setLayout(s_lay)

        btn_apply = QPushButton("Apply Configuration")
        btn_apply.clicked.connect(self.apply_node)
        btn_start = QPushButton("START"); btn_start.clicked.connect(self.start_comm)
        btn_stop = QPushButton("STOP"); btn_stop.clicked.connect(self.stop_comm)

        left_l.addWidget(cfg_box); left_l.addWidget(btn_apply)
        left_l.addWidget(btn_start); left_l.addWidget(btn_stop)
        left_l.addWidget(self.state_box); left_l.addStretch()

        # Right Panel
        right_l = QVBoxLayout()
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Name", "Port", "Status", "T-Params", "Update"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("background:#000; color:#0f0; font-family:Consolas;")
        
        right_l.addWidget(QLabel("### Monitoring Grid"))
        right_l.addWidget(self.table)
        right_l.addWidget(self.log_view)

        main_l.addLayout(left_l, 1); main_l.addLayout(right_l, 3)
        self.setCentralWidget(QWidget()); self.centralWidget().setLayout(main_l)

    def _st_lbl(self, txt):
        l = QLabel(txt); l.setAlignment(Qt.AlignmentFlag.AlignCenter); l.setMinimumHeight(40)
        l.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        l.setStyleSheet("background:#2c3e50; color:#7f8c8d;")
        return l

    def on_node_sel(self, idx):
        if idx > 0:
            name = self.cb_node.currentText()
            self.current_node = name
            inst = self.sessions[name]
            self.in_name.setText(name); self.in_host.setText(inst.host); self.in_port.setText(str(inst.port))
            # 현재 테이블에 있는 상태로 UI 즉시 동기화
            row = self.row_map[name]
            self.refresh_state_ui(self.table.item(row, 2).text())

    def apply_node(self):
        name = self.in_name.text()
        if not name: return
        if name not in self.sessions:
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()))
            inst.status_changed.connect(self.sync_grid)
            inst.log_signal.connect(lambda m: self.log_view.append(f"[{name}] {m}"))
            self.sessions[name] = inst
            self.cb_node.addItem(name)
            
            # 행 추가 및 행 맵핑 저장
            row = self.table.rowCount()
            self.row_map[name] = row
            self.table.insertRow(row)
            for i in range(5): self.table.setItem(row, i, QTableWidgetItem(""))
            self.table.item(row, 0).setText(name)
        
        self.sync_grid(name, "READY")

    def sync_grid(self, name, status):
        if name in self.row_map:
            row = self.row_map[name]
            inst = self.sessions[name]
            # 실시간 데이터 갱신 (반드시 item이 존재함을 row_map이 보장)
            self.table.item(row, 1).setText(str(inst.port))
            self.table.item(row, 2).setText(status)
            self.table.item(row, 3).setText(f"T5:{inst.params['T5']} T6:{inst.params['T6']}")
            self.table.item(row, 4).setText(datetime.now().strftime("%H:%M:%S"))
            
            if name == self.current_node:
                self.refresh_state_ui(status)

    def refresh_state_ui(self, status):
        base, act = "background:#2c3e50; color:#7f8c8d;", "background:#00ff00; color:#000; font-weight:bold;"
        self.st_nc.setStyleSheet(base); self.st_ns.setStyleSheet(base); self.st_sl.setStyleSheet(base)
        if status == "SELECTED": self.st_sl.setStyleSheet(act)
        elif status == "NOT SELECTED": self.st_ns.setStyleSheet(act)
        else: self.st_nc.setStyleSheet(act)

    def start_comm(self):
        if self.current_node:
            asyncio.run_coroutine_threadsafe(self.sessions[self.current_node].run_task(), self.loop)

    def stop_comm(self):
        if self.current_node: self.sessions[self.current_node].running = False

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
