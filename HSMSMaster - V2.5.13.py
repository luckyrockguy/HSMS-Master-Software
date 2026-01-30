import sys
import asyncio
import struct
import re
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTextEdit, QLabel, QLineEdit, QGroupBox, QFormLayout, 
                             QPushButton, QComboBox, QRadioButton, QGridLayout, QFrame, 
                             QSizePolicy, QSplitter)
from PyQt6.QtCore import QThread, pyqtSignal, QObject, Qt

# --- [1. HSMS Header & SECS-II Parser] ---
class HSMSHeader:
    def __init__(self, stream=0, function=0, s_type=0, system_bytes=0, wait_bit=False):
        # Wait Bit가 True이면 Stream 번호에 0x80(MSB 1)을 설정
        self.stream = (stream | 0x80) if wait_bit else stream
        self.function = function
        self.s_type = s_type 
        self.system_bytes = system_bytes

    def __str__(self):
        stream_num = self.stream & 0x7F
        wait = "W" if (self.stream & 0x80) else ""
        return f"S{stream_num}F{self.function}{(' (Wait)' if wait else '')} (SysByte: {self.system_bytes:08X})"

    def pack(self):
        return struct.pack(">HBBBBI", 0, self.stream, self.function, 0, self.s_type, self.system_bytes)

    @classmethod
    def unpack(cls, data):
        h = struct.unpack(">HBBBBI", data)
        return cls(stream=h[1], function=h[2], s_type=h[4], system_bytes=h[5])

class SECSParser:
    FORMAT_CODES = {0: "L", 8: "B", 16: "A", 20: "I8", 21: "I1", 22: "I2", 24: "I4", 32: "U8", 33: "U1", 34: "U2", 36: "U4"}

    @staticmethod
    def wrap_hex(data, width=16):
        if not data: return ""
        hex_str = data.hex(' ').upper()
        parts = hex_str.split(' ')
        return "\n".join([" ".join(parts[i:i+width]) for i in range(0, len(parts), width)])

    @classmethod
    def parse_recursive(cls, data, indent=0):
        if not data: return "", 0
        try:
            format_byte = data[0]
            fmt_code = (format_byte & 0xFC) >> 2
            len_bytes_cnt = format_byte & 0x03
            ptr = 1
            length = 0
            if len_bytes_cnt == 1: length = data[ptr]; ptr += 1
            elif len_bytes_cnt == 2: length = struct.unpack(">H", data[ptr:ptr+2])[0]; ptr += 2
            elif len_bytes_cnt == 3: length = struct.unpack(">I", b'\x00' + data[ptr:ptr+3])[0]; ptr += 3

            fmt_name = cls.FORMAT_CODES.get(fmt_code, f"Unk({fmt_code})")
            spacing = "  " * indent
            if fmt_name == "L":
                out = f"{spacing}<L[{length}]\n"
                sub_data, offset = data[ptr:], 0
                for _ in range(length):
                    a, consumed = cls.parse_recursive(sub_data[offset:], indent + 1)
                    out += a; offset += consumed
                return out + f"{spacing}>\n", ptr + offset
            
            val_data = data[ptr:ptr+length]
            val_ascii = "".join([chr(b) if 32 <= b <= 126 else "." for b in val_data])
            return f"{spacing}<{fmt_name} '{val_ascii}'>\n", ptr + length
        except: return f"{spacing}[Parse Error]\n", len(data)

# --- [2. HSMS Instance & Logic] ---
class HSMSInstance(QObject):
    status_changed = pyqtSignal(str, str)
    log_signal = pyqtSignal(str)

    def __init__(self, name, host, port, mode="Active", params=None):
        super().__init__()
        self.name, self.host, self.port, self.mode = name, host, port, mode
        self.params = params or {'T3': 45.0, 'T5': 10.0, 'T6': 5.0}
        self.transport, self.server, self.running, self._sys_byte = None, None, False, 0
        self.current_state = "NOT CONNECTED"

    def log_full_message(self, direction, header, body_bytes):
        # 타입 매핑
        TYPE_MAP = {
            0x00: "<L",
            0x08: "<B",
            0x09: "<BOOLEAN",
            0x10: "<A",
            0x14: "<I8",
            0x15: "<I1",
            0x16: "<I2",
            0x17: "<I4",
            0x20: "<F8",
            0x24: "<F4",
            0x30: "<U8",
            0x31: "<U1",
            0x32: "<U2",
            0x34: "<U4"
        }

        self.log_signal.emit(f"{direction} [{header}] SysByte: {header.system_bytes:08X}")
        hex_view = ' '.join(f"{b:02X}" for b in body_bytes)
        self.log_signal.emit("--- HEX RAW VIEW ---")
        self.log_signal.emit(hex_view)

        def decode_items_old(data, offset=0):
            items = []
            while offset < len(data):
                if offset + 2 > len(data):
                    break
                header_byte = data[offset]
                offset += 1
                length_byte_count = header_byte & 0x03
                fmt_code = header_byte >> 2
                length = data[offset]
                offset += 1
                if offset + length > len(data):
                    break
                val_bytes = data[offset:offset+length]
                offset += length

                type_str = TYPE_MAP.get(fmt_code, f"<UNK:{fmt_code:02X}>")

                if type_str == "<L":
                    items.append(f"{type_str}[?]")
                else:
                    if type_str == "<A":
                        val_str = val_bytes.decode('ascii', errors='replace')
                    elif type_str == "<B":
                        val_str = val_bytes.hex()
                    elif type_str == "<BOOLEAN":
                        val_str = "TRUE" if val_bytes != b'\x00' else "FALSE"
                    elif type_str in ["<I1", "<I2", "<I4", "<I8"]:
                        fmt_map = {"<I1":"b", "<I2":"h", "<I4":"i", "<I8":"q"}
                        fmt = fmt_map[type_str]
                        val_str = str(struct.unpack(f">{fmt}", val_bytes)[0])
                    elif type_str in ["<U1", "<U2", "<U4", "<U8"]:
                        fmt_map = {"<U1":"B", "<U2":"H", "<U4":"I", "<U8":"Q"}
                        fmt = fmt_map[type_str]
                        val_str = str(struct.unpack(f">{fmt}", val_bytes)[0])
                    elif type_str == "<F4":
                        val_str = f"{struct.unpack('>f', val_bytes)[0]:g}"
                    elif type_str == "<F8":
                        val_str = f"{struct.unpack('>d', val_bytes)[0]:g}"
                    else:
                        val_str = val_bytes.hex()

                    items.append(f"{type_str} '{val_str}'")
            return items

        def decode_items(data, offset=0):
            items = []
            while offset < len(data):
                if offset + 2 > len(data):
                   break
                header_byte = data[offset]
                offset += 1
                length_byte_count = header_byte & 0x03
                fmt_code = header_byte >> 2
                length = data[offset]
                offset += 1

                type_str = TYPE_MAP.get(fmt_code, f"<UNK:{fmt_code:02X}>")

                if fmt_code == 0x00:  # <L> 타입 (List)
                    # length: 리스트 아이템 개수
                    children = []
                    for _ in range(length):
                        child_items, offset = decode_items(data, offset)
                        children.extend(child_items)
						
                    items.append(f"<L[{length}]>")
                    items.extend(children)
                else:
                    if offset + length > len(data):
                        break
                    val_bytes = data[offset:offset+length]
                    offset += length

                    if type_str == "<A":
                        val_str = val_bytes.decode('ascii', errors='replace')
                    elif type_str == "<B":
                        val_str = val_bytes.hex()
                    elif type_str == "<BOOLEAN":
                        val_str = "TRUE" if val_bytes != b'\x00' else "FALSE"
                    elif type_str in ["<I1", "<I2", "<I4", "<I8"]:
                        fmt_map = {"<I1":"b", "<I2":"h", "<I4":"i", "<I8":"q"}
                        fmt = fmt_map[type_str]
                        val_str = str(struct.unpack(f">{fmt}", val_bytes)[0])
                    elif type_str in ["<U1", "<U2", "<U4", "<U8"]:
                        fmt_map = {"<U1":"B", "<U2":"H", "<U4":"I", "<U8":"Q"}
                        fmt = fmt_map[type_str]
                        val_str = str(struct.unpack(f">{fmt}", val_bytes)[0])
                    elif type_str == "<F4":
                        val_str = f"{struct.unpack('>f', val_bytes)[0]:g}"
                    elif type_str == "<F8":
                        val_str = f"{struct.unpack('>d', val_bytes)[0]:g}"
                    else:
                        val_str = val_bytes.hex()

                    items.append(f"{type_str} '{val_str}'")

            return items, offset

        decoded_items, _ = decode_items(body_bytes)  # 튜플 언패킹

        self.log_signal.emit("--- STRUCTURE VIEW ---")
        for item in decoded_items:
           self.log_signal.emit(item)
        self.log_signal.emit("--------------------------------------")

    async def send_data_message(self, payload_text):
        self.log_signal.emit("DEBUG | [Parsing Start] Analyzing input message...")
        
        # 연결 상태 확인
        if not self.transport or self.transport.is_closing():
            self.log_signal.emit("DEBUG | [ERROR] 연결된 노드가 없습니다. 전송을 중단합니다.")
            return
            
        s, f, w = 0, 0, False
        
        lines = payload_text.splitlines()
        if not lines:
            self.log_signal.emit("DEBUG | [ERROR] 입력된 메시지가 없습니다.")
            return        
        
        # 헤더 및 Wait Bit 파싱 (첫 줄 대상)
        first_line = lines[0]
        # 주석 제거 (첫 줄에서도 * 뒤는 무시)
        first_line_clean = first_line.split('*')[0]
        
        # 첫 번째 따옴표 안의 문자열 추출 (예: 'S14F1')
        match = re.search(r"'([Ss]\d+[Ff]\d+)'", first_line_clean)
        if match:
            header_str = match.group(1).upper()
            self.log_signal.emit(f"DEBUG | [Step 1] Found header string in quotes: '{header_str}'")
            
            # 2. S와 F 번호 추출
            s_match = re.search(r"S(\d+)", header_str)
            f_match = re.search(r"F(\d+)", header_str)   
            
            if s_match and f_match:
                s = int(s_match.group(1))
                f = int(f_match.group(1))
                self.log_signal.emit(f"DEBUG | [Step 2] Parsed Stream={s}, Function={f}")
                
                # Stream/Function 문자열('SxFy') 뒤에서만 W 찾기
                # match.end() 이후의 문자열에서 'W' 검색
                post_header_text = first_line_clean[match.end():].upper()
                if 'W' in post_header_text:
                    w = True

                self.log_signal.emit(f"DEBUG | [STEP 2] 헤더 파싱 완료: S{s}F{f}, Wait={w}")
            else:
                self.log_signal.emit("DEBUG | [ERROR] Could not find S or F numbers inside the quotes.")
                return
        else:
            self.log_signal.emit("DEBUG | [Error] No quoted header (e.g., 'SxFy') found in input.")
            return # 파싱 실패 시 전송 중단
            
        # 토큰화 (모든 데이터 타입 추출)
        # <TYPE [LEN]> 또는 <TYPE 값> 형태 지원
        tokens = []
        for line in lines[1:]:
            clean_line = line.split('*')[0].strip()
            if not clean_line: continue
            # 태그, 문자열, 숫자, 닫기 기호를 분리
            line_tokens = re.findall(r"<[a-zA-Z0-9]+|'.*?'|[+-]?\d+\.?\d*|>", clean_line)
            tokens.extend(line_tokens)

        # SECS-II 표준 포맷 코드 (상위 6비트 값)
        # 수치형 데이터가 Unk로 나오지 않도록 정확한 포맷 정의
        FORMATS = {
            "<L": 0x00, "<B": 0x08, "<BOOLEAN": 0x09, "<A": 0x10,
            "<I8": 0x14, "<I1": 0x15, "<I2": 0x16, "<I4": 0x17,
            "<F8": 0x20, "<F4": 0x24,
            "<U8": 0x30, "<U1": 0x31, "<U2": 0x32, "<U4": 0x34
        }

        def pack_item(token_list):
            if not token_list: return b""
            tag = token_list.pop(0).upper()
                
            # 리스트 처리 (Recursive)
            if tag == "<L":
                children = []
                while token_list and token_list[0] != ">":
                    children.append(pack_item(token_list))
                if token_list: token_list.pop(0) # pop '>'
                 
                # 포맷(0x00) | 길이바이트수(1) = 0x01
                header = bytearray([0x01, len(children)])
                for c in children: header.extend(c)
                return header

            fmt_code = FORMATS.get(tag)
            if fmt_code is None: return b""

            val_str = token_list.pop(0).strip("'")
            if token_list and token_list[0] == ">": token_list.pop(0)
			
			 # 타입별 데이터 패킹 (Big-Endian)
            if tag == "<A":
                data = val_str.encode('ascii')
            elif tag == "<B":
                data = bytes.fromhex(val_str.replace(" ", ""))
            elif tag in ["<U1","<U2","<U4","<U8"]:
                fmt = {"<U1":"B", "<U2":"H", "<U4":"I", "<U8":"Q"}[tag]
                data = struct.pack(">" + fmt, int(float(val_str)))
            elif tag in ["<I1","<I2","<I4","<I8"]:
                fmt = {"<I1":"b", "<I2":"h", "<I4":"i", "<I8":"q"}[tag]
                data = struct.pack(">" + fmt, int(float(val_str)))
            elif tag == "<F4":
                data = struct.pack(">f", float(val_str))
            elif tag == "<F8":
                data = struct.pack(">d", float(val_str))
            elif tag == "<BOOLEAN":
                data = b'\xff' if val_str.upper() in ["TRUE", "1", "T"] else b'\x00'
            else:
                data = b""
			
            # 아이템 헤더: (Format << 2) | 0x01 (Length Byte Count 1)
            header_byte = (fmt_code << 2) | 0x01
			
            self.log_signal.emit(f"DEBUG | [Var tag] : {tag}")
            self.log_signal.emit(f"DEBUG | [Var val_str] : {val_str}")
            self.log_signal.emit(f"DEBUG | [Var data] : {data}")
			
            return bytearray([header_byte, len(data)]) + data

        # 전체 바이너리 구성
        body_bytes = bytearray()
        while tokens:
            body_bytes.extend(pack_item(tokens))
        
        self.log_signal.emit(f"DEBUG | [Var body_bytes] : {body_bytes}")
		
        # HSMS 패킷 결합 및 소켓 전송
        header = HSMSHeader(stream=s, function=f, s_type=0, wait_bit=w)
        self._sys_byte = (self._sys_byte + 1) % 0xFFFFFFFF
        header.system_bytes = self._sys_byte
        
        full_packet = header.pack() + body_bytes
        msg_len = len(full_packet)
        
        try:
            # 4바이트 길이 헤더 + 10바이트 HSMS 헤더 + 본문
            self.transport.write(struct.pack(">I", msg_len) + full_packet)
            self.log_full_message("SEND", header, body_bytes)
            self.log_signal.emit(f"DEBUG | [STEP 5] 소켓 전송 성공 (Total {msg_len + 4} bytes)")
        except Exception as e:
            self.log_signal.emit(f"DEBUG | [FATAL] 전송 중 오류 발생: {str(e)}")
            
    def set_state(self, new_state):
        if self.current_state != new_state:
            self.log_signal.emit(f"NODE STATUS | '{self.name}' state: {self.current_state} -> {new_state}")
            self.current_state = new_state
            self.status_changed.emit(self.name, new_state)

    async def run_task(self):
        self.running = True
        while self.running:
            try:
                loop = asyncio.get_running_loop()
                if self.mode == "Active":
                    self.log_signal.emit(f"NODE | Active: Connecting to {self.host}:{self.port}...")
                    self.transport, _ = await asyncio.wait_for(loop.create_connection(lambda: HSMSProtocol(self), self.host, self.port), timeout=5.0)
                    self.set_state("CONNECTED")
                    self.log_signal.emit("HANDSHAKE | SEND Select.req (S-Type 1)")
                    select_req = HSMSHeader(s_type=1, system_bytes=0x1234).pack()
                    self.transport.write(struct.pack(">I", len(select_req)) + select_req)
                    while self.running and self.transport and not self.transport.is_closing(): await asyncio.sleep(0.5)
                else:
                    self.log_signal.emit(f"NODE | Passive: Server listening on {self.port}...")
                    self.server = await loop.create_server(lambda: HSMSProtocol(self), '0.0.0.0', self.port)
                    async with self.server: await self.server.serve_forever()
            except Exception as e:
                self.set_state("NOT CONNECTED")
                self.log_signal.emit(f"NODE | Error: {e}")
                await asyncio.sleep(5.0)

    def stop(self):
        self.running = False
        if self.transport: self.transport.close()
        if self.server: self.server.close()

class HSMSProtocol(asyncio.Protocol):
    def __init__(self, instance): self.instance, self.buf = instance, bytearray()
    
    def connection_made(self, transport):
        self.instance.transport = transport
        peer = transport.get_extra_info('peername')
        self.instance.log_signal.emit(f"HANDSHAKE | Connection established with {peer}")
        if self.instance.mode == "Passive": self.instance.set_state("CONNECTED")

    def data_received(self, data):
        self.buf.extend(data)
        while len(self.buf) >= 4:
            length = struct.unpack(">I", self.buf[:4])[0]
            if len(self.buf) < 4 + length: break
            raw = self.buf[4:4+length]
            self.buf = self.buf[4+length:]
            header = HSMSHeader.unpack(raw[:10])
            
            if header.s_type == 1: # Select.req
                self.instance.log_signal.emit(f"HANDSHAKE | RECV Select.req (SysByte: {header.system_bytes:08X})")
                self.instance.log_signal.emit("HANDSHAKE | SEND Select.rsp (Success)")
                resp = HSMSHeader(s_type=2, system_bytes=header.system_bytes).pack()
                if self.instance.transport: self.instance.transport.write(struct.pack(">I", len(resp)) + resp)
                self.instance.set_state("SELECTED")
            elif header.s_type == 2: # Select.rsp
                self.instance.log_signal.emit(f"HANDSHAKE | RECV Select.rsp (SysByte: {header.system_bytes:08X})")
                self.instance.set_state("SELECTED")
            elif header.s_type == 0: # Data Message
                self.instance.log_full_message("RECV", header, raw[10:])
                
    def connection_lost(self, exc):
        self.instance.log_signal.emit("HANDSHAKE | Connection lost.")
        self.instance.set_state("NOT CONNECTED")

# --- [3. Main UI Application] ---
class HSMSMonitorApp(QMainWindow):
    def __init__(self, loop):
        super().__init__()
        self.sessions, self.loop, self.current_node_name = {}, loop, None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HSMS Master v2.5.12 - Fixed Message Transmission")
        self.resize(1100, 900)
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        
        # --- 왼쪽 패널 (기존 디자인 철저 유지) ---
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

        btn_apply = QPushButton("Apply Config"); btn_apply.clicked.connect(self.apply_node)
        btn_start = QPushButton("START"); btn_start.setStyleSheet("background:#2980b9; color:white; font-weight:bold;")
        btn_start.clicked.connect(self.start_comm)
        btn_stop = QPushButton("STOP"); btn_stop.setStyleSheet("background:#c0392b; color:white; font-weight:bold;")
        btn_stop.clicked.connect(self.stop_comm)

        self.st_nc, self.st_ns, self.st_sl = self._st_lbl("NOT CONNECTED"), self._st_lbl("NOT SELECTED"), self._st_lbl("SELECTED")

        left_panel.addWidget(cfg_box); left_panel.addWidget(btn_apply)
        left_panel.addWidget(btn_start); left_panel.addWidget(btn_stop)
        left_panel.addWidget(self.st_nc); left_panel.addWidget(self.st_ns); left_panel.addWidget(self.st_sl)
        left_panel.addStretch()

        # --- 오른쪽 패널 ---
        right_panel = QVBoxLayout()
        splitter = QSplitter(Qt.Orientation.Vertical)

        send_group = QGroupBox("Message Transmission (Auto Header Detect)")
        s_lay = QVBoxLayout()
        self.in_payload = QTextEdit()
        self.in_payload.setPlaceholderText("예: GetPJObj : 'S14F1' W\n<L [0]>")
        btn_send = QPushButton("SEND MESSAGE"); btn_send.setStyleSheet("background:#27ae60; color:white; font-weight:bold; height:35px;")
        btn_send.clicked.connect(self.send_message_action)
        s_lay.addWidget(self.in_payload); s_lay.addWidget(btn_send)
        send_group.setLayout(s_lay)

        log_group = QGroupBox("Communication Logs")
        l_lay = QVBoxLayout()
        self.log_view = QTextEdit(); self.log_view.setReadOnly(True); self.log_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.log_view.setStyleSheet("background:#121212; color:#00ff00; font-family:Consolas; font-size:9pt;")
        l_lay.addWidget(self.log_view); log_group.setLayout(l_lay)

        splitter.addWidget(send_group); splitter.addWidget(log_group)
        splitter.setStretchFactor(1, 4)
        right_panel.addWidget(splitter)

        main_layout.addLayout(left_panel, 1); main_layout.addLayout(right_panel, 3)
        self.setCentralWidget(main_widget)

    def _st_lbl(self, txt):
        l = QLabel(txt); l.setAlignment(Qt.AlignmentFlag.AlignCenter); l.setMinimumHeight(40)
        l.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Plain)
        l.setStyleSheet("background:#34495e; color:#7f8c8d;")
        return l

    def apply_node(self):
        name = self.in_name.text()
        if not name: return
        inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), "Active" if self.rb_act.isChecked() else "Passive")
        inst.status_changed.connect(self.update_state_ui)
        inst.log_signal.connect(lambda m: self.log_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] {m}"))
        self.sessions[name] = inst; self.combo_nodes.addItem(name)
        self.log_view.append(f"UI | Node '{name}' Configured.")

    def update_state_ui(self, name, status):
        if name != self.current_node_name: return
        off, on = "background:#34495e; color:#7f8c8d;", "background:#2ecc71; color:#000; font-weight:bold;"
        self.st_nc.setStyleSheet(off); self.st_ns.setStyleSheet(off); self.st_sl.setStyleSheet(off)
        if status == "SELECTED": self.st_sl.setStyleSheet(on)
        elif status == "CONNECTED": self.st_ns.setStyleSheet(on)
        else: self.st_nc.setStyleSheet(on)

    def on_node_selected(self, idx):
        if idx <= 0: return
        self.current_node_name = self.combo_nodes.currentText()
        self.update_state_ui(self.current_node_name, self.sessions[self.current_node_name].current_state)

    def send_message_action(self):
        if self.current_node_name:
            asyncio.run_coroutine_threadsafe(self.sessions[self.current_node_name].send_data_message(self.in_payload.toPlainText()), self.loop)

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