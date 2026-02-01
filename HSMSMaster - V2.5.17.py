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
        # SECS-II 표준 포맷 코드 (상위 6비트 값)
        TYPE_MAP = {
            0x00: "<L",        # List
            0x08: "<B",        # Binary
            0x09: "<BOOLEAN",  # Boolean
            0x10: "<A",        # ASCII
            0x14: "<I8", 0x15: "<I1", 0x16: "<I2", 0x17: "<I4",
            0x20: "<F8", 0x24: "<F4",
            0x30: "<U8", 0x31: "<U1", 0x32: "<U2", 0x34: "<U4"
        }
        
        # 상대방 주소 정보 가져오기
        peer = "Unknown"
        if self.transport:
            try:
                peer_info = self.transport.get_extra_info('peername')
                peer = f"{peer_info[0]}:{peer_info[1]}"
            except: pass

        # 전송 방향에 따른 경로 문자열 생성
        if direction == "SEND":
            path_info = f"LOCAL[{self.name}] -> REMOTE[{peer}]"
        else:
            path_info = f"REMOTE[{peer}] -> LOCAL[{self.name}]"

        # 로그 출력부 (경로 정보 추가)
        self.log_signal.emit(f"== MESSAGE {direction} ==")
        self.log_signal.emit(f"PATH: {path_info}")
        self.log_signal.emit(f"INFO: {header}")

        def decode_recursive(data, offset, indent):
            lines = []
            if offset >= len(data):
                return lines, offset

            # 1. 헤더 분석
            fb = data[offset]
            # 상위 6비트만 추출 (포맷 코드)
            fmt = (fb & 0xFC) >> 2
            # 하위 2비트 (길이 바이트의 개수: 1, 2, 3)
            lb_cnt = fb & 0x03
            offset += 1

            # 2. 데이터 길이 추출
            if lb_cnt == 1:
                length = data[offset]; offset += 1
            elif lb_cnt == 2:
                length = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
            elif lb_cnt == 3:
                length = struct.unpack(">I", b'\x00' + data[offset:offset+3])[0]; offset += 3
            else:
                length = 0

            t_name = TYPE_MAP.get(fmt, f"<UNK:{fmt:02X}>")
            padding = "  " * indent

            # 3. 타입별 처리
            if fmt == 0x00:  # List
                lines.append(f"{padding}<L[{length}]")
                for _ in range(length):
                    child_lines, next_off = decode_recursive(data, offset, indent + 1)
                    lines.extend(child_lines)
                    offset = next_off
                lines.append(f"{padding}>")
            else:
                # 데이터 추출
                val_data = data[offset:offset+length]
                offset += length
                
                if t_name == "<A":
                    # ASCII 처리 
                    v_str = val_data.decode('ascii', errors='replace')
                elif t_name in ["<U1", "<U2", "<U4", "<U8"]:
                    f = {"<U1": "B", "<U2": "H", "<U4": "I", "<U8": "Q"}[t_name]
                    v_str = str(struct.unpack(">" + f, val_data)[0])
                elif t_name in ["<I1", "<I2", "<I4", "<I8"]:
                    f = {"<I1": "b", "<I2": "h", "<I4": "i", "<I8": "q"}[t_name]
                    v_str = str(struct.unpack(">" + f, val_data)[0])
                elif t_name in ["<F4", "<F8"]:
                    f = ">f" if t_name == "<F4" else ">d"
                    v_str = f"{struct.unpack(f, val_data)[0]:g}"
                elif t_name == "<BOOLEAN":
                    v_str = "TRUE" if val_data != b'\x00' else "FALSE"
                else:
                    v_str = val_data.hex().upper()
                
                lines.append(f"{padding}{t_name} '{v_str}'>")
            
            return lines, offset

        # 로그 출력부
        self.log_signal.emit(f"{direction} [{header}]")
        self.log_signal.emit("--- HEX RAW VIEW ---")
        self.log_signal.emit(' '.join(f"{b:02X}" for b in body_bytes))
        self.log_signal.emit("--- STRUCTURE VIEW ---")
        
        curr_off = 0
        while curr_off < len(body_bytes):
            res_lines, next_off = decode_recursive(body_bytes, curr_off, 0)
            for l in res_lines:
                self.log_signal.emit(l)
            curr_off = next_off
            
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
        self.setWindowTitle("HSMS Master v2.5.17")
        self.resize(1100, 950)
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        
        # --- 왼쪽 패널 ---
        left_panel = QVBoxLayout()
        
        # [통합] Node & Parameter Config 그룹
        cfg_box = QGroupBox("Node Configuration")
        f_lay = QFormLayout()
        
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItem("--- New Node ---")
        self.combo_nodes.currentIndexChanged.connect(self.on_node_selected)
        
        self.in_name = QLineEdit()
        self.in_host = QLineEdit("127.0.0.1")
        self.in_port = QLineEdit("5000")
        
        self.rb_act = QRadioButton("Active")
        self.rb_pas = QRadioButton("Passive")
        self.rb_act.setChecked(True)
        mode_h = QHBoxLayout(); mode_h.addWidget(self.rb_act); mode_h.addWidget(self.rb_pas)
        
        f_lay.addRow("Select Node:", self.combo_nodes)
        f_lay.addRow("Node Name:", self.in_name)
        f_lay.addRow("Mode:", mode_h)
        f_lay.addRow("IP Address:", self.in_host)
        f_lay.addRow("Port:", self.in_port)
        
        # HSMS 파라미터 입력창
        self.in_t3 = QLineEdit("45")
        self.in_t5 = QLineEdit("10")
        self.in_t6 = QLineEdit("5")
        self.in_t8 = QLineEdit("5")
        f_lay.addRow("T3 (Reply):", self.in_t3)
        f_lay.addRow("T5 (Connect):", self.in_t5)
        f_lay.addRow("T6 (Control):", self.in_t6)
        f_lay.addRow("T8 (Network):", self.in_t8)
        
        # 통합 버튼 추가
        self.btn_apply_all = QPushButton("Apply All Config")
        self.btn_apply_all.setStyleSheet("background:#34495e; color:white; font-weight:bold; height:30px;")
        self.btn_apply_all.clicked.connect(self.apply_all_config)
        f_lay.addRow(self.btn_apply_all)
        
        cfg_box.setLayout(f_lay)
        left_panel.addWidget(cfg_box)

        # START / STOP 버튼
        btn_start = QPushButton("START"); btn_start.setStyleSheet("background:#2980b9; color:white; font-weight:bold;")
        btn_start.clicked.connect(self.start_comm)
        btn_stop = QPushButton("STOP"); btn_stop.setStyleSheet("background:#c0392b; color:white; font-weight:bold;")
        btn_stop.clicked.connect(self.stop_comm)

        self.st_nc, self.st_ns, self.st_sl = self._st_lbl("NOT CONNECTED"), self._st_lbl("NOT SELECTED"), self._st_lbl("SELECTED")

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
    
    def safe_log(self, message):
        """안전한 로그 추가 메서드 - HTML 태그를 이스케이프 처리"""
        try:
            # HTML 특수문자 이스케이프
            safe_message = message.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            timestamp = datetime.now().strftime('%H:%M:%S')
            # append()를 사용하되, HTML 이스케이프된 텍스트 사용
            self.log_view.append(f"<pre>[{timestamp}] {safe_message}</pre>")
        except Exception as e:
            print(f"[ERROR] Failed to log message: {e}")
            
    def apply_all_config(self):
        """이름, 모드, 네트워크 정보 및 HSMS 파라미터를 통합하여 적용"""
        name = self.in_name.text().strip()
        if not name:
            self.safe_log("ERROR | Node name is required.")
            return

        try:
            host = self.in_host.text()
            port = int(self.in_port.text())
            mode = "Active" if self.rb_act.isChecked() else "Passive"
            
            # 파라미터 딕셔너리 생성
            new_params = {
                'T3': float(self.in_t3.text()),
                'T5': float(self.in_t5.text()),
                'T6': float(self.in_t6.text()),
                'T8': float(self.in_t8.text())
            }

            if name not in self.sessions:
                # [신규 노드 생성]
                inst = HSMSInstance(name, host, port, mode, params=new_params)
                inst.status_changed.connect(self.update_state_ui)
                inst.log_signal.connect(self.safe_log)
                self.sessions[name] = inst
                self.combo_nodes.addItem(name)
                self.safe_log(f"UI | New Node '{name}' created and configured.")
            else:
                # [기존 노드 수정]
                node = self.sessions[name]
                node.host = host
                node.port = port
                node.mode = mode
                node.params.update(new_params)
                self.safe_log(f"UI | Node '{name}' configuration updated.")

        except ValueError as e:
            self.safe_log(f"ERROR | Invalid input: {str(e)}. Please check Port and T-Parameters.")
            
    def apply_node(self):
        try:
            name = self.in_name.text()
            if not name:
                print("[DEBUG] No name provided")
                return
            
            print(f"[DEBUG] Creating node: {name}")
            inst = HSMSInstance(name, self.in_host.text(), int(self.in_port.text()), 
                              "Active" if self.rb_act.isChecked() else "Passive")
            
            print(f"[DEBUG] Connecting status_changed signal")
            inst.status_changed.connect(self.update_state_ui)
            
            print(f"[DEBUG] Connecting log_signal")
            # safe_log 메서드 사용
            inst.log_signal.connect(self.safe_log)
            
            print(f"[DEBUG] Adding to sessions")
            self.sessions[name] = inst
            
            print(f"[DEBUG] Adding to combo box")
            self.combo_nodes.addItem(name)
            
            print(f"[DEBUG] Appending log message")
            self.safe_log(f"UI | Node '{name}' Configured.")
            
            print(f"[DEBUG] Node '{name}' configured successfully")
        except Exception as e:
            error_msg = f"Error in apply_node: {type(e).__name__}: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            # UI가 있다면 표시
            try:
                self.safe_log(f"ERROR | {error_msg}")
            except:
                pass

    def update_state_ui(self, name, status):
        if name != self.current_node_name: return
        off, on = "background:#34495e; color:#7f8c8d;", "background:#2ecc71; color:#000; font-weight:bold;"
        self.st_nc.setStyleSheet(off); self.st_ns.setStyleSheet(off); self.st_sl.setStyleSheet(off)
        if status == "SELECTED": self.st_sl.setStyleSheet(on)
        elif status == "CONNECTED": self.st_ns.setStyleSheet(on)
        else: self.st_nc.setStyleSheet(on)

    def on_node_selected(self, idx):
        if idx <= 0:
            self.current_node_name = None
            self.in_name.clear()
            return
            
        self.current_node_name = self.combo_nodes.currentText()
        node = self.sessions[self.current_node_name]
        
        # 1. 기본 정보 갱신 (이름, 모드, IP, Port)
        self.in_name.setText(node.name)
        self.in_host.setText(node.host)
        self.in_port.setText(str(node.port))
        if node.mode == "Active":
            self.rb_act.setChecked(True)
        else:
            self.rb_pas.setChecked(True)
            
        # 2. HSMS 파라미터 갱신
        self.in_t3.setText(str(node.params.get('T3', 45)))
        self.in_t5.setText(str(node.params.get('T5', 10)))
        self.in_t6.setText(str(node.params.get('T6', 5)))
        self.in_t8.setText(str(node.params.get('T8', 5)))
        
        # 3. 상태 UI 업데이트
        self.update_state_ui(self.current_node_name, node.current_state)
        
    def apply_parameters_action(self):
        """현재 화면의 입력값을 선택된 노드의 파라미터로 저장"""
        if not self.current_node_name:
            self.safe_log("ERROR | No node selected. Please select a node first.")
            return
            
        node = self.sessions[self.current_node_name]
        try:
            # 입력값을 숫자로 변환하여 노드의 params 딕셔너리에 저장
            node.params['T3'] = float(self.in_t3.text())
            node.params['T5'] = float(self.in_t5.text())
            node.params['T6'] = float(self.in_t6.text())
            node.params['T8'] = float(self.in_t8.text())
            
            self.safe_log(f"UI | Parameters updated for Node '{self.current_node_name}': "
                          f"T3={node.params['T3']}, T5={node.params['T5']}, "
                          f"T6={node.params['T6']}, T8={node.params['T8']}")
        except ValueError:
            self.safe_log("ERROR | Invalid parameter value. Please enter numbers only.")
            
    def send_message_action(self):
        try:
            if self.current_node_name:
                print(f"[DEBUG] Sending message for node: {self.current_node_name}")
                asyncio.run_coroutine_threadsafe(
                    self.sessions[self.current_node_name].send_data_message(self.in_payload.toPlainText()), 
                    self.loop
                )
            else:
                print("[DEBUG] No node selected")
                self.safe_log("ERROR | No node selected. Please select a node first.")
        except Exception as e:
            error_msg = f"Error in send_message_action: {type(e).__name__}: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            try:
                self.safe_log(f"ERROR | {error_msg}")
            except:
                pass

    def start_comm(self):
        try:
            if self.current_node_name:
                print(f"[DEBUG] Starting communication for node: {self.current_node_name}")
                asyncio.run_coroutine_threadsafe(
                    self.sessions[self.current_node_name].run_task(), 
                    self.loop
                )
            else:
                print("[DEBUG] No node selected for start")
                self.safe_log("ERROR | No node selected. Please select a node first.")
        except Exception as e:
            error_msg = f"Error in start_comm: {type(e).__name__}: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            try:
                self.safe_log(f"ERROR | {error_msg}")
            except:
                pass

    def stop_comm(self):
        try:
            if self.current_node_name:
                print(f"[DEBUG] Stopping communication for node: {self.current_node_name}")
                self.sessions[self.current_node_name].stop()
            else:
                print("[DEBUG] No node selected for stop")
                self.safe_log("ERROR | No node selected.")
        except Exception as e:
            error_msg = f"Error in stop_comm: {type(e).__name__}: {str(e)}"
            print(error_msg)
            import traceback
            traceback.print_exc()
            try:
                self.safe_log(f"ERROR | {error_msg}")
            except:
                pass

class AsyncLoopThread(QThread):
    def __init__(self):
        super().__init__()
        self.loop = None
    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop); self.loop.run_forever()

if __name__ == "__main__":
    try:
        print("[DEBUG] Starting application...")
        app = QApplication(sys.argv)
        
        print("[DEBUG] Creating async thread...")
        t = AsyncLoopThread()
        t.start()
        
        print("[DEBUG] Waiting for event loop...")
        while not t.loop:
            pass
        
        print("[DEBUG] Creating main window...")
        win = HSMSMonitorApp(t.loop)
        
        print("[DEBUG] Showing window...")
        win.show()
        
        print("[DEBUG] Starting Qt event loop...")
        sys.exit(app.exec())
    except Exception as e:
        print(f"[FATAL ERROR] {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)