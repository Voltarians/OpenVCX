# SPDX-License-Identifier: LGPL-3.0-only
"""Portable ELM command core. Backend owns the exclusive physical session."""
from typing import Protocol
import re

class Backend(Protocol):
    def connect(self, bitrate: int, extended: bool) -> None: ...
    def exchange(self, identifier: int, payload: bytes, extended: bool,
                 timeout_ms: int) -> list[tuple[int, bytes]]: ...
    def voltage(self) -> float: ...
    def close(self) -> None: ...

class Elm327:
    def __init__(self, backend: Backend):
        self.backend = backend
        self.reset()

    def reset(self):
        self.echo = self.spaces = self.lines = True
        self.headers = False
        self.protocol = 0
        self.header = None
        self.filter = None
        self.timeout = 200
        self.previous = ""
        self.connected = False

    def command(self, raw: str) -> str:
        cmd = re.sub(r"\s+", "", raw).upper() or self.previous
        self.previous = cmd
        prefix = raw.strip() + "\r" if self.echo and raw.strip() else ""
        try:
            out = self.execute(cmd)
        except (OSError, RuntimeError, ValueError):
            out = "CAN ERROR"
        sep = "\r\n" if self.lines else "\r"
        return prefix + out.replace("\n", sep) + sep + ">"

    def execute(self, cmd):
        if cmd in ("ATZ", "ATWS", "ATD"):
            self.backend.close()
            self.reset()
            return "OK" if cmd == "ATD" else "OpenVCX ELM327"
        if cmd in ("ATI", "AT@1"):
            return "OpenVCX ELM327"
        for key, attr in (("ATE", "echo"), ("ATS", "spaces"),
                          ("ATL", "lines"), ("ATH", "headers")):
            if cmd in (key+"0", key+"1"):
                setattr(self, attr, cmd.endswith("1"))
                return "OK"
        if cmd in ("ATSP0", "ATSP6", "ATSP7", "ATSP8", "ATSP9"):
            self.backend.close()
            self.protocol = int(cmd[-1])
            self.connected = False
            self.header = self.filter = None
            return "OK"
        if cmd == "ATDPN":
            return ("A6" if self.connected else "0") if not self.protocol else str(self.protocol)
        if cmd == "ATDP":
            p = self.protocol or 6
            return ("AUTO, " if not self.protocol else "") + "ISO 15765-4 (CAN %s/%s)" % (29 if p in (7,9) else 11, 250 if p in (8,9) else 500)
        if cmd == "ATRV":
            return "%.1fV" % self.backend.voltage()
        if re.fullmatch(r"ATST[0-9A-F]{2}", cmd):
            self.timeout = max(4, int(cmd[4:],16)*4)
            return "OK"
        if cmd == "ATCRA":
            self.filter = None
            return "OK"
        if re.fullmatch(r"AT(?:SH|CRA)(?:[0-9A-F]{3}|[0-9A-F]{8})", cmd):
            body = cmd[4:] if cmd.startswith("ATSH") else cmd[5:]
            value = int(body,16)
            if value > (0x7ff if len(body)==3 else 0x1fffffff):
                return "?"
            if cmd.startswith("ATSH"):
                self.header = value
            else:
                self.filter = value
            return "OK"
        if not re.fullmatch(r"(?:[0-9A-F]{2}){1,7}", cmd):
            return "?"
        payload = bytes.fromhex(cmd)
        # Initial qualification intentionally allows only read services.
        if payload[0] not in (1, 3, 7, 9, 0x0a, 0x22):
            return "?"
        p = self.protocol or 6
        extended = p in (7,9)
        identifier = self.header if self.header is not None else (0x18db33f1 if extended else 0x7df)
        if identifier > (0x1fffffff if extended else 0x7ff):
            return "?"
        if not self.connected:
            self.backend.connect(250000 if p in (8,9) else 500000, extended)
            self.connected = True
        rows = self.backend.exchange(identifier, payload, extended, self.timeout)
        sep = " " if self.spaces else ""
        lines = []
        for address, data in rows:
            if self.filter is not None and address != self.filter:
                continue
            body = sep.join("%02X" % b for b in data)
            if self.headers:
                body = ("%08X" if extended else "%03X") % address + sep + body
            lines.append(body)
        return "\n".join(lines) or "NO DATA"
