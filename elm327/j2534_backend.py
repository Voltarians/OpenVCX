# SPDX-License-Identifier: LGPL-3.0-only
import ctypes as C
import time
import os

U = C.c_uint32
class Message(C.Structure):
    _fields_ = [(n,U) for n in ("ProtocolID","RxStatus","TxFlags","Timestamp","DataSize","ExtraDataIndex")] + [("Data", C.c_ubyte * 4128)]

class J2534Backend:
    def __init__(self, path):
        if os.name != "nt":
            raise OSError("Windows DLL backend only")
        self.dll = C.WinDLL(os.path.abspath(path))
        self.device = None
        self.channel = None
        self.filters = []
        self.extended = False
        P = C.POINTER(U)
        M = C.POINTER(Message)
        signatures = {
            "Open": [C.c_void_p,P], "Close":[U],
            "Connect":[U,U,U,U,P], "Disconnect":[U],
            "ReadMsgs":[U,M,P,U], "WriteMsgs":[U,M,P,U],
            "StartMsgFilter":[U,U,M,M,M,P],
            "Ioctl":[U,U,C.c_void_p,C.c_void_p],
        }
        for name,args in signatures.items():
            f = getattr(self.dll,"PassThru"+name)
            f.argtypes = args
            f.restype = C.c_int32

    def call(self,name,*args):
        status = getattr(self.dll,"PassThru"+name)(*args)
        if status:
            raise OSError("PassThru%s: 0x%X" % (name,status))

    def open(self):
        if self.device is None:
            d = U()
            self.call("Open",None,C.byref(d))
            self.device = d.value

    def connect(self, bitrate, extended):
        self.close()
        self.open()
        ch = U()
        self.extended = extended
        try:
            self.call("Connect",self.device,6,0x100 if extended else 0,bitrate,C.byref(ch))
            self.channel = ch.value
        except OSError:
            self.close()
            raise

    def message(self, identifier, payload=b""):
        m = Message()
        m.ProtocolID = 6
        m.TxFlags = 0x40 | (0x100 if self.extended else 0)
        raw = identifier.to_bytes(4,"big") + payload
        m.DataSize = len(raw)
        m.Data[:len(raw)] = raw
        return m

    def configure_filters(self, identifier):
        if self.extended:
            if identifier == 0x18db33f1:
                raise OSError("29-bit functional ISO-TP not qualified")
            if identifier & 0x1fff00ff != 0x18da00f1:
                raise OSError("Unsupported physical address")
            pairs = [(0x18daf100 | ((identifier >> 8)&255), identifier)]
        elif identifier == 0x7df:
            pairs = [(i+8,i) for i in range(0x7e0,0x7e8)]
        elif 0x7e0 <= identifier <= 0x7e7:
            pairs = [(identifier+8,identifier)]
        else:
            raise OSError("Unsupported physical address")
        self.call("Ioctl",self.channel,0x0a,None,None)
        for rx,tx in pairs:
            mask = self.message(0x1fffffff if self.extended else 0x7ff)
            pattern,flow = self.message(rx),self.message(tx)
            f = U()
            self.call("StartMsgFilter",self.channel,3,C.byref(mask),C.byref(pattern),C.byref(flow),C.byref(f))

    def exchange(self, identifier, payload, extended, timeout_ms):
        if self.channel is None or extended != self.extended:
            raise OSError("Channel not open")
        self.configure_filters(identifier)
        self.call("Ioctl",self.channel,8,None,None)
        msg,n = self.message(identifier,payload),U(1)
        self.call("WriteMsgs",self.channel,C.byref(msg),C.byref(n),timeout_ms)
        if n.value != 1:
            raise OSError("Message not accepted")
        end = time.monotonic()+timeout_ms/1000
        rows = []
        while time.monotonic() < end:
            msg,n = Message(),U(1)
            status = self.dll.PassThruReadMsgs(self.channel,C.byref(msg),C.byref(n),max(1,int((end-time.monotonic())*1000)))
            if status in (9,16):
                break
            if status:
                raise OSError("ReadMsgs: 0x%X" % status)
            if n.value and not msg.RxStatus & 0x0b and 4 < msg.DataSize <= 4128:
                raw = bytes(msg.Data[:msg.DataSize])
                rows.append((int.from_bytes(raw[:4],"big"),raw[4:]))
        return rows

    def voltage(self):
        self.open()
        mv = U()
        self.call("Ioctl",self.device,3,None,C.byref(mv))
        return mv.value/1000

    def close(self):
        try:
            if self.channel is not None:
                ch,self.channel = self.channel,None
                self.call("Disconnect",ch)
        finally:
            if self.device is not None:
                d,self.device = self.device,None
                self.call("Close",d)
