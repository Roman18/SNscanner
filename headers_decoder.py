import struct
import ipaddress


class IP:
    def __init__(self, buffer):
        header = struct.unpack("<BBHHHBBH4s4s", buffer)
        self.ver = header[0] >> 4
        self.h_size = header[0] & 0xF
        self.type = header[1]
        self.p_size = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.p_num = header[6]
        self.sum = header[7]
        self.src = ipaddress.ip_address(header[8])
        self.dst = ipaddress.ip_address(header[9])

        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}

        self.protocol = str(self.p_num) if protocols.get(self.p_num) is None else protocols.get(self.p_num)


class ICMP:
    def __init__(self, buffer):
        header = struct.unpack("<BBHHH", buffer)
        self.type = header[0]
        self.code = header[1]
        self.chek_sum = header[2]
        self.id = header[3]
        self.number = header[4]
