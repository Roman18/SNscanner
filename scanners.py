import socket
import os
from headers_decoder import IP, ICMP
import ipaddress


class HostScanner:
    def __init__(self, host, subnet):
        self.host = host
        self.subnet = subnet
        self.MESSAGE = 'JUST SCAN'
        self.scanner = None
        self.__prepare_socket()

    def __prepare_socket(self):
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.scanner = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.scanner.bind((self.host, 0))
        self.scanner.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == "nt":
            self.scanner.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def host_scan(self) -> list:
        hosts = []
        try:
            while True:
                raw_bytes = self.scanner.recvfrom(65565)[0]
                ip = IP(raw_bytes[:20])

                if ip.protocol == "ICMP":
                    offset = ip.h_size * 4
                    buff = raw_bytes[offset: offset + 8]
                    icmp = ICMP(buff)
                    if icmp.type == 3 and icmp.code == 3:
                        if ipaddress.ip_address(ip.src) in ipaddress.IPv4Network(self.subnet):

                            if raw_bytes[len(raw_bytes) - len(self.MESSAGE):] == bytes(self.MESSAGE, 'utf-8'):
                                target = str(ip.src)
                                if target != self.host and target not in hosts:
                                    print(f'Host up: {target}')
                                    hosts.append(target)
        except KeyboardInterrupt as e:
            print('Host Scanner was interrupted by user')
        finally:
            if os.name == "nt":
                self.scanner.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        return hosts

    def send_udp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for ip in ipaddress.ip_network(self.subnet).hosts():
                s.sendto(self.MESSAGE.encode('utf-8'), (str(ip), 60123))


# TODO: port scanner of alive hosts
class PortScanner:
    ...
