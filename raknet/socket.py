import errno
import socket
from abc import ABC
from typing import Self, Optional

from .other import InternetAddress

__all__ = [
    'ClientSocket',
    'ServerSocket',
]


class Socket(ABC):
    def __init__(self, ipv6: bool):
        try:
            __socket = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
        except socket.error as err:
            raise RuntimeError(err)

        self.socket = __socket
        if ipv6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

    def close(self) -> None:
        self.socket.close()

    def set_send_buffer(self, size: int) -> Self:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, size)
        return self

    def set_recv_buffer(self, size: int) -> Self:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
        return self

    def set_recv_timeout(self, seconds: int) -> Self:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, seconds)
        return self

    def set_blocking(self, blocking: bool) -> None:
        self.socket.setblocking(blocking)


class ClientSocket(Socket):
    def __init__(self, address: InternetAddress):
        super().__init__(address.version == 6)

        self.address = address
        try:
            self.socket.connect((address.ip, address.port))
        except socket.error as e:
            code, message = e.args
            raise RuntimeError(f"Failed to connect to {address.ip}:{address.port} (code {code}):", message.strip())

        # TODO: is an 8 MB buffer really appropriate for a client??
        self.set_send_buffer(1024 * 1024 * 8).set_recv_buffer(1024 * 1024 * 8)

    def read_packet(self) -> Optional[bytes]:
        try:
            buffer = self.socket.recv(socket.SOL_SOCKET, 0)
        except socket.error as e:
            code, message = e.args
            if code == errno.EWOULDBLOCK:
                return None
            raise RuntimeError(f"Failed to recv (code {code}):", message.strip())
        return buffer

    def write_packet(self, buffer: bytes) -> int:
        try:
            result = self.socket.send(buffer, 0)
        except socket.error as e:
            code, message = e.args
            raise RuntimeError(f"Failed to send packet (code {code}):", message.strip())
        return result


class ServerSocket(Socket):
    def __init__(self, address: InternetAddress):
        super().__init__(address.version == 6)
        try:
            self.socket.bind((address.ip, address.port))
        except socket.error as e:
            code, message = e.args
            if code == errno.EADDRINUSE:
                raise RuntimeError(f"Failed to bind socket. Something else is already running on {address.ip}:{address.port} (code {code}):", message.strip())
            raise RuntimeError(f"Failed to bind to {address.ip}:{address.port} (code {code}):", message.strip())

    def set_broadcast(self, broadcast: bool) -> bool:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1 if broadcast else 0)
        return broadcast

    def read_packet(self) -> Optional[bytes]:
        try:
            buffer = self.socket.recvfrom(65535, 0)
        except socket.error as e:
            code, message = e.args
            if code == errno.EWOULDBLOCK:
                return None
            raise RuntimeError(f"Failed to recv (code {code}):", message.strip())
        return buffer[0]

    def write_packet(self, buffer: bytes, ip: str, port: int) -> int:
        try:
            result = self.socket.sendto(buffer, (ip, port))
        except socket.error as e:
            code, message = e.args
            raise RuntimeError(f"Failed to send to {ip}:{port} (code {code}):", message.strip())
        return result
