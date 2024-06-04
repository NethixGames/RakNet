import socket
from abc import ABC, abstractmethod
from typing import Self

from binary import BinaryStream, ByteOrder

from .other import InternetAddress

__all__ = [
    'Packet',
    'OnlinePacket',
    'OfflinePacket',
    'PacketReliability',
    'PacketSerializer'
]


class PacketReliability:
    UNRELIABLE = 0x00
    UNRELIABLE_SEQUENCED = 0x01
    RELIABLE = 0x02
    RELIABLE_ORDERED = 0x03
    RELIABLE_SEQUENCED = 0x04
    UNRELIABLE_WITH_ACK_RECEIPT = 0x05
    RELIABLE_WITH_ACK_RECEIPT = 0x06
    RELIABLE_ORDERED_WITH_ACK_RECEIPT = 0x07

    @staticmethod
    def is_reliable(reliability: int) -> bool:
        return reliability not in [
            PacketReliability.UNRELIABLE,
            PacketReliability.UNRELIABLE_SEQUENCED,
            PacketReliability.UNRELIABLE_WITH_ACK_RECEIPT
        ]

    @staticmethod
    def is_ordered(reliability: int) -> bool:
        return reliability in [
            PacketReliability.UNRELIABLE_SEQUENCED,
            PacketReliability.RELIABLE_ORDERED,
            PacketReliability.RELIABLE_SEQUENCED,
            PacketReliability.RELIABLE_ORDERED_WITH_ACK_RECEIPT
        ]

    @staticmethod
    def is_sequenced(reliability: int) -> bool:
        return reliability in [
            PacketReliability.UNRELIABLE_SEQUENCED,
            PacketReliability.RELIABLE_SEQUENCED,
        ]


class PacketSerializer(BinaryStream):
    def read_string(self) -> str:
        return self.read(self.read_short()).decode('ascii')

    def write_string(self, value: str) -> None:
        self.write_short(len(value))
        self.write(value.encode('ascii'))

    def read_address(self) -> InternetAddress:
        version = self.read_byte()
        if version == 4:
            network_ids = []
            for _ in range(4):
                network_ids.append(str(~self.read_byte() & 0xff))
            ip = '.'.join(network_ids)
            port = self.read_short()
            return InternetAddress(ip, port, version)
        elif version == 6:
            self.read_short(order=ByteOrder.LITTLE_ENDIAN)
            port = self.read_short()

            self.read_int()
            ip = socket.inet_ntop(socket.AF_INET6, self.read(16))

            self.read_int()
            return InternetAddress(ip, port, version)
        else:
            raise ValueError(f'Unknown IP address version: {version}')

    def write_address(self, value: InternetAddress) -> None:
        self.write_byte(value.version)
        if value.version == 4:
            network_ids = value.ip.split('.')
            for part in network_ids:
                self.write_byte(~int(part) & 0xff)
            self.write_short(value.port)
        elif value.version == 6:
            self.write_short(socket.AF_INET6, order=ByteOrder.LITTLE_ENDIAN)
            self.write_short(value.port)

            self.write_int(0)
            self.write(socket.inet_pton(socket.AF_INET6, value.ip))
            self.write_int(0)


class Packet(ABC):
    ID: int = -1

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        pass

    def encode_header(self, __out: PacketSerializer) -> None:
        __out.write_byte(self.ID)

    @abstractmethod
    def encode_payload(self, __out: PacketSerializer) -> None:
        pass

    def encode(self, __out: PacketSerializer) -> None:
        self.encode_header(__out)
        self.encode_payload(__out)

    def decode_header(self, __in: PacketSerializer) -> None:
        if __in.read_byte() != self.ID:
            raise ValueError(f'Invalid packet ID: {__in.read_byte()}')

    @abstractmethod
    def decode_payload(self, __in: PacketSerializer) -> None:
        pass

    def decode(self, __in: PacketSerializer) -> None:
        self.decode_header(__in)
        self.decode_payload(__in)


class OfflinePacket(Packet, ABC):
    # Magic bytes used to distinguish offline messages from loose garbage.
    magic: bytes = b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"

    def read_magic(self, __in: BinaryStream):
        self.magic = __in.read(16)

    def write_magic(self, __out: BinaryStream) -> None:
        __out.write(self.magic)

    def is_valid(self) -> bool:
        return self.magic == b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'


class OnlinePacket(Packet, ABC):
    pass
