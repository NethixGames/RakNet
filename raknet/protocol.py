import copy
from typing import Self

from .other import InternetAddress, MessageIdentifiers
from .packet import Packet, OnlinePacket, OfflinePacket, AcknowledgePacket, PacketSerializer
from .raknet import RakNet


class ACK(AcknowledgePacket):
    ID = 0xc0


class AdvertiseSystem(Packet):
    ID = MessageIdentifiers.ADVERTISE_SYSTEM

    response: str

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_string(self.response)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.response = __in.read_string()


class ConnectedPing(OnlinePacket):
    ID = MessageIdentifiers.CONNECTED_PING

    send_time: int

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        result = cls()
        result.send_time = kwargs['send_time']
        return result

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_long(self.send_time)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.send_time = __in.read_long()


class ConnectedPong(OnlinePacket):
    ID = MessageIdentifiers.CONNECTED_PONG

    send_time: int
    receive_time: int

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        result = cls()
        result.send_time = kwargs['send_time']
        result.receive_time = kwargs['receive_time']
        return result

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_long(self.send_time)
        __out.write_long(self.receive_time)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.send_time = __in.read_long()
        self.receive_time = __in.read_long()


class ConnectionRequest(OnlinePacket):
    ID = MessageIdentifiers.CONNECTION_REQUEST

    client_id: int
    send_time: int
    use_security: bool

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_long(self.client_id)
        __out.write_long(self.send_time)
        __out.write_bool(self.use_security)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.client_id = __in.read_long()
        self.send_time = __in.read_long()
        self.use_security = __in.read_bool()


class ConnectionRequestAccepted(OnlinePacket):
    ID = MessageIdentifiers.CONNECTION_REQUEST_ACCEPTED

    address: InternetAddress
    system_address: list[InternetAddress]
    send_time: int
    receive_time: int

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        result = cls()
        result.address = kwargs['address']
        result.system_address = kwargs['system_address']
        result.send_time = kwargs['send_time']
        result.receive_time = kwargs['receive_time']
        return result

    def __init__(self):
        self.system_address.append(InternetAddress('127.0.0.1', 0, 4))

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_address(self.address)
        __out.write_short(0)

        dummy = InternetAddress('0.0.0.0', 0, 4)
        for _ in range(RakNet.SYSTEM_ADDRESS_COUNT):
            __out.write_address(dummy)

        __out.write_long(self.send_time)
        __out.write_long(self.receive_time)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.address = __in.read_address()
        __in.read_short()  # TODO: Check this

        length = len(__in.buffer)
        dummy = InternetAddress('0.0.0.0', 0, 4)
        for i in range(RakNet.SYSTEM_ADDRESS_COUNT):
            self.system_address.append(__in.read_address() if (__in.offset + 16) < length else dummy)

        self.send_time = __in.read_long()
        self.receive_time = __in.read_long()


class DisconnectNotification(OnlinePacket):
    ID = MessageIdentifiers.DISCONNECT_NOTIFICATION

    def encode_payload(self, __out: PacketSerializer) -> None:
        pass

    def decode_payload(self, __in: PacketSerializer) -> None:
        pass


class IncompatibleProtocolVersion(OfflinePacket):
    ID = MessageIdentifiers.INCOMPATIBLE_PROTOCOL_VERSION

    protocol: int
    server_id: int

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        result = cls()
        result.protocol = kwargs['protocol']
        result.server_id = kwargs['server_id']
        return result

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_byte(self.protocol)
        self.write_magic(__out)
        __out.write_long(self.server_id)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.protocol = __in.read_byte()
        self.read_magic(__in)
        self.server_id = __in.read_long()


class NACK(AcknowledgePacket):
    ID = 0xa0


class NewIncomingConnection(OnlinePacket):
    ID = MessageIdentifiers.NEW_INCOMING_CONNECTION

    address: InternetAddress
    system_address: list[InternetAddress]
    send_time: int
    receive_time: int

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_address(self.address)
        for address in self.system_address:
            __out.write_address(address)

        __out.write_long(self.send_time)
        __out.write_long(self.receive_time)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.address = __in.read_address()

        end_offset = len(__in.buffer) - 16
        dummy = InternetAddress('0.0.0.0', 0, 4)
        for i in range(RakNet.SYSTEM_ADDRESS_COUNT):
            value = copy.copy(dummy) if (__in.offset >= end_offset) else __in.read_address()
            self.system_address.append(value)

        self.send_time = __in.read_long()
        self.receive_time = __in.read_long()


class OpenConnectionReplyOne(OfflinePacket):
    ID = MessageIdentifiers.OPEN_CONNECTION_REPLY_ONE

    server_id: int
    use_security: bool
    mtu_size: int

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        result = cls()
        result.server_id = kwargs['server_id']
        result.use_security = kwargs['use_security']
        result.mtu_size = kwargs['mtu_size']
        return result

    def encode_payload(self, __out: PacketSerializer) -> None:
        self.write_magic(__out)
        __out.write_long(self.server_id)
        __out.write_bool(self.use_security)
        __out.write_short(self.mtu_size)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.read_magic(__in)
        self.server_id = __in.read_long()
        self.use_security = __in.read_bool()
        self.mtu_size = __in.read_short()


class OpenConnectionReplyTwo(OfflinePacket):
    ID = MessageIdentifiers.OPEN_CONNECTION_REPLY_TWO

    server_id: int
    client_address: InternetAddress
    mtu_size: int
    use_security: bool

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        result = cls()
        result.server_id = kwargs['server_id']
        result.use_security = kwargs['use_security']
        result.mtu_size = kwargs['mtu_size']
        result.client_address = kwargs['client_address']
        return result

    def encode_payload(self, __out: PacketSerializer) -> None:
        self.write_magic(__out)
        __out.write_long(self.server_id)
        __out.write_address(self.client_address)
        __out.write_short(self.mtu_size)
        __out.write_bool(self.use_security)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.read_magic(__in)
        self.server_id = __in.read_long()
        self.client_address = __in.read_address()
        self.mtu_size = __in.read_short()
        self.use_security = __in.read_bool()


class OpenConnectionRequestOne(OfflinePacket):
    ID = MessageIdentifiers.OPEN_CONNECTION_REQUEST_ONE

    protocol: int = RakNet.DEFAULT_PROTOCOL_VERSION
    mtu_size: int

    def encode_payload(self, __out: PacketSerializer) -> None:
        self.write_magic(__out)
        __out.write_byte(self.protocol)

        length = self.mtu_size - 46
        __out.write(b'\x00' * length)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.read_magic(__in)
        self.protocol = __in.read_short()
        self.mtu_size = len(__in.read(len(__in.buffer) - __in.offset)) + 46


class OpenConnectionRequestTwo(OfflinePacket):
    ID = MessageIdentifiers.OPEN_CONNECTION_REQUEST_TWO

    client_id: int
    server_address: InternetAddress
    mtu_size: int

    def encode_payload(self, __out: PacketSerializer) -> None:
        self.write_magic(__out)
        __out.write_address(self.server_address)
        __out.write_short(self.mtu_size)
        __out.write_long(self.client_id)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.read_magic(__in)
        self.server_address = __in.read_address()
        self.mtu_size = __in.read_short()
        self.client_id = __in.read_long()


class UnconnectedPing(OfflinePacket):
    ID = MessageIdentifiers.UNCONNECTED_PING

    send_time: int
    client_id: int

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_long(self.send_time)
        self.write_magic(__out)
        __out.write_byte(self.client_id)
        pass

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.send_time = __in.read_long()
        self.read_magic(__in)
        self.client_id = __in.read_short()
        pass


class UnconnectedPingOpenConnections(UnconnectedPing):
    ID: MessageIdentifiers.UNCONNECTED_PING_OPEN_CONNECTIONS


class UnconnectedPong(OfflinePacket):
    ID = MessageIdentifiers.UNCONNECTED_PONG

    send_time: int
    server_id: int
    response: str

    @classmethod
    def create(cls, *args, **kwargs) -> Self:
        instance = cls()
        instance.send_time = kwargs['send_time']
        instance.server_id = kwargs['server_id']
        instance.response = kwargs['response']
        return instance

    def encode_payload(self, __out: PacketSerializer) -> None:
        __out.write_long(self.send_time)
        __out.write_long(self.server_id)
        self.write_magic(__out)
        __out.write_string(self.response)

    def decode_payload(self, __in: PacketSerializer) -> None:
        self.send_time = __in.read_long()
        self.server_id = __in.read_long()
        self.read_magic(__in)
        self.response = __in.read_string()
