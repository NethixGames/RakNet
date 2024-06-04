from typing import Final, Self

__all__ = [
    'InternetAddress',
    'ProtocolAcceptor',
    'DisconnectReason',
    'MessageIdentifiers'
]


class InternetAddress(Final):
    def __init__(self, ip: str, port: int, version: int):
        self.ip = ip
        self.port = port
        self.version = version

    def __eq__(self, other: Self) -> bool:
        return self.ip == other.ip and self.port == other.port and self.version == other.version

    def __str__(self) -> str:
        return f'{self.ip} {self.port}'


class ProtocolAcceptor(Final):
    def __init__(self, version: int):
        self.version = version

    def accepts(self, version: int) -> bool:
        return version == self.version


class DisconnectReason(Final):
    CLIENT_DISCONNECT = 0x00
    SERVER_DISCONNECT = 0x01
    PEER_TIMEOUT = 0x02
    CLIENT_RECONNECT = 0x03
    SERVER_SHUTDOWN = 0x04  # TODO: do we really need a separate reason for this in addition to SERVER_DISCONNECT?
    SPLIT_PACKET_TOO_LARGE = 0x05
    SPLIT_PACKET_TOO_MANY_CONCURRENT = 0x06
    SPLIT_PACKET_INVALID_PART_INDEX = 0x07
    SPLIT_PACKET_INCONSISTENT_HEADER = 0x08

    @staticmethod
    def to_string(reason: int):
        return {
            DisconnectReason.CLIENT_DISCONNECT: "client disconnect",
            DisconnectReason.SERVER_DISCONNECT: "server disconnect",
            DisconnectReason.PEER_TIMEOUT: "timeout",
            DisconnectReason.CLIENT_RECONNECT: "new session established on same address and port",
            DisconnectReason.SERVER_SHUTDOWN: "server shutdown",
            DisconnectReason.SPLIT_PACKET_TOO_LARGE: "received packet split into more parts than allowed",
            DisconnectReason.SPLIT_PACKET_TOO_MANY_CONCURRENT: "too many received split packets being reassembled at once",
            DisconnectReason.SPLIT_PACKET_INVALID_PART_INDEX: "invalid split packet part index",
            DisconnectReason.SPLIT_PACKET_INCONSISTENT_HEADER: "received split packet header inconsistent with previous fragments",
        }.get(reason, f"Unknown reason {reason}")


class MessageIdentifiers:
    ###
    # RESERVED TYPES - DO NOT CHANGE THESE
    # All types from RakPeer
    ###

    # Ping from a connected system.  Update timestamps (internal use only)
    CONNECTED_PING = 0x00
    # Ping from an unconnected system.  Reply but do not update timestamps. (internal use only)
    UNCONNECTED_PING = 0x01
    # Ping from an unconnected system.  Only reply if we have open connections. Do not update timestamps. (internal use only)
    UNCONNECTED_PING_OPEN_CONNECTIONS = 0x02
    # Pong from a connected system.  Update timestamps (internal use only)
    CONNECTED_PONG = 0x03
    # C2S: Initial query: Header(1), OfflineMessageID(16), Protocol number(1), Pad(toMTU), sent with no fragment set.
    # If protocol fails on server, returns ID_INCOMPATIBLE_PROTOCOL_VERSION to client
    OPEN_CONNECTION_REQUEST_ONE = 0x05
    # S2C: Header(1), OfflineMessageID(16), server GUID(8), HasSecurity(1), Cookie(4, if HasSecurity),
    # public key (if do security is true), MTU(2). If public key fails on client, returns ID_PUBLIC_KEY_MISMATCH
    OPEN_CONNECTION_REPLY_ONE = 0x06
    # C2S: Header(1), OfflineMessageID(16), Cookie(4, if HasSecurity is true on the server), clientSupportsSecurity(1 bit),
    # handshakeChallenge (if has security on both server and client), remoteBindingAddress(6), MTU(2), client GUID(8)
    # Connection slot allocated if cookie is valid, server is not full, GUID and IP not already in use.
    OPEN_CONNECTION_REQUEST_TWO = 0x07
    # S2C: Header(1), OfflineMessageID(16), server GUID(8), mtu(2), doSecurity(1 bit), handshakeAnswer (if do security is true)
    OPEN_CONNECTION_REPLY_TWO = 0x08
    # C2S: Header(1), GUID(8), Timestamp, HasSecurity(1), Proof(32)
    CONNECTION_REQUEST = 0x09

    ###
    # USER TYPES - DO NOT CHANGE THESE
    ###

    # RakPeer - In a client/server environment, our connection request to the server has been accepted.
    CONNECTION_REQUEST_ACCEPTED = 0x10
    # RakPeer - A remote system has successfully connected.
    NEW_INCOMING_CONNECTION = 0x13
    # RakPeer - The system specified in Packet::systemAddress has disconnected from us.  For the client, this would mean the
    # server has shutdown.
    DISCONNECT_NOTIFICATION = 0x15
    # RAKNET_PROTOCOL_VERSION in RakNetVersion.h does not match on the remote system what we have on our system
    # This means the two systems cannot communicate.
    # The 2nd byte of the message contains the value of RAKNET_PROTOCOL_VERSION for the remote system
    INCOMPATIBLE_PROTOCOL_VERSION = 0x19
    # RakPeer - Pong from an unconnected system.  First byte is ID_UNCONNECTED_PONG, second sizeof(RakNet::TimeMS) bytes is the ping,
    # following bytes is system specific enumeration data.
    # Read using bitstreams
    UNCONNECTED_PONG = 0x1c
    # RakPeer - Inform a remote system of our IP/Port. On the recipient, all data past ID_ADVERTISE_SYSTEM is whatever was passed to
    # the data parameter
    ADVERTISE_SYSTEM = 0x1d
