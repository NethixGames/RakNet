from typing import Final

__all__ = [
    "RakNet"
]


class RakNet(Final):
    # Default vanilla RakNet protocol version that this library implements. Things using RakNet can override this
    # protocol version with something different.
    DEFAULT_PROTOCOL_VERSION = 6

    # Regular RakNet uses 10 by default. MCPE uses 20. Configure this value as appropriate.
    SYSTEM_ADDRESS_COUNT = 20
