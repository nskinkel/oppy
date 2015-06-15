from oppy.cell.fixedlen import DestroyCell, EncryptedCell
from oppy.cell.relay import (
    RelayDataCell,
    RelayEndCell,
    RelayConnectedCell,
    RelaySendMeCell,
    RelayExtendedCell,
    RelayExtended2Cell,
    RelayTruncatedCell,
    RelayDropCell,
    RelayResolvedCell,
    RelayExtended2Cell,
)
from oppy.util.tools import enum


CIRCUIT_WINDOW_THRESHOLD_INIT = 1000
SENDME_THRESHOLD = 900
WINDOW_SIZE = 100


CState = enum(
    OPEN=0,
    BUFFERING=1,
)


CircuitType = enum(
    IPv4=0,
    IPv6=1,
)


BACKWARD_CELL_TYPES = (
    DestroyCell,
    EncryptedCell,
)


BACKWARD_RELAY_CELL_TYPES = (
    RelayDataCell,
    RelayEndCell,
    RelayConnectedCell,
    RelaySendMeCell,
    RelayExtendedCell,
    RelayExtended2Cell,
    RelayTruncatedCell,
    RelayDropCell,
    RelayResolvedCell,
    RelayExtended2Cell,
)


DEFAULT_OPEN_IPv4 = 4
DEFAULT_OPEN_IPv6 = 1


MAX_STREAMS_V3 = 65535
