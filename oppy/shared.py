# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import oppy.netstatus.netstatus as ns
net_status = ns.NetStatus()

from oppy.connection.connectionpool import ConnectionPool
connection_pool = ConnectionPool()

from oppy.circuit.circuitmanager import CircuitManager
circuit_manager = CircuitManager()
