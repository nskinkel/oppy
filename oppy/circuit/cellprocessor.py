# Copyright 2014, 2015, Nik Kinkel
# See LICENSE for licensing information

import logging

from oppy.cell.definitions import (
    DESTROY_CMD,
    RELAY_CMD,
    RELAY_DATA_CMD,
    RELAY_END_CMD,
    RELAY_CONNECTED_CMD,
    RELAY_SENDME_CMD,
    RELAY_TRUNCATED_CMD,
    RELAY_DROP_CMD,
    RELAY_RESOLVED_CMD,
    REASON_DONE,
)


def _processDestroyCell(circuit, cell):
    logging.debug("Circuit {} received a DestroyCell with reason {}. "
                  "Tearing down circuit.".format(cell.reason, circuit.id))
    circuit.closeCircuit()


def _processRelayDataCell(circuit, cell):
    sid = cell.rheader.stream_id
    try:
        circuit.streamhandler.streams[sid].recv(cell.rpayload)
        circuit.flowcontrol.dataReceived()
    except KeyError:
        logging.debug("Circuit {} received a cell for non existent stream "
                      "{}. Dropping cell.".format(circuit.id, sid))


def _processRelayEndCell(circuit, cell):
    sid = cell.rheader.stream_id
    try:
        circuit.streamhandler.streams[sid].closeFromCircuit()
        if cell.reason != REASON_DONE:
            logging.debug("Circuit {} received a RelayEndCell for stream "
                          "{}, and reason was not REASON_DONE. Reason: {}."
                          .format(circuit.id, sid, cell.reason))
    except KeyError:
        logging.debug("Circuit {} received a RelayEndCell for non existent"
                      " stream {}.".format(circuit.id, sid))


def _processRelayConnectedCell(circuit, cell):
    sid = cell.rheader.stream_id
    try:
        circuit.streamhandler.streams[sid].streamConnected()
        logging.debug("Circuit {} received a RelayConnectedCell for stream {}"
                      .format(circuit.id, sid))
    except KeyError:
        logging.debug("Circuit {} received a RelayConnectedCell for "
                      "nonexistent stream {}. Dropping cell."
                      .format(circuit.id, sid))


def _processRelaySendMeCell(circuit, cell):
    sid = cell.rheader.stream_id
    if sid == 0:
        circuit.flowcontrol.sendMeCellReceived()
    else:
        try:
            circuit.streamhandler.streams[sid].incrementPackageWindow()
        except KeyError:
            logging.debug("Circuit {} received a RelaySendMe cell on "
                          "nonexistentstream {}. Dropping cell."
                          .format(circuit.id, sid))


def _processRelayTruncatedCell(circuit, cell):
    logging.debug("Circuit {} received a RelayTruncatedCell. oppy can't "
                  "rebuild or cannabalize circuits yet, so the circuit "
                  "will be destroyed.".format(circuit.id))
    circuit.sendDestroyCell()
    circuit.closeCircuit()


def _processRelayDropCell(circuit, cell):
    logging.debug("Circuit {} received a RelayDropCell.".format(circuit.id))


def _processRelayResolvedCell(circuit, cell):
    logging.debug("Circuit {} received a RelayResolvedCell for stream {}."
                  .format(circuit.id, cell.rheader.stream_id))


class CellProcessor(object):

    _processingMap = {
        DESTROY_CMD: _processDestroyCell,
        RELAY_DATA_CMD: _processRelayDataCell,
        RELAY_END_CMD: _processRelayEndCell,
        RELAY_CONNECTED_CMD: _processRelayConnectedCell,
        RELAY_SENDME_CMD: _processRelaySendMeCell,
        RELAY_TRUNCATED_CMD: _processRelayTruncatedCell,
        RELAY_DROP_CMD: _processRelayDropCell,
        RELAY_RESOLVED_CMD: _processRelayResolvedCell,
    }

    slots = ('circuit')

    def __init__(self, circuit):
        self.circuit = circuit

    def processCell(self, cell):
        try:
            if cell.header.cmd == RELAY_CMD:
                CellProcessor._processingMap[cell.rheader.cmd](self.circuit, cell)
            else:
                CellProcessor._processingMap[cell.header.cmd](self.circuit, cell)
        except KeyError:
            msg = ("Circuit {} received a {} cell that violates the Tor "
                   "protocol. Destroying circuit."
                   .format(self.circuit.id, type(cell)))
            logging.warning(msg)
            self.circuit.sendDestroyCell()
            self.circuit.closeCircuit()
