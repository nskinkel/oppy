import logging

from oppy.circuit.definitions import CState

# TODO: make this an abc
class FlowControlManager(object):
    
    def dataReceived(self):
        # this calls incDeliverwindow on it's own
        self._decDeliverWindow()

    def dataSent(self):
        self._decPackageWindow()

    def sendMeCellReceived(self):
        self._incPackageWindow()

    def _incPackageWindow(self):
        pass

    def _decPackageWindow(self):
        pass

    def _incDeliverWindow(self):
        pass

    def _decDeliverWindow(self):
        pass


CIRCUIT_WINDOW_START = 1000
CIRCUIT_SENDME_THRESHOLD = 900
CIRCUIT_BLOCK_SIZE = 100


# TODO: check states are correct when methods are called for consistency
# TODO: set can_read and can_write to manage read/write state
class CircuitFlowControlManager(FlowControlManager):
    
    def __init__(self, circuit):
        self._package_window = CIRCUIT_WINDOW_START
        self._deliver_window = CIRCUIT_WINDOW_START
        self.circuit = circuit

    def _incPackageWindow(self):
        self._package_window += CIRCUIT_BLOCK_SIZE
        logging.debug("Circuit {} received a circuit-level RelaySendMeCell. "
                      "Its packaging window is now: {}."
                      .format(self.circuit.id, self._package_window))

        if self.circuit.state.state == CState.BUFFERING\
            and self._package_window > 0:

            self.circuit.setStateOpen()

    def _decPackageWindow(self):
        self._package_window -= 1
        if self._package_window == 0:
            logging.debug("Circuit {}'s packaging window fell to 0."
                          .format(self.circuit.id))
            self.circuit.setStateBuffering()

    def _decDeliverWindow(self):
        self._deliver_window -= 1
        if self._deliver_window < CIRCUIT_SENDME_THRESHOLD:
            logging.debug("Circuit {}'s deliver window fell below {}."
                          .format(self.circuit.id, CIRCUIT_SENDME_THRESHOLD))
            self.circuit.sendCircuitSendMe()
            self._incDeliverWindow()

    def _incDeliverWindow(self):
        self._deliver_window += CIRCUIT_BLOCK_SIZE


STREAM_WINDOW_START = 500
STREAM_SENDME_THRESHOLD = 450
STREAM_BLOCK_SIZE = 50


def StreamFlowControlManager(FlowControlManager):

    def __init__(self, stream):
        self.stream = stream
        self._package_window = STREAM_WINDOW_START
        self._deliver_window = STREAM_WINDOW_START

    def _incPackageWindow(self):
        pass

    def _decPackageWindow(self):
        pass

    def _incDeliverWindow(self):
        pass

    def _decDeliverWindow(self):
        pass
