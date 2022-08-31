from threading import Thread
from ctt import CTT
from snmp_requester import SnmpRequester

class ProxyWorker(Thread):

    def __init__(self, socket, addr):
        self.socket = socket
        self.addr = addr

        Thread.__init__(self)

    def run(self):
        pass
