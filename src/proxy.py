import socket
from pysnmp import hlapi
from mibsec import MIBSec
from proxy_worker import ProxyWorker

class Proxy:

    def __init__(self):
        self.server_socket = None
        self.SERVER_IP = '10.0.1.20'
        self.SERVER_PORT = 65432
    
    def run(self):

        # Inicializar a MIBSec
        mib_sec = MIBSec()

        # Inicializar o servidor que irá comunicar com o manager
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.SERVER_IP, self.SERVER_PORT))
        self.server_socket.listen()
        print('[PROXY SERVER] À escuta em {0}:{1} ..'.format(self.SERVER_IP, self.SERVER_PORT))

        try:
            while True:
                # Esperar que o manager se conecte
                client_socket, addr = self.server_socket.accept()
                print('[PROXY SERVER] Conexão aceite. {0}'.format(addr))

                # Criar thread responsável pela comunicação com o manager
                worker = ProxyWorker(client_socket, addr, mib_sec)
                worker.daemon = True
                worker.start()

        except KeyboardInterrupt:
            print('\n[PROXY SERVER] Servidor interrompido!')

proxy = Proxy()
proxy.run()
