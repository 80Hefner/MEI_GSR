import socket

from mibsec import MIBSec
from proxy_worker import ProxyWorker

server_socket = None
SERVER_IP = '10.0.1.20'
SERVER_PORT = 65432

def run_proxy():

    # Inicializar a MIBSec
    mib_sec = MIBSec()

    # Inicializar o servidor que irá comunicar com o manager
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()
    print('[PROXY SERVER] À escuta em {0}:{1} ..'.format(SERVER_IP, SERVER_PORT))

    try:
        while True:
            # Esperar que o manager se conecte
            client_socket, addr = server_socket.accept()
            print('[PROXY SERVER] Conexão aceite. {0}'.format(addr))

            # Criar thread responsável pela comunicação com o manager
            worker = ProxyWorker(client_socket, addr, mib_sec)
            worker.daemon = True
            worker.start()

    except KeyboardInterrupt:
        print('\n[PROXY SERVER] Servidor interrompido!')

if __name__ == '__main__':
    run_proxy()
