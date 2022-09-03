import socket
import encryption
from ctt import CTT, Packet

class Manager:

    def __init__(self):
        self.PROXY_IP = '10.0.1.20'
        self.PROXY_PORT = 65432
        self.socket = None
        #TODO guardar mais informação nas operations
        self.operations = []
        self.shared_cipher_key = None
        self.shared_hmac_key = None
    
    # Apresenta o menu e recebe o input do manager
    def menu(self):
        
        option = -1

        while option < 0 or option > 3:
            print()
            print('┌───┬────────────────────────────┐')
            print('│ 1 │ Obter resultados           │')
            print('│ 2 │ Get request                │')
            print('│ 3 │ Getnext request            │')
            # print('├───┼────────────────────────────┤')
            print('│ 0 │ Sair                       │')
            print('└───┴────────────────────────────┘')

            try:
                option = int(input('Insira a sua opção: '))
            except ValueError:
                option = -1
        
        return option
    
    # Processa o pedido do manager para obter os resultados dos requests anteriores
    def process_get_results(self):

        # Obter input do manager, até ser inserido um número inteiro
        while True:
            try:
                operation_id = int(input('Insira o ID da operação a consultar: '))
                break
            except ValueError:
                print('[ERROR] Input inválido. Insira um número inteiro.')
        
        # Enviar pedido para o proxy
        request = Packet(Packet.MANAGER_RESPONSE, operation_id)
        CTT.send_msg(request, self.socket, self.shared_cipher_key, self.shared_hmac_key)

        # Esperar pela resposta do proxy
        response = CTT.recv_msg(self.socket, self.shared_cipher_key, self.shared_hmac_key)

        if response.type == Packet.PROXY_RESPONSE_FAIL:
            print(f'[ERROR] {response.data}')
        elif response.type == Packet.PROXY_RESPONSE:
            operation_entry = response.data
            print(str(operation_entry))

    # Processa o pedido do manager para executar um get request
    def process_get_request(self):
        
        # Obter input do manager
        target_ip = input('Insira IP do agent: ')
        oids = input('Insira os oids (separados por espaços): ').split(' ')
        community_string = input('Insira a community string: ')

        # Enviar pedido para o proxy
        request = Packet(Packet.MANAGER_GET_REQUEST, { 'target_ip': target_ip, 'oids': oids, 'community_string': community_string })
        CTT.send_msg(request, self.socket, self.shared_cipher_key, self.shared_hmac_key)

        # Esperar pelos ACKs vindos do proxy, que indicam o ID de cada operação executada
        for _ in range(len(oids)):
            ack = CTT.recv_msg(self.socket, self.shared_cipher_key, self.shared_hmac_key)
            if (ack.type == Packet.PROXY_REQUEST_ACK):
                self.operations.append(ack.data)
                print(f'Recebido ACK da operação com ID: {ack.data}')


    # Processa o pedido do manager para executar um getnext request
    def process_get_next_request(self):

        # Obter input do manager
        target_ip = input('Insira IP do agent: ')
        oids = input('Insira os oids (separados por espaços): ').split(' ')
        community_string = input('Insira a community string: ')

        # Enviar pedido para o proxy
        request = Packet(Packet.MANAGER_GETNEXT_REQUEST, { 'target_ip': target_ip, 'oids': oids, 'community_string': community_string })
        CTT.send_msg(request, self.socket, self.shared_cipher_key, self.shared_hmac_key)

        # Esperar pelos ACKs vindos do proxy, que indicam o ID de cada operação executada
        for _ in range(len(oids)):
            ack = CTT.recv_msg(self.socket, self.shared_cipher_key, self.shared_hmac_key)
            if (ack.type == Packet.PROXY_REQUEST_ACK):
                self.operations.append(ack.data)
                print(f'Recebido ACK da operação com ID: {ack.data}')

    # Processa o pedido do manager para se desconectar do proxy
    def process_disconnect(self):
        request = Packet(Packet.MANAGER_DISCONNECT)
        CTT.send_msg(request, self.socket, self.shared_cipher_key, self.shared_hmac_key)
        
        self.socket.close()


    # Execução do manager
    def run(self):

        try:
            # Estabelecer conexão com o proxy
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.PROXY_IP, self.PROXY_PORT))

            # Troca de chaves Diffie-Hellman com o proxy
            self.shared_cipher_key = encryption.dh_key_exchange(self.socket)
            self.shared_hmac_key = encryption.dh_key_exchange(self.socket)

            # Menu principal
            while True:
                option = self.menu()

                if option == 1:
                    self.process_get_results()
                elif option == 2:
                    self.process_get_request()
                elif option == 3:
                    self.process_get_next_request()
                elif option == 0:
                    self.process_disconnect()
                    break

        except KeyboardInterrupt:
            print('\nExecução interrompida.')
        
        except ConnectionRefusedError:
            print('[ERROR] Proxy indisponível.')

manager = Manager()
manager.run()
