import socket
from ctt import CTT, ManagerRequest, ProxyResponse
from mibsec import OperationEntryValue

class Manager:

    def __init__(self):
        self.SERVER_IP = '10.0.1.20'
        self.SERVER_PORT = 65432
        self.socket = None
        #TODO guardar mais informação nas operations
        self.operations = []
    
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
        request = ManagerRequest(type= ManagerRequest.RESPONSE,
                                 operation_id= operation_id)
        CTT.send_msg(request, self.socket)

        # Esperar pela resposta do proxy
        response = CTT.recv_msg(self.socket)

        if response.type == ProxyResponse.REQUEST_RESULT_FAIL:
            print(f'[ERROR] {response.data}')
        elif response.type == ProxyResponse.REQUEST_RESULT:
            operation_entry = response.data
            print(str(operation_entry))


    # Processa o pedido do manager para executar um get request
    def process_get_request(self):
        
        # Obter input do manager
        target_ip = input('Insira IP do agent: ')
        oids = input('Insira os oids (separados por espaços): ').split(' ')
        community_string = input('Insira a community string: ')

        # Enviar pedido para o proxy
        request = ManagerRequest(type= ManagerRequest.GET_REQUEST,
                                 target_ip= target_ip,
                                 oids= oids,
                                 community_string= community_string)
        CTT.send_msg(request, self.socket)

        # Esperar pelos ACKs vindos do proxy, que indicam o ID de cada operação executada
        for _ in range(len(oids)):
            ack = CTT.recv_msg(self.socket)
            if (ack.type == ProxyResponse.REQUEST_ACK):
                self.operations.append(ack.data)
                print(f'Recebido ACK da operação com ID: {ack.data}')


    # Processa o pedido do manager para executar um getnext request
    def process_get_next_request(self):

        # Obter input do manager
        target_ip = input('Insira IP do agent: ')
        oids = input('Insira os oids (separados por espaços): ').split(' ')
        community_string = input('Insira a community string: ')

        # Enviar pedido para o proxy
        request = ManagerRequest(type= ManagerRequest.GETNEXT_REQUEST,
                                 target_ip= target_ip,
                                 oids= oids,
                                 community_string= community_string)
        CTT.send_msg(request, self.socket)

        # Esperar pelos ACKs vindos do proxy, que indicam o ID de cada operação executada
        for _ in range(len(oids)):
            ack = CTT.recv_msg(self.socket)
            if (ack.type == ProxyResponse.REQUEST_ACK):
                self.operations.append(ack.data)
                print(f'Recebido ACK da operação com ID: {ack.data}')

    # Processa o pedido do manager para se desconectar do proxy
    def process_disconnect(self):
        request = ManagerRequest(type= ManagerRequest.DISCONNECT)
        CTT.send_msg(request, self.socket)
        
        self.socket.close()


    # Execução do manager
    def run(self):

        try:
            # Estabelecer conexão com o proxy
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.SERVER_IP, self.SERVER_PORT))

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
