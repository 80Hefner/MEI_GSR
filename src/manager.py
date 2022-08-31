import socket
from ctt import CTT

class Manager:

    def __init__(self):
        self.SERVER_IP = '10.0.1.20'
        self.SERVER_PORT = 65432
        self.socket = None
    
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
    
    # Processa o pedido do manager para obter os resultados dos rerquests anteriores
    def process_get_results(self):
        print('GET RESULTS') #TODO

    # Processa o pedido do manager para executar um get request
    def process_get_request(self):
        print('GET REQUEST') #TODO

    # Processa o pedido do manager para executar um getnext request
    def process_get_next_request(self):
        print('GET NEXT REQUEST') #TODO

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
                    break

        except KeyboardInterrupt:
            print('\nExecução interrompida.')

manager = Manager()
manager.run()
