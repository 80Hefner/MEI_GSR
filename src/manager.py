import socket

import encryption
from ctt import CTT, Packet, Packet_Type

PROXY_IP = '10.0.1.20'
PROXY_PORT = 65432
ctt = CTT(None)

# Apresenta o menu e recebe o input do manager
def menu():
    
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
def process_get_results():

    # Obter input do manager, até ser inserido um número inteiro
    while True:
        try:
            operation_id = int(input('Insira o ID da operação a consultar: '))
            break
        except ValueError:
            print('[ERROR] Input inválido. Insira um número inteiro.')
    
    # Enviar pedido para o proxy
    request = Packet(Packet_Type.MANAGER_RESPONSE, operation_id)
    ctt.send_msg(request)

    # Esperar pela resposta do proxy
    response = ctt.recv_msg()

    if response.type == Packet_Type.PROXY_RESPONSE_FAIL:
        print(f'[ERROR] {response.data}')
    elif response.type == Packet_Type.PROXY_RESPONSE:
        operation_entry = response.data
        print(str(operation_entry))

# Processa o pedido do manager para executar um get request
def process_get_request():
    
    # Obter input do manager
    target_ip = input('Insira IP do agent: ')
    oids = input('Insira os oids (separados por espaços): ').split(' ')
    community_string = input('Insira a community string: ')

    # Enviar pedido para o proxy
    request = Packet(Packet_Type.MANAGER_GET_REQUEST, { 'target_ip': target_ip, 'oids': oids, 'community_string': community_string })
    ctt.send_msg(request)

    # Esperar pelos ACKs vindos do proxy, que indicam o ID de cada operação executada
    for _ in range(len(oids)):
        ack = ctt.recv_msg()
        if (ack.type == Packet_Type.PROXY_REQUEST_ACK):
            print(f'Recebido ACK da operação com ID: {ack.data}')

# Processa o pedido do manager para executar um getnext request
def process_get_next_request():

    # Obter input do manager
    target_ip = input('Insira IP do agent: ')
    oids = input('Insira os oids (separados por espaços): ').split(' ')
    community_string = input('Insira a community string: ')

    # Enviar pedido para o proxy
    request = Packet(Packet_Type.MANAGER_GETNEXT_REQUEST, { 'target_ip': target_ip, 'oids': oids, 'community_string': community_string })
    ctt.send_msg(request)

    # Esperar pelos ACKs vindos do proxy, que indicam o ID de cada operação executada
    for _ in range(len(oids)):
        ack = ctt.recv_msg()
        if (ack.type == Packet_Type.PROXY_REQUEST_ACK):
            print(f'Recebido ACK da operação com ID: {ack.data}')

# Processa o pedido do manager para se desconectar do proxy
def process_disconnect():
    request = Packet(Packet_Type.MANAGER_DISCONNECT)
    ctt.send_msg(request)
    
    ctt.socket.close()


# Execução do manager
def run_manager():

    try:
        # Estabelecer conexão com o proxy
        ctt.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctt.socket.connect((PROXY_IP, PROXY_PORT))

        # Troca de chaves Diffie-Hellman com o proxy
        ctt.shared_key = encryption.dh_key_exchange(ctt)

        # Menu principal
        while True:
            option = menu()

            if option == 1:
                process_get_results()
            elif option == 2:
                process_get_request()
            elif option == 3:
                process_get_next_request()
            elif option == 0:
                process_disconnect()
                break

    except KeyboardInterrupt:
        print('\nExecução interrompida.')
    
    except ConnectionRefusedError:
        print('[ERROR] Proxy indisponível.')

if __name__ == '__main__':
    run_manager()
