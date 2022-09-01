import socket
import pickle

class ProxyResponse:

    REQUEST_ACK = 1
    REQUEST_RESULT = 2
    REQUEST_RESULT_FAIL = 3

    def __init__(self, type, data):
        self.type = type
        self.data = data

class ManagerRequest:

    RESPONSE = 1
    GET_REQUEST = 2
    GETNEXT_REQUEST = 3
    DISCONNECT = 0

    def __init__(self, type, target_ip = '', oids = [], community_string = '', operation_id = 0):
        self.type = type
        self.target_ip = target_ip
        self.oids = oids
        self.community_string = community_string
        self.operation_id = operation_id

class CTT:
    
    HEADER_SIZE = 8
    BUFFER_SIZE = 1024
    
    # Envia a mensagem através do socket, anexando-lhe um cabeçalho que indica o seu tamanho
    def send_msg(msg, socket):
        # Transformar mensagem num array de bytes
        msg_bytes = CTT.serialize(msg)

        # Calcular tamanho do array de bytes
        msg_len = len(msg_bytes)
        header = msg_len.to_bytes(CTT.HEADER_SIZE, 'big')

        # Enviar cabeçalho + array de bytes contendo a mensagem
        socket.sendall(header + msg_bytes)
    
    # Recebe uma mensagem através do socket
    def recv_msg(socket):
        # Receber cabeçalho que indica o tamanho da mensagem a receber
        header = socket.recv(CTT.HEADER_SIZE)
        msg_len = int.from_bytes(header, 'big')

        # Ler do socket enquanto a mensagem não foi totalmente recebida
        recv_bytes = 0
        msg = b''
        while recv_bytes < msg_len:
            bytes_left = msg_len - recv_bytes
            if (bytes_left < CTT.BUFFER_SIZE):
                buffer = socket.recv(bytes_left)
                recv_bytes += bytes_left
            else:
                buffer = socket.recv(CTT.BUFFER_SIZE)
                recv_bytes += CTT.BUFFER_SIZE

            msg += buffer
        
        # Retornar a mensagem desserializada
        return CTT.deserialize(msg)

    # Transforma um objeto num array de bytes
    def serialize(object):
        return pickle.dumps(object)
    
    # Transforma um array de bytes num objeto
    def deserialize(object_bytes):
        return pickle.loads(object_bytes)
