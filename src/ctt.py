import pickle
import encryption

class Packet:

    MANAGER_RESPONSE        = 11   # data: Operation ID -> int
    MANAGER_GET_REQUEST     = 12   # data: { 'target_ip': String
                                   #         'oids': [String]
                                   #         'community_string': String }
    MANAGER_GETNEXT_REQUEST = 13   # data: { 'target_ip': String
                                   #         'oids': [String]
                                   #         'community_string': String }
    MANAGER_DISCONNECT      = 14   # data: None

    PROXY_REQUEST_ACK       = 21   # data: Operation ID -> int
    PROXY_RESPONSE          = 22   # data: Result -> OperationEntryValue
    PROXY_RESPONSE_FAIL     = 23   # data: Error Message -> String

    def __init__(self, type, data=None):
        self.type = type
        self.data = data

class CTT:

    # TODO tornar possível instanciar esta classe e guardar o socket e as keys nela
    
    HEADER_SIZE = 8
    AUTENTICATED_HEADER_SIZE = 40  # 8 + 32  ->  HEADER + HMAC SHA256
    BUFFER_SIZE = 1024
    
    # Envia a mensagem através do socket, anexando-lhe um cabeçalho que indica o seu tamanho
    # Opcionalmente pode cifrar e autenticar a mensagem
    def send_msg(msg, socket, cipher_key=None, hmac_key=None, encrypted=True):
        
        # Cifrar mensagem, caso a opção 'encrypted' seja selecionada
        if encrypted:
            msg = encryption.encrypt(msg, cipher_key, hmac_key)

        # Transformar mensagem num array de bytes
        msg_bytes = CTT.serialize(msg)

        # Calcular tamanho do array de bytes
        msg_len = len(msg_bytes)
        header = msg_len.to_bytes(CTT.HEADER_SIZE, 'big')

        # Autenticar o cabeçalho, caso a opção 'encrypted' seja selecionada
        if encrypted:
            header = header + encryption.generate_HMAC(header, hmac_key)
        
        # Enviar o cabeçalho
        socket.sendall(header)

        # Enviar mensagem
        socket.sendall(msg_bytes)
        
    # Recebe uma mensagem através do socket
    # Opcionalmente pode decifrar e verificar a autenticação da mensagem
    def recv_msg(socket, cipher_key=None, hmac_key=None, encrypted=True):
        
        # Receber cabeçalho que indica o tamanho da mensagem a receber
        # Verificar autenticação do cabeçalho, caso a opção 'encrypted' seja selecionada
        if encrypted:
            full_header = socket.recv(CTT.AUTENTICATED_HEADER_SIZE)
            header = full_header[:8]
            header_hmac = full_header[8:]

            if encryption.generate_HMAC(header, hmac_key) != header_hmac:
                raise encryption.HMACAuthenticationFailed('HMAC Authentication failed when verifying message header.')
        else:
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

        # Desserializar a mensagem
        msg = CTT.deserialize(msg)
        
        # Decifrar mensagem, caso a opção 'encrypted' seja selecionada
        if encrypted:
            msg = encryption.decrypt(msg, cipher_key, hmac_key)

        return msg

    # Transforma um objeto num array de bytes
    def serialize(object):
        return pickle.dumps(object)
    
    # Transforma um array de bytes num objeto
    def deserialize(object_bytes):
        return pickle.loads(object_bytes)
