import pickle
import socket
from enum import Enum
from typing import Any

import encryption

class Packet_Type(Enum):
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

class Packet:
    def __init__(self, type: Packet_Type, data: Any = None):
        self.type = type
        self.data = data

class CTT:

    HEADER_SIZE = 8
    HMAC_SIZE = 32  # HMAC SHA256
    BUFFER_SIZE = 1024

    def __init__(self, socket: socket.socket, cipher_key: bytes = None, hmac_key: bytes = None):
        self.socket = socket
        self.cipher_key = cipher_key
        self.hmac_key = hmac_key
    
    # Envia a mensagem através do socket, anexando-lhe um cabeçalho que indica o seu tamanho
    # Opcionalmente pode cifrar e autenticar a mensagem
    def send_msg(self, msg: Any, encrypted: bool = True):
        
        # Cifrar mensagem, caso a opção 'encrypted' seja selecionada
        if encrypted:
            msg = encryption.encrypt(msg, self.cipher_key, self.hmac_key)

        # Transformar mensagem num array de bytes
        msg_bytes = CTT.serialize(msg)

        # Calcular tamanho do array de bytes a ser enviado
        msg_len = len(msg_bytes)
        if encrypted:
            msg_len += CTT.HMAC_SIZE
        header = msg_len.to_bytes(CTT.HEADER_SIZE, 'big')

        # Autenticar o cabeçalho e a mensagem, caso a opção 'encrypted' seja selecionada
        if encrypted:
            header = header + encryption.generate_HMAC(header, self.hmac_key)
            msg_bytes = msg_bytes + encryption.generate_HMAC(msg_bytes, self.hmac_key)
        
        # Enviar o cabeçalho
        self.socket.sendall(header)

        # Enviar mensagem
        self.socket.sendall(msg_bytes)
        
    # Recebe uma mensagem através do socket
    # Opcionalmente pode decifrar e verificar a autenticação da mensagem
    def recv_msg(self, encrypted: bool = True):
        
        # Receber cabeçalho que indica o tamanho da mensagem a receber
        # Verificar autenticação do cabeçalho, caso a opção 'encrypted' seja selecionada
        if encrypted:
            full_header = self.socket.recv(CTT.HEADER_SIZE + CTT.HMAC_SIZE)
            header = full_header[:CTT.HEADER_SIZE]
            header_hmac = full_header[CTT.HEADER_SIZE:]

            if encryption.generate_HMAC(header, self.hmac_key) != header_hmac:
                raise encryption.HMACAuthenticationFailedException('HMAC Authentication failed when verifying message header.')
        else:
            header = self.socket.recv(CTT.HEADER_SIZE)
        
        full_msg_len = int.from_bytes(header, 'big')

        # Ler do socket enquanto a mensagem não foi totalmente recebida
        recv_bytes = 0
        full_msg = b''
        while recv_bytes < full_msg_len:
            bytes_left = full_msg_len - recv_bytes
            if (bytes_left < CTT.BUFFER_SIZE):
                buffer = self.socket.recv(bytes_left)
                recv_bytes += bytes_left
            else:
                buffer = self.socket.recv(CTT.BUFFER_SIZE)
                recv_bytes += CTT.BUFFER_SIZE

            full_msg += buffer

        # Verificar autenticação da mensagem e decifrá-la, caso a opção 'encrypted' seja selecionada
        if encrypted:
            msg = full_msg[:-CTT.HMAC_SIZE]
            msg_hmac = full_msg[-CTT.HMAC_SIZE:]

            if encryption.generate_HMAC(msg, self.hmac_key) != msg_hmac:
                raise encryption.HMACAuthenticationFailedException('HMAC Authentication failed when verifying message.')

            msg = CTT.deserialize(msg)
            msg = encryption.decrypt(msg, self.cipher_key, self.hmac_key)
        # Desserializar a mensagem
        else:
            msg = CTT.deserialize(full_msg)

        return msg

    # Transforma um objeto num array de bytes
    @staticmethod
    def serialize(object: Any):
        return pickle.dumps(object)
    
    # Transforma um array de bytes num objeto
    @staticmethod
    def deserialize(object_bytes: bytes):
        return pickle.loads(object_bytes)
