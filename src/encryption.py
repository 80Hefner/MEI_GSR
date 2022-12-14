import secrets
from typing import Any, Dict
from pickle import dumps, loads
from cryptography.hazmat.primitives import hmac, hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ctt import CTT

# Exceção lançada quando a autenticação HMAC de uma mensagem falha
class HMACAuthenticationFailedException(Exception):
    pass

# RFC 3526 - Group 14
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
dh_params_numbers = dh.DHParameterNumbers(p,g)
dh_parameters = dh_params_numbers.parameters()

# Gera o valor de autenticação de uma mensagem, através duma chave de autenticação
def generate_HMAC(message: Any, hmac_key: bytes):

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(dumps(message))

    return h.finalize()

# Cifra e autentica um objeto, através da chave de cifragem
def encrypt(plain_object: Any, key: bytes):

    # Gerar um vetor de inicialização aleatório
    iv = secrets.token_bytes(12)

    # Criar um Cipher AES-GCM a chave de cifragem e o vetor de inicialização gerado
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

    # Cifrar o objeto
    cipher_object = encryptor.update(dumps(plain_object)) + encryptor.finalize()

    # Mensagem a ser enviada
    message = { 'iv': iv, 'tag': encryptor.tag, 'cipher_object': cipher_object }

    return message

# Decifra uma mensagem, através da chave de cifragem
def decrypt(message: Dict[str, Any], key: bytes):
    
    # Parsing da mensagem recebida
    iv = message['iv']
    tag = message['tag']
    cipher_object = message['cipher_object']

    # Criar um Cipher AES-GCM a chave de cifragem, o nounce e a tag
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()

    # Obter objeto original
    object_bytes = decryptor.update(cipher_object) + decryptor.finalize()

    return loads(object_bytes)

# Executa a troca de chaves Diffie-Hellman entre o proxy e um manager
def dh_key_exchange(ctt: CTT):

    # Gerar chave privada
    private_key = dh_parameters.generate_private_key()

    # Enviar e receber as chaves públicas
    ctt.send_msg(private_key.public_key().public_bytes(encoding= serialization.Encoding.PEM,
                                                       format= serialization.PublicFormat.SubjectPublicKeyInfo),
                 encrypted= False)
    received_public_key = load_pem_public_key(ctt.recv_msg(encrypted= False))

    # Gerar chave partilhada
    key = private_key.exchange(received_public_key)
    shared_key = HKDF(algorithm=hashes.SHA256(), length=32,
                        salt=None, info=b'handshake data').derive(key)
    
    return shared_key
