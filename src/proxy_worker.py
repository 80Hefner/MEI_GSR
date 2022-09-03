import sys
import encryption
from threading import Thread, Lock
from ctt import CTT, Packet
from mibsec import MIBSec
from snmp_requester import SnmpRequester

class Counter:
    count = 0
    lock = Lock()

    def get_count():
        with Counter.lock:
            ret = Counter.count
            Counter.count += 1
        return ret

class ProxyWorker(Thread):

    def __init__(self, socket, addr, mib_sec):
        self.ctt = CTT(socket)
        self.addr = addr
        self.mib_sec = mib_sec

        Thread.__init__(self)
    
    # Processa um pedido do manager para consultar os resultados de uma operação
    def process_response_request(self, manager_req):

        # Obter operação correspondente ao ID requisitado
        operation_entry = self.mib_sec.get_operation(manager_req.data)

        # Verificar se operação existe na tabela ou se foi executada pelo manager
        if not operation_entry or self.addr[0] != operation_entry.idSrc:
            response = Packet(Packet.PROXY_RESPONSE_FAIL, 'ID de operação inválido.')
            self.ctt.send_msg(response)
            return

        # Enviar o resultado da operação para o manager
        response = Packet(Packet.PROXY_RESPONSE, operation_entry)
        self.ctt.send_msg(response)

    #TODO juntar get com getnext?
    # Processa um pedido do manager para executar um get request
    def process_get_request(self, manager_req):

        # Parsing do pedido do manager
        target_ip = manager_req.data['target_ip']
        oids = manager_req.data['oids']
        community_string = manager_req.data['community_string']

        # Percorrer os OIDs no pedido do manager
        for oid in oids:
            
            # Inserir operação na MIBSec
            idOper = Counter.get_count()
            idSrc = self.addr[0]
            self.mib_sec.new_operation(idOper, MIBSec.TYPEOPER_GET, idSrc, target_ip, oid)

            # Informar manager qual o ID da operação
            self.ctt.send_msg(Packet(Packet.PROXY_REQUEST_ACK, idOper))

            # Executar operação no agente remoto
            (valueArg, typeArg) = SnmpRequester.get_request(target_ip, oid, community_string)
            
            # Guardar resultado da operação na MIBSec
            self.mib_sec.update_operation(idOper, valueArg, typeArg, sys.getsizeof(valueArg))


    # Processa um pedido do manager para executar um get next request
    def process_get_next_request(self, manager_req):

        # Parsing do pedido do manager
        target_ip = manager_req.data['target_ip']
        oids = manager_req.data['oids']
        community_string = manager_req.data['community_string']

        # Percorrer os OIDs no pedido do manager
        for oid in oids:
            
            # Inserir operação na MIBSec
            idOper = Counter.get_count()
            idSrc = self.addr[0]
            self.mib_sec.new_operation(idOper, MIBSec.TYPEOPER_GETNEXT, idSrc, target_ip, oid)

            # Informar manager qual o ID da operação
            self.ctt.send_msg(Packet(Packet.PROXY_REQUEST_ACK, idOper))

            # Executar operação no agente remoto
            (valueArg, typeArg) = SnmpRequester.get_next_request(target_ip, oid, community_string)
            
            # Guardar resultado da operação na MIBSec
            self.mib_sec.update_operation(idOper, valueArg, typeArg, sys.getsizeof(valueArg))


    # Execução da thread responsável por comunicar com um manager
    def run(self):

        # Troca de chaves Diffie-Hellman com o manager
        self.ctt.cipher_key = encryption.dh_key_exchange(self.ctt)
        self.ctt.hmac_key = encryption.dh_key_exchange(self.ctt)

        try:
            while True:
                # Receber pedido do manager
                manager_req = self.ctt.recv_msg()

                # Processar pedido do manager
                if manager_req.type == Packet.MANAGER_RESPONSE:
                    self.process_response_request(manager_req)
                elif manager_req.type == Packet.MANAGER_GET_REQUEST:
                    self.process_get_request(manager_req)
                elif manager_req.type == Packet.MANAGER_GETNEXT_REQUEST:
                    self.process_get_next_request(manager_req)
                elif manager_req.type == Packet.MANAGER_DISCONNECT:
                    self.ctt.socket.close()
                    print('[PROXY_WORKER] Conexão terminada. {0}'.format(self.addr))
                    break

        except KeyboardInterrupt:
            self.ctt.socket.close()

