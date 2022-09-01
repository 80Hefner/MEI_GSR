from curses import resetty
import sys
from threading import Thread, Lock
from ctt import CTT, ManagerRequest, ProxyResponse
from mibsec import MIBSec, OperationEntryValue
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
        self.socket = socket
        self.addr = addr
        self.mib_sec = mib_sec

        Thread.__init__(self)
    
    # Processa um pedido do manager para consultar os resultados de uma operação
    def process_response_request(self, manager_req):

        # Obter operação correspondente ao ID requisitado
        operation_entry = self.mib_sec.get_operation(manager_req.operation_id)

        # Verificar se operação existe na tabela ou se foi executada pelo manager
        if not operation_entry or self.addr[0] != operation_entry.idSrc:
            response = ProxyResponse(ProxyResponse.REQUEST_RESULT_FAIL, 'ID de operação inválido.')
            CTT.send_msg(response, self.socket)
            return

        # Enviar o resultado da operação para o manager
        response = ProxyResponse(ProxyResponse.REQUEST_RESULT, operation_entry)
        CTT.send_msg(response, self.socket)

    # Processa um pedido do manager para executar um get request
    def process_get_request(self, manager_req):

        # Percorrer os OIDs no pedido do manager
        for oid in manager_req.oids:
            
            # Inserir operação na MIBSec
            idOper = Counter.get_count()
            #TODO verificar se manager ou agente já estão na MIBSec e usar aliases
            idSrc = self.addr[0]
            self.mib_sec.new_operation(idOper, MIBSec.TYPEOPER_GET, idSrc, manager_req.target_ip, oid)

            # Informar manager qual o ID da operação
            CTT.send_msg(ProxyResponse(ProxyResponse.REQUEST_ACK, idOper), self.socket)

            # Executar operação no agente remoto
            (valueArg, typeArg) = SnmpRequester.get_request(manager_req.target_ip, oid, manager_req.community_string)
            
            # Guardar resultado da operação na MIBSec
            self.mib_sec.update_operation(idOper, valueArg, typeArg, sys.getsizeof(valueArg))


    # Processa um pedido do manager para executar um get next request
    def process_get_next_request(self, manager_req):

        # Percorrer os OIDs no pedido do manager
        for oid in manager_req.oids:
            
            # Inserir operação na MIBSec
            idOper = Counter.get_count()
            #TODO verificar se manager ou agente já estão na MIBSec e usar aliases
            idSrc = self.addr[0]
            self.mib_sec.new_operation(idOper, MIBSec.TYPEOPER_GETNEXT, idSrc, manager_req.target_ip, oid)

            # Informar manager qual o ID da operação
            CTT.send_msg(ProxyResponse(ProxyResponse.REQUEST_ACK, idOper), self.socket)

            # Executar operação no agente remoto
            (valueArg, typeArg) = SnmpRequester.get_next_request(manager_req.target_ip, oid, manager_req.community_string)
            
            # Guardar resultado da operação na MIBSec
            self.mib_sec.update_operation(idOper, valueArg, typeArg, sys.getsizeof(valueArg))


    # Execução da thread responsável por comunicar com um manager
    def run(self):

        try:
            while True:
                # Receber pedido do manager
                manager_req = CTT.recv_msg(self.socket)

                # Processar pedido do manager
                if manager_req.type == ManagerRequest.RESPONSE:
                    self.process_response_request(manager_req)
                elif manager_req.type == ManagerRequest.GET_REQUEST:
                    self.process_get_request(manager_req)
                elif manager_req.type == ManagerRequest.GETNEXT_REQUEST:
                    self.process_get_next_request(manager_req)
                elif manager_req.type == ManagerRequest.DISCONNECT:
                    self.socket.close()
                    print('[PROXY_WORKER] Conexão terminada. {0}'.format(self.addr))
                    break

        except KeyboardInterrupt:
            self.socket.close()

