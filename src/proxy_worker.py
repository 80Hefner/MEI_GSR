from curses import resetty
from threading import Thread
from ctt import CTT, ManagerRequest, ProxyResponse
from snmp_requester import SnmpRequester

class ProxyWorker(Thread):

    def __init__(self, socket, addr):
        self.socket = socket
        self.addr = addr

        Thread.__init__(self)
    
    # Processa um pedido do manager para consultar os resultados de um resquest
    def process_response_request(self, manager_req):
        pass #TODO

    # Processa um pedido do manager para executar um get request
    def process_get_request(self, manager_req):
        
        response = None
        try:
            result = SnmpRequester.get_request(manager_req.target_ip,
                                                manager_req.oids,
                                                manager_req.community_string)
            response = ProxyResponse(result)

        except Exception as err:
            response = ProxyResponse(str(err), False)
                
        # TODO guardar na MIB
        CTT.send_msg(response, self.socket)

    # Processa um pedido do manager para executar um get next request
    def process_get_next_request(self, manager_req):

        response = None
        try:
            result = SnmpRequester.get_next_request(manager_req.target_ip,
                                                    manager_req.oids,
                                                    manager_req.community_string)
            response = ProxyResponse(result)

        except Exception as err:
            response = ProxyResponse(str(err), False)
                        
        # TODO guardar na MIB
        CTT.send_msg(response, self.socket)

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

