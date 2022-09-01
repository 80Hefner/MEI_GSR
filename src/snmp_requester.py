from pysnmp import hlapi

class SnmpRequester:

    # Faz um pedido get para um ou mais objetos na MIB, indicando o IP ou nome do dispositivo remoto,
    # uma lista com os OIDs requisitados e a Community String
    def get_request(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.getCmd(
            engine,
            hlapi.CommunityData(credentials),
            hlapi.UdpTransportTarget((target, port)),
            context,
            *SnmpRequester.construct_object_types(oids)
        )
        return SnmpRequester.fetch(handler, 1)

    # Faz um pedido get next para um ou mais objetos na MIB, indicando o IP ou nome do dispositivo remoto,
    # uma lista com os OIDs requisitados e a Community String
    def get_next_request(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.nextCmd(
            engine,
            hlapi.CommunityData(credentials),
            hlapi.UdpTransportTarget((target, port)),
            context,
            *SnmpRequester.construct_object_types(oids)
        )
        return SnmpRequester.fetch(handler, 1)

    # Recebe uma lista de OIDs (em formato string) e transforma-os em ObjectType
    def construct_object_types(list_of_oids):
        object_types = []
        for oid in list_of_oids:
            object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
        return object_types

    # TODO provavelmente retirar o max_iter
    # Itera sobre um handler e retorna os resultados do pedido
    def fetch(handler, max_iter):
        # Lista de tuplos resultante. Cada tuplo associa um OID ao seu valor na MIB
        result = []

        # Percorre o iterador handler num máximo de vezes especificado
        for _ in range(max_iter):

            try:
                # Obter próximo objeto do iterador
                error_indication, error_status, error_index, var_binds =  next(handler)

                # Verificar se houve erros no pedido get. Em caso afirmativo, é lançada uma exceção
                if not error_indication and not error_status:
                    # Iterar sobre os resultados do pedido get e adicionar o tuplo (oid, oid_value) à lista
                    for var_bind in var_binds:
                        oid = str(var_bind[0])  # var_bind[0].prettyPrint()
                        oid_value = str(var_bind[1])
                        result.append((oid, oid_value))
                    
                else:
                    raise RuntimeError('Got SNMP error \'{0}\''.format(error_indication))
            
            except StopIteration:
                break
                
        return result
