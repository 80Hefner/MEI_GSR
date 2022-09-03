from logging import exception
from pysnmp import hlapi
from pysnmp.smi import error
from mibsec import MIBSec

class SnmpRequester:

    # Faz um pedido get para um objeto na MIB, indicando o IP ou nome do dispositivo remoto,
    # o OID requisitado e a Community String
    def get_request(target, oid, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.getCmd(
            engine,
            hlapi.CommunityData(credentials),
            hlapi.UdpTransportTarget((target, port)),
            context,
            hlapi.ObjectType(hlapi.ObjectIdentity(oid))
        )
        return _fetch_get(handler)

    # Faz um pedido get next para um objeto na MIB, indicando o IP ou nome do dispositivo remoto,
    # o OID requisitado e a Community String
    def get_next_request(target, oid, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.nextCmd(
            engine,
            hlapi.CommunityData(credentials),
            hlapi.UdpTransportTarget((target, port)),
            context,
            hlapi.ObjectType(hlapi.ObjectIdentity(oid))
        )
        return _fetch_get(handler)

# Obtém o primeiro objeto do handler e retorna o resultado do pedido
# O handler deve ser o resultado de um pedido com apenas um OID
def _fetch_get(handler):
    # Obter primeiro objeto do iterador
    try:
        error_indication, error_status, error_index, var_binds =  next(handler)

        # Verificar se houve erros no pedido get
        if not error_indication and not error_status:
            result = _cast(var_binds[0][1])
        else:
            result = (f'Got SNMP error \'{error_indication}\'', MIBSec.TYPEARG_STR)

    except Exception as e:
        result = (str(e), MIBSec.TYPEARG_STR)

    return result

# Recebe um valor e tenta dar cast para um inteiro ou uma string
# Retorna um tuplo com o valor casted e o seu tipo
def _cast(value):
    try:
        int_value = int(value)
        return (int_value, MIBSec.TYPEARG_INT)
    except (ValueError, TypeError):
        try:
            str_value = str(value)
            return (str_value, MIBSec.TYPEARG_STR)
        except (ValueError, TypeError):
            return (value, MIBSec.TYPEARG_NONE)


# Itera sobre um handler e retorna os resultados da subtree do primeiro OID
def _fetch_walk(handler, root_oid):
    # Lista de tuplos resultante. Cada tuplo associa um OID ao seu valor na MIB
    result = []

    for error_indication, error_status, error_index, var_binds in handler:

        if not error_indication and not error_status:

            if (not str(var_binds[0][0]).startswith(root_oid)):
                break
            
            oid = str(var_binds[0][0])
            oid_value = str(var_binds[0][1])
            result.append((oid, oid_value))

        else:
            raise RuntimeError('Got SNMP error \'{0}\''.format(error_indication))

    return result
