from pysnmp import hlapi
from typing import Any, Iterable, Tuple

from mibsec import MIBSec_TypeArg

# Faz um pedido get para um objeto na MIB, indicando o IP ou nome do dispositivo remoto,
# o OID requisitado e a Community String
def get_request(target: str, oid: str, credentials: str, port: int = 161,
                engine: hlapi.SnmpEngine = hlapi.SnmpEngine(),
                context: hlapi.ContextData = hlapi.ContextData()):
    try:
        handler = hlapi.getCmd(
            engine,
            hlapi.CommunityData(credentials),
            hlapi.UdpTransportTarget((target, port)),
            context,
            hlapi.ObjectType(hlapi.ObjectIdentity(oid))
        )
        return _fetch_get(handler)
    
    except Exception as e:
        return (str(e), MIBSec_TypeArg.STR)    

# Faz um pedido get next para um objeto na MIB, indicando o IP ou nome do dispositivo remoto,
# o OID requisitado e a Community String
def get_next_request(target: str, oid: str, credentials: str, port: int = 161,
                        engine: hlapi.SnmpEngine = hlapi.SnmpEngine(),
                        context: hlapi.ContextData = hlapi.ContextData()):
    try:
        handler = hlapi.nextCmd(
            engine,
            hlapi.CommunityData(credentials),
            hlapi.UdpTransportTarget((target, port)),
            context,
            hlapi.ObjectType(hlapi.ObjectIdentity(oid))
        )
        return _fetch_get(handler)
    
    except Exception as e:
        return (str(e), MIBSec_TypeArg.STR)

# Obtém o primeiro objeto do handler e retorna o resultado do pedido
# O handler deve ser o resultado de um pedido com apenas um OID
def _fetch_get(handler) -> Tuple[Any, MIBSec_TypeArg]:
    # Obter primeiro objeto do iterador
    error_indication, error_status, error_index, var_binds = next(handler)

    # Verificar se houve erros no pedido get
    if not error_indication and not error_status:
        result = _cast(var_binds[0][1])
    else:
        result = (f'Got SNMP error \'{error_indication}\'', MIBSec_TypeArg.STR)

    return result

# Recebe um valor e tenta dar cast para um inteiro ou uma string
# Retorna um tuplo com o valor casted e o seu tipo
def _cast(value: Any) -> Tuple[Any, MIBSec_TypeArg]:
    try:
        int_value = int(value)
        return (int_value, MIBSec_TypeArg.INT)
    except (ValueError, TypeError):
        try:
            str_value = str(value)
            return (str_value, MIBSec_TypeArg.STR)
        except (ValueError, TypeError):
            return (value, MIBSec_TypeArg.NONE)
