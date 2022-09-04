from enum import Enum
from threading import Lock
from typing import Any, Dict

class MIBSec_TypeArg(Enum):
    NONE = 0
    INT  = 1
    STR  = 2

class MIBSec_TypeOper(Enum):
    GET     = 1
    GETNEXT = 2

class OperationEntryValue:

    def __init__(self, typeOper: MIBSec_TypeOper, idSrc: str, idDest: str, oidArg: str,
            valueArg: Any = None, typeArg: MIBSec_TypeArg = MIBSec_TypeArg.NONE, sizeArg: int = 0):
        self.typeOper = typeOper
        self.idSrc = idSrc
        self.idDest = idDest
        self.oidArg = oidArg
        self.valueArg = valueArg
        self.typeArg = typeArg
        self.sizeArg = sizeArg
    
    def __str__(self):
        string = '{\n  typeOper: '
        if self.typeOper == MIBSec_TypeOper.GET:
            string += 'GET REQUEST'
        elif self.typeOper == MIBSec_TypeOper.GETNEXT:
            string += 'GET_NEXT REQUEST'
        
        string += '\n  idSrc:    ' + self.idSrc
        string += '\n  idDest:   ' + self.idDest
        string += '\n  oidArg:   ' + self.oidArg
        string += '\n  valueArg: ' + str(self.valueArg)

        string += '\n  typeArg:  '
        if self.typeArg == MIBSec_TypeArg.NONE:
            string += 'NONE'
        elif self.typeArg == MIBSec_TypeArg.INT:
            string += 'INTEGER'
        elif self.typeArg == MIBSec_TypeArg.STR:
            string += 'STRING'
        
        string += '\n  sizeArg:  ' + str(self.sizeArg)
        string += '\n}'

        return string

class MIBSec:

    def __init__(self, operations_dict: Dict[int, OperationEntryValue]={}):
        self.operations_dict = operations_dict
        self.operations_dict_lock = Lock()

    def new_operation(self, idOper: int, typeOper: MIBSec_TypeOper, idSrc: str, idDest: str, oidArg: str):
        operation_entry_value = OperationEntryValue(typeOper, idSrc, idDest, oidArg)
        with self.operations_dict_lock:
            self.operations_dict[idOper] = operation_entry_value
    
    def update_operation(self, idOper: int, valueArg: Any, typeArg: MIBSec_TypeArg, sizeArg: int):
        with self.operations_dict_lock:
            operation_entry_value = self.operations_dict[idOper]
            
        operation_entry_value.valueArg = valueArg
        operation_entry_value.typeArg = typeArg
        operation_entry_value.sizeArg = sizeArg
    
    def get_operation(self, idOper: int):
        with self.operations_dict_lock:
            return self.operations_dict.get(idOper, None)
