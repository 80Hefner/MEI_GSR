
class MIBSec:
    #TODO implementar locks e assim

    TYPEARG_NONE = 0
    TYPEARG_INT = 1
    TYPEARG_STR = 2

    TYPEOPER_GET = 1
    TYPEOPER_GETNEXT = 2

    def __init__(self, operations_dict={}):
        self.operations_dict = operations_dict

    def new_operation(self, idOper, typeOper, idSrc, idDest, oidArg):
        operation_entry_value = OperationEntryValue(typeOper, idSrc, idDest, oidArg)
        self.operations_dict[idOper] = operation_entry_value
    
    def update_operation(self, idOper, valueArg, typeArg, sizeArg):
        operation_entry_value = self.operations_dict[idOper]
        operation_entry_value.valueArg = valueArg
        operation_entry_value.typeArg = typeArg
        operation_entry_value.sizeArg = sizeArg
    
    def get_operation(self, idOper):
        return self.operations_dict.get(idOper, None)
    
class OperationEntryValue:

    def __init__(self, typeOper, idSrc, idDest, oidArg,
            valueArg=b'', typeArg=MIBSec.TYPEARG_NONE, sizeArg=0):
        self.typeOper = typeOper
        self.idSrc = idSrc
        self.idDest = idDest
        self.oidArg = oidArg
        self.valueArg = valueArg
        self.typeArg = typeArg
        self.sizeArg = sizeArg
    
    def __str__(self):
        string = '{\n  typeOper: '
        if self.typeOper == MIBSec.TYPEOPER_GET:
            string += 'GET REQUEST'
        elif self.typeOper == MIBSec.TYPEOPER_GETNEXT:
            string += 'GET_NEXT REQUEST'
        
        string += '\n  idSrc:    ' + self.idSrc
        string += '\n  idDest:   ' + self.idDest
        string += '\n  oidArg:   ' + self.oidArg
        string += '\n  valueArg: ' + str(self.valueArg)

        string += '\n  typeArg:  '
        if self.typeArg == MIBSec.TYPEARG_NONE:
            string += 'NONE'
        elif self.typeArg == MIBSec.TYPEARG_INT:
            string += 'INTEGER'
        elif self.typeArg == MIBSec.TYPEARG_STR:
            string += 'STRING'
        
        string += '\n  sizeArg:  ' + str(self.sizeArg)
        string += '\n}'

        return string
