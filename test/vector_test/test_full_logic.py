# Replicate full matchEmptyPattern logic
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.data import Pointer

print("=" * 80)
print("FULL PATTERN MATCHING LOGIC TEST")
print("=" * 80)

OFFSET_MYFIRST = 0x0
OFFSET_MYLAST = 0x8
OFFSET_MYEND = 0x10

def isVectorType(varnode):
    if varnode == None:
        return False
    highVar = varnode.getHigh()
    if highVar == None:
        return False
    dataType = highVar.getDataType()
    if dataType == None:
        return False
    typeName = dataType.getName()
    if typeName == None:
        return False

    # Check type name
    if "vector<" in typeName or "vector_" in typeName or "Vector_val" in typeName:
        return True

    # Check for pointer
    if isinstance(dataType, Pointer):
        pointedType = dataType.getDataType()
        if pointedType:
            pointedName = pointedType.getName()
            if pointedName and ("vector<" in pointedName or "vector_" in pointedName or "Vector_val" in pointedName):
                return True

    return False

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        break

    highFunc = results.getHighFunction()
    ops = list(highFunc.getPcodeOps())

    # Find first INT_EQUAL
    for op in ops:
        if op.getOpcode() != PcodeOp.INT_EQUAL:
            continue

        print("\n>>> Checking INT_EQUAL at " + str(op.getSeqnum().getTarget()))

        if op.getNumInputs() < 2:
            print("  Not enough inputs")
            continue

        operand1 = op.getInput(0)
        operand2 = op.getInput(1)

        # Check operand 1
        print("\n  Operand 1:")
        defOp1 = operand1.getDef()
        if defOp1 == None:
            print("    No def - skipping")
            continue

        print("    Def: " + defOp1.getMnemonic())

        if defOp1.getOpcode() == PcodeOp.LOAD:
            print("    >>> IS LOAD <<<")
            if defOp1.getNumInputs() >= 2:
                addrVn1 = defOp1.getInput(1)
                addrDef1 = addrVn1.getDef()

                if addrDef1 and addrDef1.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                    print("    >>> Address is PTRSUB/PTRADD <<<")
                    if addrDef1.getNumInputs() >= 2:
                        base1 = addrDef1.getInput(0)
                        offsetVn1 = addrDef1.getInput(1)

                        if offsetVn1.isConstant():
                            offset1 = offsetVn1.getOffset()
                            print("    Offset: 0x" + hex(offset1)[2:])

                            memberType1 = None
                            if offset1 == OFFSET_MYFIRST:
                                memberType1 = "MYFIRST"
                            elif offset1 == OFFSET_MYLAST:
                                memberType1 = "MYLAST"
                            elif offset1 == OFFSET_MYEND:
                                memberType1 = "MYEND"

                            print("    Member type: " + str(memberType1))

                            if memberType1:
                                # Check vector type
                                isVec = isVectorType(base1)
                                print("    Base is vector: " + str(isVec))

                                if isVec:
                                    print("    >>> OPERAND 1 IDENTIFIED: " + memberType1 + " <<<")

        # Check operand 2
        print("\n  Operand 2:")
        defOp2 = operand2.getDef()
        if defOp2 == None:
            print("    No def - skipping")
            continue

        print("    Def: " + defOp2.getMnemonic())

        if defOp2.getOpcode() == PcodeOp.LOAD:
            print("    >>> IS LOAD <<<")
            if defOp2.getNumInputs() >= 2:
                addrVn2 = defOp2.getInput(1)
                addrDef2 = addrVn2.getDef()

                if addrDef2 and addrDef2.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                    print("    >>> Address is PTRSUB/PTRADD <<<")
                    if addrDef2.getNumInputs() >= 2:
                        base2 = addrDef2.getInput(0)
                        offsetVn2 = addrDef2.getInput(1)

                        if offsetVn2.isConstant():
                            offset2 = offsetVn2.getOffset()
                            print("    Offset: 0x" + hex(offset2)[2:])

                            memberType2 = None
                            if offset2 == OFFSET_MYFIRST:
                                memberType2 = "MYFIRST"
                            elif offset2 == OFFSET_MYLAST:
                                memberType2 = "MYLAST"
                            elif offset2 == OFFSET_MYEND:
                                memberType2 = "MYEND"

                            print("    Member type: " + str(memberType2))

                            if memberType2:
                                # Check vector type
                                isVec = isVectorType(base2)
                                print("    Base is vector: " + str(isVec))

                                if isVec:
                                    print("    >>> OPERAND 2 IDENTIFIED: " + memberType2 + " <<<")

        # Only check first INT_EQUAL
        break
    break

decompiler.dispose()
print("\nComplete")
