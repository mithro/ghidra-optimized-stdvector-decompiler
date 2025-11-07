# Test traceToSourceVariable
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

print("=" * 80)
print("TEST TRACE TO SOURCE")
print("=" * 80)

def traceToSource(varnode):
    """Replicate traceToSourceVariable logic"""
    if varnode == None:
        return None

    maxDepth = 20
    current = varnode

    for depth in range(maxDepth):
        # If it's a free varnode or input, stop here
        if current.isFree() or current.isInput():
            return current

        defOp = current.getDef()
        if defOp == None:
            return current

        opcode = defOp.getOpcode()

        # Trace through COPY, CAST
        if opcode == PcodeOp.COPY or opcode == PcodeOp.CAST:
            if defOp.getNumInputs() > 0:
                current = defOp.getInput(0)
                continue
        # Trace through PTRSUB, PTRADD
        elif opcode == PcodeOp.PTRSUB or opcode == PcodeOp.PTRADD:
            if defOp.getNumInputs() > 0:
                current = defOp.getInput(0)
                continue
        # Trace through LOAD
        elif opcode == PcodeOp.LOAD:
            if defOp.getNumInputs() > 1:
                current = defOp.getInput(1)
                continue

        # Can't trace further
        return current

    return current

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

    # Find first INT_EQUAL with two LOAD operands
    for op in ops:
        if op.getOpcode() == PcodeOp.INT_EQUAL:
            if op.getNumInputs() >= 2:
                operand1 = op.getInput(0)
                operand2 = op.getInput(1)

                defOp1 = operand1.getDef()
                defOp2 = operand2.getDef()

                if (defOp1 and defOp1.getOpcode() == PcodeOp.LOAD and
                    defOp2 and defOp2.getOpcode() == PcodeOp.LOAD):

                    print("\nFound INT_EQUAL with two LOAD operands")

                    # Get bases
                    addr1 = defOp1.getInput(1)
                    addrDef1 = addr1.getDef()
                    base1 = None
                    if addrDef1 and addrDef1.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                        if addrDef1.getNumInputs() >= 2:
                            base1 = addrDef1.getInput(0)

                    addr2 = defOp2.getInput(1)
                    addrDef2 = addr2.getDef()
                    base2 = None
                    if addrDef2 and addrDef2.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                        if addrDef2.getNumInputs() >= 2:
                            base2 = addrDef2.getInput(0)

                    if base1 and base2:
                        print("\nBase 1: " + str(base1))
                        print("Base 2: " + str(base2))
                        print("Bases equal: " + str(base1.equals(base2)))

                        # Trace to source
                        source1 = traceToSource(base1)
                        source2 = traceToSource(base2)

                        print("\nSource 1: " + str(source1))
                        print("Source 2: " + str(source2))
                        print("Sources equal: " + str(source1.equals(source2) if source1 and source2 else "N/A"))

                        # Check HighVariables
                        high1 = base1.getHigh()
                        high2 = base2.getHigh()
                        print("\nHigh 1: " + str(high1))
                        print("High 2: " + str(high2))
                        print("Highs equal: " + str(high1.equals(high2) if high1 and high2 else "N/A"))

                    # Only check first one
                    break
            break
    break

decompiler.dispose()
print("\nComplete")
