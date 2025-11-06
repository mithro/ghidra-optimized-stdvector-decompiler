# Check if base varnodes are the same
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

print("=" * 80)
print("CHECK BASE VARNODES")
print("=" * 80)

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

                    # Get base of first LOAD
                    addr1 = defOp1.getInput(1)
                    addrDef1 = addr1.getDef()
                    if addrDef1 and addrDef1.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                        if addrDef1.getNumInputs() >= 2:
                            base1 = addrDef1.getInput(0)
                            offset1 = addrDef1.getInput(1)
                            print("\nOperand 1:")
                            print("  Base: " + str(base1))
                            if offset1.isConstant():
                                print("  Offset: 0x" + hex(offset1.getOffset())[2:])

                    # Get base of second LOAD
                    addr2 = defOp2.getInput(1)
                    addrDef2 = addr2.getDef()
                    if addrDef2 and addrDef2.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                        if addrDef2.getNumInputs() >= 2:
                            base2 = addrDef2.getInput(0)
                            offset2 = addrDef2.getInput(1)
                            print("\nOperand 2:")
                            print("  Base: " + str(base2))
                            if offset2.isConstant():
                                print("  Offset: 0x" + hex(offset2.getOffset())[2:])

                    # Check if bases are equal
                    if addrDef1 and addrDef2:
                        if addrDef1.getNumInputs() >= 2 and addrDef2.getNumInputs() >= 2:
                            base1 = addrDef1.getInput(0)
                            base2 = addrDef2.getInput(0)
                            print("\nBase comparison:")
                            print("  base1 == base2: " + str(base1 == base2))
                            print("  base1.equals(base2): " + str(base1.equals(base2)))

                    # Only check first one
                    break
            break
    break

decompiler.dispose()
print("\nComplete")
