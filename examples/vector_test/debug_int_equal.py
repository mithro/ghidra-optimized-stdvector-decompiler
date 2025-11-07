# Debug INT_EQUAL patterns to see structure
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

print("=" * 80)
print("DEBUG INT_EQUAL PATTERNS")
print("=" * 80)

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nFunction: " + func.getName())
    print("-" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("Decompilation failed!")
        break

    highFunc = results.getHighFunction()
    if highFunc == None:
        print("No high function!")
        break

    # Find all INT_EQUAL operations
    ops = highFunc.getPcodeOps()
    equalCount = 0

    while ops.hasNext():
        op = ops.next()

        if op.getOpcode() == PcodeOp.INT_EQUAL:
            equalCount += 1
            print("\n[INT_EQUAL #" + str(equalCount) + "]")
            print("  Operation: " + op.toString())
            print("  Sequence: " + str(op.getSeqnum()))

            # Show inputs
            for i in range(op.getNumInputs()):
                inputVar = op.getInput(i)
                print("  Input " + str(i) + ": " + str(inputVar))

                # Show definition of this input
                defOp = inputVar.getDef()
                if defOp:
                    print("    Def: " + defOp.getMnemonic() + " " + str(defOp))

                    # If it's a LOAD, show what it's loading
                    if defOp.getOpcode() == PcodeOp.LOAD and defOp.getNumInputs() >= 2:
                        addrVar = defOp.getInput(1)
                        print("    LoadAddr: " + str(addrVar))

                        addrDef = addrVar.getDef()
                        if addrDef:
                            print("    AddrDef: " + addrDef.getMnemonic() + " " + str(addrDef))

                            # Show PTRSUB details
                            if addrDef.getOpcode() == PcodeOp.PTRSUB or addrDef.getOpcode() == PcodeOp.PTRADD:
                                if addrDef.getNumInputs() >= 2:
                                    base = addrDef.getInput(0)
                                    offset = addrDef.getInput(1)
                                    print("      Base: " + str(base))
                                    print("      Offset: " + str(offset))
                                    if offset.isConstant():
                                        offsetVal = offset.getOffset()
                                        print("      Offset value: 0x" + format(offsetVal, 'x'))
                                        if offsetVal == 0x0:
                                            print("      >>> This is MYFIRST! <<<")
                                        elif offsetVal == 0x8:
                                            print("      >>> This is MYLAST! <<<")
                                        elif offsetVal == 0x10:
                                            print("      >>> This is MYEND! <<<")
                else:
                    print("    (no def)")

    print("\n" + "=" * 80)
    print("Total INT_EQUAL operations: " + str(equalCount))
    break

decompiler.dispose()
print("Complete")
