# Analyze all operations to find vector patterns
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

print("=" * 80)
print("ANALYZE ALL VECTOR-RELATED OPERATIONS")
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

    # Count operation types
    opCounts = {}
    ops = highFunc.getPcodeOps()

    while ops.hasNext():
        op = ops.next()
        mnemonic = op.getMnemonic()
        opCounts[mnemonic] = opCounts.get(mnemonic, 0) + 1

    print("\nOperation counts:")
    for opType in sorted(opCounts.keys()):
        if opCounts[opType] > 5:  # Only show common ops
            print("  " + opType + ": " + str(opCounts[opType]))

    # Look for SIZE patterns: INT_SUB followed by INT_RIGHT
    print("\n" + "=" * 80)
    print("SIZE PATTERNS (subtraction >> shift)")
    print("=" * 80)

    ops = highFunc.getPcodeOps()
    sizeCount = 0
    while ops.hasNext():
        op = ops.next()

        # Look for right shift operations
        if op.getOpcode() == PcodeOp.INT_RIGHT or op.getOpcode() == PcodeOp.INT_SRIGHT:
            if op.getNumInputs() >= 2:
                leftInput = op.getInput(0)
                rightInput = op.getInput(1)

                # Check if left side is subtraction
                defOp = leftInput.getDef()
                if defOp and defOp.getOpcode() == PcodeOp.INT_SUB:
                    sizeCount += 1
                    print("\n[SIZE #" + str(sizeCount) + "]")
                    print("  Shift: " + op.toString())
                    print("  Subtract: " + defOp.toString())

                    # Check the subtraction operands
                    if defOp.getNumInputs() >= 2:
                        sub0 = defOp.getInput(0)
                        sub1 = defOp.getInput(1)

                        print("  Sub operand 0: " + str(sub0))
                        def0 = sub0.getDef()
                        if def0 and def0.getOpcode() == PcodeOp.LOAD:
                            if def0.getNumInputs() >= 2:
                                addr0 = def0.getInput(1)
                                addrDef0 = addr0.getDef()
                                if addrDef0 and (addrDef0.getOpcode() == PcodeOp.PTRSUB or addrDef0.getOpcode() == PcodeOp.PTRADD):
                                    if addrDef0.getNumInputs() >= 2:
                                        offset0 = addrDef0.getInput(1)
                                        if offset0.isConstant():
                                            print("    -> LOAD from offset 0x" + format(offset0.getOffset(), 'x'))

                        print("  Sub operand 1: " + str(sub1))
                        def1 = sub1.getDef()
                        if def1 and def1.getOpcode() == PcodeOp.LOAD:
                            if def1.getNumInputs() >= 2:
                                addr1 = def1.getInput(1)
                                addrDef1 = addr1.getDef()
                                if addrDef1 and (addrDef1.getOpcode() == PcodeOp.PTRSUB or addrDef1.getOpcode() == PcodeOp.PTRADD):
                                    if addrDef1.getNumInputs() >= 2:
                                        offset1 = addrDef1.getInput(1)
                                        if offset1.isConstant():
                                            print("    -> LOAD from offset 0x" + format(offset1.getOffset(), 'x'))

                    if rightInput.isConstant():
                        print("  Shift amount: " + str(rightInput.getOffset()))

    print("\nTotal SIZE-like patterns found: " + str(sizeCount))

    # Look for DATA patterns: Just accessing _Myfirst
    print("\n" + "=" * 80)
    print("DATA PATTERNS (accessing _Myfirst)")
    print("=" * 80)

    ops = highFunc.getPcodeOps()
    dataCount = 0
    while ops.hasNext():
        op = ops.next()

        # Look for LOAD operations
        if op.getOpcode() == PcodeOp.LOAD:
            if op.getNumInputs() >= 2:
                addr = op.getInput(1)
                addrDef = addr.getDef()

                if addrDef and (addrDef.getOpcode() == PcodeOp.PTRSUB or addrDef.getOpcode() == PcodeOp.PTRADD):
                    if addrDef.getNumInputs() >= 2:
                        offset = addrDef.getInput(1)
                        if offset.isConstant() and offset.getOffset() == 0x0:
                            dataCount += 1
                            if dataCount <= 3:  # Only show first 3
                                print("\n[DATA #" + str(dataCount) + "]")
                                print("  LOAD: " + op.toString())
                                print("  Address: " + addrDef.toString())
                                print("  Offset: 0x0 (_Myfirst)")

    print("\nTotal DATA accesses to _Myfirst: " + str(dataCount))

    break

decompiler.dispose()
print("\nComplete")
