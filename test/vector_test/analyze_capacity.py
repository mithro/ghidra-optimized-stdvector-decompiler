# Analyze CAPACITY patterns
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

print("=" * 80)
print("ANALYZE CAPACITY PATTERNS")
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

    # Look for CAPACITY patterns: (_Myend - _Myfirst) >> shift
    print("\nCAPACITY PATTERNS (_Myend - _Myfirst) >> shift")
    print("=" * 80)

    ops = highFunc.getPcodeOps()
    capacityCount = 0
    while ops.hasNext():
        op = ops.next()

        # Look for right shift operations
        if op.getOpcode() == PcodeOp.INT_RIGHT or op.getOpcode() == PcodeOp.INT_SRIGHT:
            if op.getNumInputs() >= 2:
                leftInput = op.getInput(0)

                # Check if left side is subtraction
                defOp = leftInput.getDef()
                if defOp and defOp.getOpcode() == PcodeOp.INT_SUB:
                    if defOp.getNumInputs() >= 2:
                        sub0 = defOp.getInput(0)
                        sub1 = defOp.getInput(1)

                        # Check operands for MYEND and MYFIRST
                        def0 = sub0.getDef()
                        def1 = sub1.getDef()

                        offset0 = None
                        offset1 = None

                        if def0 and def0.getOpcode() == PcodeOp.LOAD and def0.getNumInputs() >= 2:
                            addr0 = def0.getInput(1)
                            addrDef0 = addr0.getDef()
                            if addrDef0 and (addrDef0.getOpcode() == PcodeOp.PTRSUB or addrDef0.getOpcode() == PcodeOp.PTRADD):
                                if addrDef0.getNumInputs() >= 2:
                                    offsetVar = addrDef0.getInput(1)
                                    if offsetVar.isConstant():
                                        offset0 = offsetVar.getOffset()

                        if def1 and def1.getOpcode() == PcodeOp.LOAD and def1.getNumInputs() >= 2:
                            addr1 = def1.getInput(1)
                            addrDef1 = addr1.getDef()
                            if addrDef1 and (addrDef1.getOpcode() == PcodeOp.PTRSUB or addrDef1.getOpcode() == PcodeOp.PTRADD):
                                if addrDef1.getNumInputs() >= 2:
                                    offsetVar = addrDef1.getInput(1)
                                    if offsetVar.isConstant():
                                        offset1 = offsetVar.getOffset()

                        # Check if this is MYEND - MYFIRST
                        if offset0 == 0x10 and offset1 == 0x0:
                            capacityCount += 1
                            print("\n[CAPACITY #" + str(capacityCount) + "]")
                            print("  Pattern: (_Myend - _Myfirst) >> shift")
                            print("  Shift op: " + op.toString())
                            print("  Subtract: " + defOp.toString())
                            print("  MYEND (0x10): " + str(sub0))
                            print("  MYFIRST (0x0): " + str(sub1))

    print("\nTotal CAPACITY patterns: " + str(capacityCount))
    break

decompiler.dispose()
print("\nComplete")
