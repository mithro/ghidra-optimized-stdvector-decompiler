# Manual check of what identifyVectorMember should see
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

print("=" * 80)
print("MANUAL TYPE CHECKING")
print("=" * 80)

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nAnalyzing: " + func.getName())

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        break

    highFunc = results.getHighFunction()
    if highFunc == None:
        break

    ops = list(highFunc.getPcodeOps())

    # Find the first INT_EQUAL operation
    for op in ops:
        if op.getOpcode() == PcodeOp.INT_EQUAL:
            print("\nFound INT_EQUAL at " + str(op.getSeqnum().getTarget()))

            if op.getNumInputs() >= 2:
                operand1 = op.getInput(0)
                operand2 = op.getInput(1)

                # Check operand1
                print("\nOperand 1:")
                print("  Varnode: " + str(operand1))
                defOp1 = operand1.getDef()
                if defOp1:
                    print("  Defined by: " + defOp1.getMnemonic())

                    if defOp1.getOpcode() == PcodeOp.LOAD:
                        print("  >>> IS LOAD <<<")
                        if defOp1.getNumInputs() >= 2:
                            addrVn = defOp1.getInput(1)
                            print("  Address varnode: " + str(addrVn))

                            # Check type of address varnode
                            high = addrVn.getHigh()
                            if high:
                                dt = high.getDataType()
                                if dt:
                                    print("  Address type: " + dt.getName())
                                    print("  Contains 'Vector_val': " + str("Vector_val" in dt.getName()))
                            else:
                                print("  Address has no HighVariable")

                            addrDef = addrVn.getDef()
                            if addrDef:
                                print("  Address defined by: " + addrDef.getMnemonic())
                                if addrDef.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                                    if addrDef.getNumInputs() >= 2:
                                        base = addrDef.getInput(0)
                                        offsetVn = addrDef.getInput(1)

                                        if offsetVn.isConstant():
                                            offset = offsetVn.getOffset()
                                            print("  >>> PTRSUB offset: 0x" + hex(offset)[2:] + " <<<")

                                        # Check type of base
                                        baseHigh = base.getHigh()
                                        if baseHigh:
                                            baseDt = baseHigh.getDataType()
                                            if baseDt:
                                                print("  Base type: " + baseDt.getName())
                                                print("  Contains 'Vector_val': " + str("Vector_val" in baseDt.getName()))
                                        else:
                                            print("  Base has no HighVariable")

                # Only check first INT_EQUAL
                break
    break

decompiler.dispose()
print("\nComplete")
