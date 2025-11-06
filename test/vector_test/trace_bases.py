# Trace bases to see what they point to
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

def traceVarnode(varnode, depth=0, maxDepth=10):
    indent = "  " * depth
    if depth > maxDepth:
        print(indent + "(max depth)")
        return

    if varnode == None:
        print(indent + "(null)")
        return

    print(indent + str(varnode))

    defOp = varnode.getDef()
    if defOp:
        print(indent + "  def: " + defOp.getMnemonic())
        for i in range(min(2, defOp.getNumInputs())):
            print(indent + "  input " + str(i) + ":")
            traceVarnode(defOp.getInput(i), depth + 2, maxDepth)
    else:
        # Check if it has a HighVariable
        highVar = varnode.getHigh()
        if highVar:
            print(indent + "  HighVar: " + str(highVar))
            print(indent + "  Symbol: " + (str(highVar.getSymbol()) if highVar.getSymbol() else "(none)"))

print("=" * 80)
print("TRACE VECTOR BASES")
print("=" * 80)

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nFunction: " + func.getName())

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("Decompilation failed!")
        break

    highFunc = results.getHighFunction()
    if highFunc == None:
        print("No high function!")
        break

    # Find first INT_EQUAL
    ops = highFunc.getPcodeOps()
    while ops.hasNext():
        op = ops.next()

        if op.getOpcode() == PcodeOp.INT_EQUAL:
            print("\n" + "=" * 80)
            print("First INT_EQUAL: " + str(op.getSeqnum()))
            print("=" * 80)

            for i in range(2):
                inputVar = op.getInput(i)
                print("\nInput " + str(i) + ":")

                # Get the LOAD
                defOp = inputVar.getDef()
                if defOp and defOp.getOpcode() == PcodeOp.LOAD:
                    addrVar = defOp.getInput(1)
                    addrDef = addrVar.getDef()

                    if addrDef and (addrDef.getOpcode() == PcodeOp.PTRSUB or addrDef.getOpcode() == PcodeOp.PTRADD):
                        baseVar = addrDef.getInput(0)
                        offsetVar = addrDef.getInput(1)

                        if offsetVar.isConstant():
                            offset = offsetVar.getOffset()
                            print("  Vector member offset: 0x" + format(offset, 'x'))

                            print("\n  Base varnode:")
                            traceVarnode(baseVar, 2, 15)

            # Only show first one
            break

    break

decompiler.dispose()
print("\nComplete")
