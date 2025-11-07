# Debug ALL PTRSUB operations to see what offsets are used
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("DEBUG: All PTRSUB Operations")
print("=" * 80)

# Analyze main function
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "main" not in func.getName():
        continue

    print("\nAnalyzing: " + func.getName())
    print("-" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("  Decompilation failed!")
        continue

    highFunc = results.getHighFunction()
    if highFunc == None:
        print("  No high function!")
        continue

    ops = list(highFunc.getPcodeOps())
    print("  Total pcode ops: " + str(len(ops)))

    # Find ALL PTRSUB operations
    ptrsub_ops = []
    for op in ops:
        if op.getOpcode() == PcodeOp.PTRSUB:
            ptrsub_ops.append(op)

    print("  Total PTRSUB ops: " + str(len(ptrsub_ops)))

    # Show first 20
    for i, op in enumerate(ptrsub_ops[:20]):
        if op.getNumInputs() >= 2:
            baseVarnode = op.getInput(0)
            offsetVarnode = op.getInput(1)

            offset_str = "?"
            if offsetVarnode.isConstant():
                offset = offsetVarnode.getOffset()
                offset_str = "0x" + hex(offset)[2:]

            print("  PTRSUB #" + str(i) + ": offset=" + offset_str)

            # Get type info
            highVar = baseVarnode.getHigh()
            if highVar is not None:
                dt = highVar.getDataType()
                if dt is not None:
                    print("    Base type: " + dt.getName())

    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Debug Complete")
print("=" * 80)
