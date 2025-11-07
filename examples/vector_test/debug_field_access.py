# Debug how vector fields are actually accessed in pcode
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("DEBUG: Vector Field Access in Pcode")
print("=" * 80)

# Analyze TestComplexOperations
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nAnalyzing: " + func.getName())
    print("-" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        print("  Decompilation failed!")
        continue

    # Get C code to see what it looks like
    decomp = results.getDecompiledFunction()
    if decomp:
        code_lines = decomp.getC().split('\n')
        print("\nFirst 40 lines of decompiled C:")
        for i, line in enumerate(code_lines[:40]):
            if "_Myfirst" in line or "_Mylast" in line or "_Myend" in line:
                print("  " + str(i) + ": >>>" + line)
            elif i < 30:
                print("  " + str(i) + ": " + line)

    highFunc = results.getHighFunction()
    if highFunc == None:
        print("\n  No high function!")
        continue

    # Look at the pcode more carefully
    ops = list(highFunc.getPcodeOps())
    print("\n  Total pcode ops: " + str(len(ops)))

    # The decompiled C shows "(param_1->_Mypair)._Myval2._Myfirst"
    # Let's see how this is represented in pcode
    # It's probably a series of PTRSUB/LOAD operations

    # Look for patterns involving the parameter
    print("\n  Looking for operations on parameter...")
    param_ops = []
    for op in ops:
        # Check if any input is a parameter
        for i in range(op.getNumInputs()):
            input_vn = op.getInput(i)
            if input_vn and input_vn.isInput():
                param_ops.append(op)
                break

    print("  Operations using parameters: " + str(len(param_ops)))

    # Show some LOAD operations
    print("\n  Sample LOAD operations:")
    load_count = 0
    for op in ops:
        if op.getOpcode() == PcodeOp.LOAD and load_count < 10:
            load_count += 1
            print("  LOAD #" + str(load_count) + ":")
            if op.getNumInputs() >= 2:
                space = op.getInput(0)
                addr = op.getInput(1)
                print("    Address varnode: " + str(addr))
                # Check what defines the address
                addr_def = addr.getDef()
                if addr_def:
                    print("    Address defined by: " + addr_def.getMnemonic())

    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Debug Complete")
print("=" * 80)
