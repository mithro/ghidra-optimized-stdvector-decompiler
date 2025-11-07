# Debug LOAD operations to see how _Myfirst/_Mylast/_Myend are accessed
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("DEBUG: LOAD Operations Accessing Vector Members")
print("=" * 80)

# Analyze Test Complex Operations
for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nAnalyzing: " + func.getName())
    print("-" * 80)

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        continue

    highFunc = results.getHighFunction()
    if highFunc == None:
        continue

    ops = list(highFunc.getPcodeOps())

    # Find LOAD operations
    load_ops = [op for op in ops if op.getOpcode() == PcodeOp.LOAD]
    print("  Total LOAD operations: " + str(len(load_ops)))

    # Look at first 15 LOADs
    for i, op in enumerate(load_ops[:15]):
        if op.getNumInputs() >= 2:
            addr_vn = op.getInput(1)

            print("\n  LOAD #" + str(i+1) + ":")
            print("    Address: " + str(addr_vn))

            # Check what defines the address
            addr_def = addr_vn.getDef()
            if addr_def:
                print("    Defined by: " + addr_def.getMnemonic() + " (opcode " + str(addr_def.getOpcode()) + ")")

                # If it's PTRSUB, show the offset
                if addr_def.getOpcode() == PcodeOp.PTRSUB and addr_def.getNumInputs() >= 2:
                    base = addr_def.getInput(0)
                    offset_vn = addr_def.getInput(1)

                    if offset_vn.isConstant():
                        offset = offset_vn.getOffset()
                        print("      PTRSUB offset: 0x" + hex(offset)[2:])

                    # Check type of base
                    base_high = base.getHigh()
                    if base_high:
                        base_dt = base_high.getDataType()
                        if base_dt:
                            print("      Base type: " + base_dt.getName())

                # If it's COPY, trace further
                elif addr_def.getOpcode() == PcodeOp.COPY and addr_def.getNumInputs() >= 1:
                    copy_input = addr_def.getInput(0)
                    print("      COPY from: " + str(copy_input))

                    copy_def = copy_input.getDef()
                    if copy_def:
                        print("        Defined by: " + copy_def.getMnemonic())

                        if copy_def.getOpcode() == PcodeOp.PTRSUB and copy_def.getNumInputs() >= 2:
                            offset_vn2 = copy_def.getInput(1)
                            if offset_vn2.isConstant():
                                print("          PTRSUB offset: 0x" + hex(offset_vn2.getOffset())[2:])
            else:
                # No definition - might be a parameter or input
                print("    No def - input/parameter")
                high = addr_vn.getHigh()
                if high:
                    dt = high.getDataType()
                    if dt:
                        print("      Type: " + dt.getName())

    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Complete")
print("=" * 80)
