# Detailed pcode flow analysis
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

print("=" * 80)
print("DETAILED PCODE FLOW ANALYSIS")
print("=" * 80)

# Analyze TestComplexOperations
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

    # Get decompiled code for reference
    code = results.getDecompiledFunction().getC()
    print("\nDecompiled Code Snippet:")
    print("-" * 40)
    lines = code.split("\n")[:30]
    for line in lines:
        print(line)
    print("-" * 40)

    ops = list(highFunc.getPcodeOps())

    # Find INT_EQUAL operations (for empty check)
    print("\n\n=== INT_EQUAL Operations (vector.empty() pattern) ===")
    equal_count = 0
    for op in ops:
        if op.getOpcode() == PcodeOp.INT_EQUAL:
            equal_count += 1
            if equal_count > 3:  # Only show first 3
                continue

            print("\nINT_EQUAL #" + str(equal_count) + ":")
            print("  Address: " + str(op.getSeqnum().getTarget()))

            if op.getNumInputs() >= 2:
                v1 = op.getInput(0)
                v2 = op.getInput(1)

                print("  Operand 1: " + str(v1))
                print("    Is constant: " + str(v1.isConstant()))
                if v1.getHigh():
                    dt = v1.getHigh().getDataType()
                    print("    Type: " + (dt.getName() if dt else "null"))

                v1def = v1.getDef()
                if v1def:
                    print("    Defined by: " + v1def.getMnemonic() + " (opcode " + str(v1def.getOpcode()) + ")")

                    # If it's a LOAD, show details
                    if v1def.getOpcode() == PcodeOp.LOAD:
                        print("      >>> THIS IS A LOAD! <<<")
                        if v1def.getNumInputs() >= 2:
                            addr_vn = v1def.getInput(1)
                            print("      Loading from: " + str(addr_vn))

                            addr_def = addr_vn.getDef()
                            if addr_def:
                                print("      Address defined by: " + addr_def.getMnemonic())
                                if addr_def.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                                    if addr_def.getNumInputs() >= 2:
                                        base = addr_def.getInput(0)
                                        offset_vn = addr_def.getInput(1)
                                        if offset_vn.isConstant():
                                            offset = offset_vn.getOffset()
                                            print("      >>> PTRSUB offset: 0x" + hex(offset)[2:] + " <<<")

                                            # Check base type
                                            if base.getHigh():
                                                base_dt = base.getHigh().getDataType()
                                                if base_dt:
                                                    print("      >>> Base type: " + base_dt.getName() + " <<<")
                                                    if "vector" in base_dt.getName().lower():
                                                        print("      >>> VECTOR TYPE FOUND! <<<")

                print("\n  Operand 2: " + str(v2))
                print("    Is constant: " + str(v2.isConstant()))
                if v2.getHigh():
                    dt = v2.getHigh().getDataType()
                    print("    Type: " + (dt.getName() if dt else "null"))

                v2def = v2.getDef()
                if v2def:
                    print("    Defined by: " + v2def.getMnemonic() + " (opcode " + str(v2def.getOpcode()) + ")")

                    # If it's a LOAD, show details
                    if v2def.getOpcode() == PcodeOp.LOAD:
                        print("      >>> THIS IS A LOAD! <<<")
                        if v2def.getNumInputs() >= 2:
                            addr_vn = v2def.getInput(1)
                            print("      Loading from: " + str(addr_vn))

                            addr_def = addr_vn.getDef()
                            if addr_def:
                                print("      Address defined by: " + addr_def.getMnemonic())
                                if addr_def.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                                    if addr_def.getNumInputs() >= 2:
                                        base = addr_def.getInput(0)
                                        offset_vn = addr_def.getInput(1)
                                        if offset_vn.isConstant():
                                            offset = offset_vn.getOffset()
                                            print("      >>> PTRSUB offset: 0x" + hex(offset)[2:] + " <<<")

                                            # Check base type
                                            if base.getHigh():
                                                base_dt = base.getHigh().getDataType()
                                                if base_dt:
                                                    print("      >>> Base type: " + base_dt.getName() + " <<<")
                                                    if "vector" in base_dt.getName().lower():
                                                        print("      >>> VECTOR TYPE FOUND! <<<")

    # Find INT_RIGHT operations (for size check)
    print("\n\n=== INT_RIGHT Operations (vector.size() pattern) ===")
    shift_count = 0
    for op in ops:
        if op.getOpcode() == PcodeOp.INT_RIGHT:
            shift_count += 1
            if shift_count > 2:  # Only show first 2
                continue

            print("\nINT_RIGHT #" + str(shift_count) + ":")
            print("  Address: " + str(op.getSeqnum().getTarget()))

            if op.getNumInputs() >= 2:
                v1 = op.getInput(0)  # Should be subtraction
                v2 = op.getInput(1)  # Shift amount

                print("  Shift input: " + str(v1))
                print("  Shift amount: " + str(v2))
                if v2.isConstant():
                    print("    Shift by: " + str(v2.getOffset()))

                v1def = v1.getDef()
                if v1def:
                    print("  Input defined by: " + v1def.getMnemonic() + " (opcode " + str(v1def.getOpcode()) + ")")

                    if v1def.getOpcode() == PcodeOp.INT_SUB:
                        print("    >>> THIS IS A SUB! <<<")
                        if v1def.getNumInputs() >= 2:
                            sub_v1 = v1def.getInput(0)
                            sub_v2 = v1def.getInput(1)

                            print("    SUB operand 1: " + str(sub_v1))
                            sub_v1def = sub_v1.getDef()
                            if sub_v1def:
                                print("      Defined by: " + sub_v1def.getMnemonic())

                                # Check if it's a LOAD
                                if sub_v1def.getOpcode() == PcodeOp.LOAD:
                                    print("        >>> LOAD FOUND! <<<")
                                    if sub_v1def.getNumInputs() >= 2:
                                        addr_vn = sub_v1def.getInput(1)
                                        addr_def = addr_vn.getDef()
                                        if addr_def and addr_def.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                                            if addr_def.getNumInputs() >= 2:
                                                offset_vn = addr_def.getInput(1)
                                                if offset_vn.isConstant():
                                                    print("        >>> Offset: 0x" + hex(offset_vn.getOffset())[2:] + " <<<")

                            print("    SUB operand 2: " + str(sub_v2))
                            sub_v2def = sub_v2.getDef()
                            if sub_v2def:
                                print("      Defined by: " + sub_v2def.getMnemonic())

                                # Check if it's a LOAD
                                if sub_v2def.getOpcode() == PcodeOp.LOAD:
                                    print("        >>> LOAD FOUND! <<<")
                                    if sub_v2def.getNumInputs() >= 2:
                                        addr_vn = sub_v2def.getInput(1)
                                        addr_def = addr_vn.getDef()
                                        if addr_def and addr_def.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                                            if addr_def.getNumInputs() >= 2:
                                                offset_vn = addr_def.getInput(1)
                                                if offset_vn.isConstant():
                                                    print("        >>> Offset: 0x" + hex(offset_vn.getOffset())[2:] + " <<<")

    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Complete")
print("=" * 80)
