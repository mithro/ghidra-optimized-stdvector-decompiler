# Debug the new tracing logic
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

# Try to import the extension
try:
    from vectorsimplify import VectorSimplifyingDecompiler, VectorPatternMatcher
    EXTENSION_AVAILABLE = True
except ImportError:
    EXTENSION_AVAILABLE = False
    print("ERROR: Extension not available")
    exit(1)

print("=" * 80)
print("DEBUG: Tracing Logic")
print("=" * 80)

decompiler = VectorSimplifyingDecompiler()
decompiler.openProgram(currentProgram)

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

    # Find PTRSUB operations with offset 0x8, 0x10, or 0x18
    ptrsub_count = 0
    for op in ops:
        if op.getOpcode() == PcodeOp.PTRSUB:
            if op.getNumInputs() >= 2:
                offsetVarnode = op.getInput(1)
                if offsetVarnode.isConstant():
                    offset = offsetVarnode.getOffset()
                    if offset == 0x8 or offset == 0x10 or offset == 0x18:
                        ptrsub_count += 1
                        print("\n  Found PTRSUB with offset 0x" + hex(offset)[2:])

                        baseVarnode = op.getInput(0)
                        print("    Base varnode: " + str(baseVarnode))

                        # Check type on base
                        highVar = baseVarnode.getHigh()
                        if highVar is not None:
                            dt = highVar.getDataType()
                            print("    Base type: " + (dt.getName() if dt is not None else "None"))

                        # Trace back to find source
                        print("    Tracing back...")
                        current = baseVarnode
                        for depth in range(10):
                            defOp = current.getDef()
                            if defOp is None:
                                print("      Depth " + str(depth) + ": No def (input/free)")
                                # Check type here
                                hv = current.getHigh()
                                if hv is not None:
                                    dt = hv.getDataType()
                                    if dt is not None:
                                        print("        Type: " + dt.getName())
                                        print("        Path: " + dt.getPathName())
                                        if "vector" in dt.getName().lower() or "vector" in dt.getPathName().lower():
                                            print("        *** FOUND VECTOR TYPE! ***")
                                break

                            print("      Depth " + str(depth) + ": " + defOp.getMnemonic() + " (opcode " + str(defOp.getOpcode()) + ")")

                            # Check type at this level
                            hv = current.getHigh()
                            if hv is not None:
                                dt = hv.getDataType()
                                if dt is not None:
                                    print("        Type: " + dt.getName())
                                    if "vector" in dt.getName().lower():
                                        print("        *** FOUND VECTOR TYPE! ***")
                                        break

                            opcode = defOp.getOpcode()
                            if opcode == PcodeOp.COPY or opcode == PcodeOp.CAST:
                                if defOp.getNumInputs() > 0:
                                    current = defOp.getInput(0)
                                    continue
                            elif opcode == PcodeOp.PTRSUB or opcode == PcodeOp.PTRADD:
                                if defOp.getNumInputs() > 0:
                                    current = defOp.getInput(0)
                                    continue
                            elif opcode == PcodeOp.LOAD:
                                if defOp.getNumInputs() > 1:
                                    current = defOp.getInput(1)
                                    continue

                            print("        Can't trace further (opcode " + str(opcode) + ")")
                            break

                        if ptrsub_count >= 3:
                            break  # Don't spam too much

    print("\n  Total PTRSUB with vector offsets: " + str(ptrsub_count))
    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Debug Complete")
print("=" * 80)
