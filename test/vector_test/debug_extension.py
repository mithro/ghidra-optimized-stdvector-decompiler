# Debug vector simplification - why isn't it working?
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp

# Try to import the VectorSimplification extension
try:
    from vectorsimplify import VectorSimplifyingDecompiler, VectorPatternMatcher
    EXTENSION_AVAILABLE = True
except ImportError:
    EXTENSION_AVAILABLE = False
    print("ERROR: Extension not available")
    exit(1)

print("=" * 80)
print("DEBUG: Extension Pattern Matching")
print("=" * 80)

decompiler = VectorSimplifyingDecompiler()
decompiler.openProgram(currentProgram)

# Look at main() or TestComplexOperations
target = "main"
for func in currentProgram.getFunctionManager().getFunctions(True):
    if target not in func.getName():
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

    print("  High function: OK")

    # Check pcode operations
    ops = list(highFunc.getPcodeOps())
    print("  Total pcode ops: " + str(len(ops)))

    # Count operation types we care about
    right_shifts = 0
    equals = 0
    subs = 0
    ptrsubs = 0

    for op in ops:
        opcode = op.getOpcode()
        if opcode == PcodeOp.INT_RIGHT:
            right_shifts += 1
        elif opcode == PcodeOp.INT_EQUAL:
            equals += 1
        elif opcode == PcodeOp.INT_SUB:
            subs += 1
        elif opcode == PcodeOp.PTRSUB:
            ptrsubs += 1

    print("  INT_RIGHT ops (>>): " + str(right_shifts))
    print("  INT_EQUAL ops (==): " + str(equals))
    print("  INT_SUB ops (-): " + str(subs))
    print("  PTRSUB ops: " + str(ptrsubs))

    # Try the pattern matcher
    matcher = VectorPatternMatcher()
    patterns = matcher.findVectorPatterns(highFunc)

    print("\n  Patterns found: " + str(len(patterns)))

    if len(patterns) == 0:
        print("\n  Why no patterns? Let's check manually...")

        # Look for right shift operations
        for op in ops:
            if op.getOpcode() == PcodeOp.INT_RIGHT:
                print("\n  Found INT_RIGHT:")
                if op.getNumInputs() >= 1:
                    input0 = op.getInput(0)
                    print("    Input 0: " + str(input0))

                    if input0 is not None:
                        defOp = input0.getDef()
                        if defOp is not None:
                            print("    Input 0 def op: " + str(defOp.getOpcode()) +
                                  " (" + str(defOp.getMnemonic()) + ")")

                            if defOp.getOpcode() == PcodeOp.INT_SUB:
                                print("    Found SUB feeding RIGHT SHIFT!")

                                if defOp.getNumInputs() >= 2:
                                    v1 = defOp.getInput(0)
                                    v2 = defOp.getInput(1)

                                    print("      SUB input 0: " + str(v1))
                                    if v1 is not None:
                                        high1 = v1.getHigh()
                                        print("        High var: " + str(high1))
                                        if high1 is not None:
                                            dt = high1.getDataType()
                                            print("          Data type: " + str(dt))
                                            if dt is not None:
                                                print("          Type name: " + dt.getName())

                                    print("      SUB input 1: " + str(v2))
                                    if v2 is not None:
                                        high2 = v2.getHigh()
                                        print("        High var: " + str(high2))
                                        if high2 is not None:
                                            dt = high2.getDataType()
                                            print("          Data type: " + str(dt))
                                            if dt is not None:
                                                print("          Type name: " + dt.getName())

                                # Check what the subtraction operands are defined by
                                    v1def = v1.getDef() if v1 is not None else None
                                    v2def = v2.getDef() if v2 is not None else None

                                    if v1def is not None:
                                        print("      V1 defined by: " + str(v1def.getMnemonic()))
                                        print("         Opcode: " + str(v1def.getOpcode()))

                                    if v2def is not None:
                                        print("      V2 defined by: " + str(v2def.getMnemonic()))
                                        print("         Opcode: " + str(v2def.getOpcode()))

                # Only analyze first few to avoid spam
                break

    break

decompiler.dispose()

print("\n" + "=" * 80)
print("Debug Complete")
print("=" * 80)
