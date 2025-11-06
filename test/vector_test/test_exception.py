# Test if exceptions show up
#@category Testing

from ghidra.app.decompiler import DecompInterface
from vectorsimplify import VectorPatternMatcher

print("=" * 80)
print("EXCEPTION TEST")
print("=" * 80)

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    print("\nTesting: " + func.getName())

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        break

    highFunc = results.getHighFunction()
    if highFunc == None:
        break

    # Call pattern matcher and catch any exceptions
    try:
        matcher = VectorPatternMatcher()
        print("Matcher created")
        patterns = matcher.findVectorPatterns(highFunc)
        print("Patterns found: " + str(len(patterns)))

        # Try to access the HighFunction to verify it's valid
        ops = list(highFunc.getPcodeOps())
        print("Total ops: " + str(len(ops)))

        # Count INT_EQUAL operations
        from ghidra.program.model.pcode import PcodeOp
        equals = [op for op in ops if op.getOpcode() == PcodeOp.INT_EQUAL]
        print("INT_EQUAL ops: " + str(len(equals)))

    except Exception as e:
        print("ERROR: " + str(e))
        import traceback
        traceback.print_exc()

    break

decompiler.dispose()
print("\nComplete")
