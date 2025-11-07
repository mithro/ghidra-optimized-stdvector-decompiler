# Test isVectorType logic manually
#@category Testing

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.data import Pointer

print("=" * 80)
print("TEST isVectorType LOGIC")
print("=" * 80)

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

for func in currentProgram.getFunctionManager().getFunctions(True):
    if "TestComplexOperations" not in func.getName():
        continue

    results = decompiler.decompileFunction(func, 30, monitor)
    if not results.decompileCompleted():
        break

    highFunc = results.getHighFunction()
    ops = list(highFunc.getPcodeOps())

    # Find first INT_EQUAL with LOAD operands
    for op in ops:
        if op.getOpcode() == PcodeOp.INT_EQUAL:
            if op.getNumInputs() >= 2:
                operand1 = op.getInput(0)
                defOp1 = operand1.getDef()

                if defOp1 and defOp1.getOpcode() == PcodeOp.LOAD:
                    if defOp1.getNumInputs() >= 2:
                        addrVn = defOp1.getInput(1)
                        addrDef = addrVn.getDef()

                        if addrDef and addrDef.getOpcode() in [PcodeOp.PTRSUB, PcodeOp.PTRADD]:
                            if addrDef.getNumInputs() >= 2:
                                base = addrDef.getInput(0)

                                print("\nTesting isVectorType logic on base varnode")
                                print("Base varnode: " + str(base))

                                # Replicate isVectorType logic
                                highVar = base.getHigh()
                                print("  Has HighVariable: " + str(highVar is not None))

                                if highVar:
                                    dataType = highVar.getDataType()
                                    print("  Has DataType: " + str(dataType is not None))

                                    if dataType:
                                        typeName = dataType.getName()
                                        print("  Type name: " + str(typeName))

                                        if typeName:
                                            print("  Contains 'vector<': " + str("vector<" in typeName))
                                            print("  Contains 'vector_': " + str("vector_" in typeName))
                                            print("  Contains 'Vector_val': " + str("Vector_val" in typeName))

                                            matches = "vector<" in typeName or "vector_" in typeName or "Vector_val" in typeName
                                            print("  >>> Matches vector type: " + str(matches) + " <<<")

                                        # Check for pointer type
                                        print("  Is Pointer: " + str(isinstance(dataType, Pointer)))
                                        if isinstance(dataType, Pointer):
                                            ptrType = dataType
                                            pointedType = ptrType.getDataType()
                                            if pointedType:
                                                pointedName = pointedType.getName()
                                                print("  Pointed type: " + str(pointedName))
                                                if pointedName:
                                                    print("  Pointed contains 'Vector_val': " + str("Vector_val" in pointedName))

                                # Only check first one
                                break
            break
    break

decompiler.dispose()
print("\nComplete")
