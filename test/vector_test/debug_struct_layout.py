# Check the actual struct layout for vector type
#@category Testing

from ghidra.program.model.data import Structure

program = currentProgram
dtm = program.getDataTypeManager()

print("=" * 80)
print("Vector Structure Layout")
print("=" * 80)

# Find vector type
vector_types = []
for dt in dtm.getAllDataTypes():
    name = dt.getName()
    if "vector<int" in name and "allocator" in name:
        vector_types.append(dt)
        print("\nFound type: " + dt.getPathName())
        print("  Name: " + name)
        print("  Size: " + str(dt.getLength()))

        if isinstance(dt, Structure):
            struct = dt
            print("  Components:")
            for comp in struct.getComponents():
                print("    Offset 0x" + hex(comp.getOffset())[2:] + ": " +
                      comp.getFieldName() + " (" + comp.getDataType().getName() + ")")

# Also look for _Compressed_pair, _Vector_val, etc.
print("\n" + "=" * 80)
print("Related Types:")
print("=" * 80)

for dt in dtm.getAllDataTypes():
    name = dt.getName()
    if ("Compressed_pair" in name or "Vector_val" in name or "_Mypair" in name) and "int" in name:
        print("\nType: " + dt.getPathName())
        print("  Size: " + str(dt.getLength()))

        if isinstance(dt, Structure):
            struct = dt
            print("  Components:")
            for comp in struct.getComponents():
                print("    Offset 0x" + hex(comp.getOffset())[2:] + ": " +
                      comp.getFieldName() + " (" + comp.getDataType().getName() + ")")

print("\n" + "=" * 80)
print("Complete")
print("=" * 80)
