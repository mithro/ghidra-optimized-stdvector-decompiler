# Check _Vector_val structure
#@category Testing

from ghidra.program.model.data import Structure

program = currentProgram
dtm = program.getDataTypeManager()

print("=" * 80)
print("_Vector_val Structure")
print("=" * 80)

# Find _Vector_val type
for dt in dtm.getAllDataTypes():
    name = dt.getName()
    if "_Vector_val" in name and "int" in name and "Simple" in name:
        print("\nType: " + dt.getPathName())
        print("  Size: " + str(dt.getLength()))

        if isinstance(dt, Structure):
            struct = dt
            print("  Components:")
            for comp in struct.getComponents():
                offset_hex = "0x" + hex(comp.getOffset())[2:]
                field_name = comp.getFieldName() if comp.getFieldName() else "<unnamed>"
                type_name = comp.getDataType().getName()
                print("    Offset " + offset_hex + ": " + field_name + " (" + type_name + ")")

                # If this component is also a structure, show its contents
                comp_dt = comp.getDataType()
                if isinstance(comp_dt, Structure):
                    for sub_comp in comp_dt.getComponents():
                        sub_offset_hex = "0x" + hex(sub_comp.getOffset())[2:]
                        sub_field = sub_comp.getFieldName() if sub_comp.getFieldName() else "<unnamed>"
                        sub_type = sub_comp.getDataType().getName()
                        print("      Offset " + sub_offset_hex + ": " + sub_field + " (" + sub_type + ")")

print("\n" + "=" * 80)
print("Complete")
print("=" * 80)
