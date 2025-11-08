# List all functions in the binary
#@category Testing

print("All functions in binary:")
for func in currentProgram.getFunctionManager().getFunctions(True):
    name = func.getName()
    print("  - " + name)
