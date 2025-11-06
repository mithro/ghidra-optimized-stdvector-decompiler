# Test if we can write files from Python/Java
#@category Testing

print("Testing file writing...")

# Test 1: Python file write
print("\n[TEST 1] Python file write:")
try:
    with open('/tmp/python_write_test.txt', 'w') as f:
        f.write("Python can write!\n")
    print("  SUCCESS - Python can write to /tmp")
except Exception as e:
    print("  FAILED: " + str(e))

# Test 2: Java file write from Python
print("\n[TEST 2] Java FileWriter from Python:")
try:
    from java.io import FileWriter
    fw = FileWriter("/tmp/java_write_test.txt")
    fw.write("Java can write!\n")
    fw.close()
    print("  SUCCESS - Java FileWriter works from Python")
except Exception as e:
    print("  FAILED: " + str(e))

# Test 3: Check if our test file exists
print("\n[TEST 3] Checking if test files were created:")
import os
if os.path.exists('/tmp/python_write_test.txt'):
    print("  Python file: EXISTS")
else:
    print("  Python file: NOT FOUND")

if os.path.exists('/tmp/java_write_test.txt'):
    print("  Java file: EXISTS")
else:
    print("  Java file: NOT FOUND")

print("\nDone")
