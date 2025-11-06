# Test SimpleTest class to isolate integration issues
#@category Testing

print("=" * 80)
print("SIMPLE TEST - Isolating Jython Integration Issue")
print("=" * 80)

# Clean up old test files
import os
test_files = [
    '/tmp/simple_test_basic.txt',
    '/tmp/simple_test_return.txt',
    '/tmp/simple_test_list.txt',
    '/tmp/simple_test_empty_list.txt',
    '/tmp/simple_test_param.txt'
]

print("\n[CLEANUP] Removing old test files...")
for f in test_files:
    if os.path.exists(f):
        os.remove(f)
        print("  Removed: " + f)

# Import the test class
print("\n[IMPORT] Importing SimpleTest...")
try:
    from vectorsimplify import SimpleTest
    print("  SUCCESS - SimpleTest imported")
except Exception as e:
    print("  FAILED: " + str(e))
    exit(1)

# Create instance
print("\n[INSTANTIATE] Creating SimpleTest instance...")
try:
    tester = SimpleTest()
    print("  SUCCESS - Instance: " + str(tester))
except Exception as e:
    print("  FAILED: " + str(e))
    exit(1)

# Test 1: Basic method
print("\n[TEST 1] Calling testBasic()...")
try:
    tester.testBasic()
    print("  Method returned")
    if os.path.exists('/tmp/simple_test_basic.txt'):
        with open('/tmp/simple_test_basic.txt', 'r') as f:
            print("  File contents: " + f.read().strip())
        print("  RESULT: SUCCESS - Method body executed!")
    else:
        print("  RESULT: FAILED - File not created, body didn't execute")
except Exception as e:
    print("  EXCEPTION: " + str(e))

# Test 2: Method with return value
print("\n[TEST 2] Calling testWithReturn()...")
try:
    result = tester.testWithReturn()
    print("  Return value: " + str(result))
    if os.path.exists('/tmp/simple_test_return.txt'):
        with open('/tmp/simple_test_return.txt', 'r') as f:
            print("  File contents: " + f.read().strip())
        print("  RESULT: SUCCESS - Method body executed!")
    else:
        print("  RESULT: FAILED - File not created, body didn't execute")
except Exception as e:
    print("  EXCEPTION: " + str(e))

# Test 3: Method returning List
print("\n[TEST 3] Calling testWithList()...")
try:
    result = tester.testWithList()
    print("  Return value: " + str(result))
    print("  Return type: " + str(type(result)))
    print("  List size: " + str(len(result)))
    if os.path.exists('/tmp/simple_test_list.txt'):
        with open('/tmp/simple_test_list.txt', 'r') as f:
            print("  File contents: " + f.read().strip())
        print("  RESULT: SUCCESS - Method body executed!")
    else:
        print("  RESULT: FAILED - File not created, body didn't execute")
except Exception as e:
    print("  EXCEPTION: " + str(e))

# Test 4: Method returning empty List (like our problem!)
print("\n[TEST 4] Calling testWithEmptyList()...")
try:
    result = tester.testWithEmptyList()
    print("  Return value: " + str(result))
    print("  Return type: " + str(type(result)))
    print("  List size: " + str(len(result)))
    if os.path.exists('/tmp/simple_test_empty_list.txt'):
        with open('/tmp/simple_test_empty_list.txt', 'r') as f:
            print("  File contents: " + f.read().strip())
        print("  RESULT: SUCCESS - Method body executed!")
    else:
        print("  RESULT: FAILED - File not created, body didn't execute")
except Exception as e:
    print("  EXCEPTION: " + str(e))

# Test 5: Method with parameter
print("\n[TEST 5] Calling testWithParameter('hello')...")
try:
    result = tester.testWithParameter("hello")
    print("  Return value: " + str(result))
    print("  Return type: " + str(type(result)))
    print("  List size: " + str(len(result)))
    if os.path.exists('/tmp/simple_test_param.txt'):
        with open('/tmp/simple_test_param.txt', 'r') as f:
            print("  File contents: " + f.read().strip())
        print("  RESULT: SUCCESS - Method body executed!")
    else:
        print("  RESULT: FAILED - File not created, body didn't execute")
except Exception as e:
    print("  EXCEPTION: " + str(e))

print("\n" + "=" * 80)
print("SIMPLE TEST COMPLETE")
print("=" * 80)
