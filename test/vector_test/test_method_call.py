# Test if VectorPatternMatcher.testMethod() works
#@category Testing

print("=" * 80)
print("TEST METHOD CALL")
print("=" * 80)

import os

# Clean up
if os.path.exists("/tmp/patternmatcher_test.txt"):
    os.remove("/tmp/patternmatcher_test.txt")
    print("Removed old test file")

# Import and create
from vectorsimplify import VectorPatternMatcher
matcher = VectorPatternMatcher()
print("Matcher created: " + str(matcher))

# Call testMethod
print("\nCalling testMethod()...")
matcher.testMethod()
print("testMethod() returned")

# Check if file was created
if os.path.exists("/tmp/patternmatcher_test.txt"):
    print("\nSUCCESS! File created:")
    with open("/tmp/patternmatcher_test.txt", 'r') as f:
        print(f.read())
else:
    print("\nFAILED! File not created")

print("\nComplete")
