# Check what we're actually importing
#@category Testing

print("=" * 80)
print("IMPORT CHECK")
print("=" * 80)

try:
    from vectorsimplify import VectorPatternMatcher
    print("Import successful!")
    print("VectorPatternMatcher class: " + str(VectorPatternMatcher))
    print("VectorPatternMatcher module: " + str(VectorPatternMatcher.__module__))

    # Try to instantiate
    matcher = VectorPatternMatcher()
    print("Instance created: " + str(matcher))
    print("Instance class: " + str(matcher.__class__))

    # Check if findVectorPatterns method exists
    if hasattr(matcher, 'findVectorPatterns'):
        print("findVectorPatterns method exists!")
        print("Method: " + str(matcher.findVectorPatterns))
    else:
        print("ERROR: findVectorPatterns method NOT FOUND!")

except ImportError as e:
    print("ERROR: Import failed!")
    print("Error: " + str(e))

print("\n" + "=" * 80)
print("Complete")
print("=" * 80)
