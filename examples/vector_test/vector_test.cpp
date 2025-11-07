#include <vector>
#include <iostream>
#include <algorithm>

// Pattern 1: vec.size() -> (field_0x10 - field_0x8) / element_size
size_t TestVectorSize(const std::vector<int>& vec) {
    return vec.size();
}

// Pattern 2: vec.empty() -> field_0x10 == field_0x8
bool TestVectorEmpty(const std::vector<int>& vec) {
    return vec.empty();
}

// Pattern 3: vec.data() -> field_0x8
const int* TestVectorData(const std::vector<int>& vec) {
    return vec.data();
}

// Pattern 4: vec.capacity() -> (field_0x18 - field_0x8) / element_size
size_t TestVectorCapacity(const std::vector<int>& vec) {
    return vec.capacity();
}

// Pattern 5: vec.reserve() -> capacity check (field_0x18 - field_0x8) < requested
void TestVectorReserve(std::vector<int>& vec, size_t n) {
    vec.reserve(n);
}

// Pattern 6: vec.resize() -> capacity and size checks
void TestVectorResize(std::vector<int>& vec, size_t n) {
    vec.resize(n);
}

// Pattern 7: vec.push_back() -> field_0x10 increment, capacity check
void TestVectorPushBack(std::vector<int>& vec, int value) {
    vec.push_back(value);
}

// Pattern 8: vec.clear() -> field_0x10 = field_0x8 (size becomes 0)
void TestVectorClear(std::vector<int>& vec) {
    vec.clear();
}

// Pattern 9: vec[index] with computed index -> *(field_0x8 + index * element_size)
int TestVectorIndexing(const std::vector<int>& vec, size_t idx) {
    if (idx < vec.size()) {
        return vec[idx];
    }
    return 0;
}

// Pattern 10: vec.begin() and vec.end() -> field_0x8 and field_0x10
int TestVectorIterators(const std::vector<int>& vec) {
    int sum = 0;
    for (auto it = vec.begin(); it != vec.end(); ++it) {
        sum += *it;
    }
    return sum;
}

// Pattern 11: vec.front() -> *field_0x8
int TestVectorFront(const std::vector<int>& vec) {
    if (!vec.empty()) {
        return vec.front();
    }
    return 0;
}

// Pattern 12: vec.back() -> *(field_0x10 - element_size)
int TestVectorBack(const std::vector<int>& vec) {
    if (!vec.empty()) {
        return vec.back();
    }
    return 0;
}

// Pattern 13: vec.pop_back() -> field_0x10 decrement
void TestVectorPopBack(std::vector<int>& vec) {
    if (!vec.empty()) {
        vec.pop_back();
    }
}

// Pattern 14: vec.shrink_to_fit() -> field_0x18 adjustment
void TestVectorShrinkToFit(std::vector<int>& vec) {
    vec.shrink_to_fit();
}

// Pattern 15: vector swap -> field-to-field copy
void TestVectorSwap(std::vector<int>& vec1, std::vector<int>& vec2) {
    vec1.swap(vec2);
}

// Pattern 16: vector assignment -> multiple field operations
std::vector<int> TestVectorAssignment(const std::vector<int>& source) {
    std::vector<int> dest;
    dest = source;
    return dest;
}

// Pattern 17: Complex operations combining multiple patterns
int TestComplexOperations(std::vector<int>& vec) {
    // Size check
    if (vec.empty()) {
        return -1;
    }

    // Capacity check and reserve
    if (vec.capacity() < 20) {
        vec.reserve(20);
    }

    // Multiple pushes trigger capacity checks and field increments
    for (int i = 0; i < 5; i++) {
        vec.push_back(i * 10);
    }

    // Iteration with pointer arithmetic
    int sum = 0;
    const int* data = vec.data();
    for (size_t i = 0; i < vec.size(); i++) {
        sum += data[i];
    }

    // Resize triggers capacity and size checks
    size_t old_size = vec.size();
    vec.resize(old_size + 10);

    // Back and pop operations
    int last = vec.back();
    vec.pop_back();

    return sum + last;
}

// Pattern 18: Vector in struct (nested field access)
struct VectorContainer {
    std::vector<int> data;
    int count;
};

int TestNestedVectorAccess(VectorContainer& container) {
    // Nested access: container.data.field_0x8, etc.
    if (!container.data.empty()) {
        container.count = static_cast<int>(container.data.size());
        container.data.reserve(container.count * 2);
        return container.data[0];
    }
    return 0;
}

// Main to prevent aggressive optimization
int main(int argc, char** argv) {
    std::vector<int> vec1 = {1, 2, 3, 4, 5};
    std::vector<int> vec2;

    // Execute all test functions
    size_t size = TestVectorSize(vec1);
    bool empty = TestVectorEmpty(vec1);
    const int* data = TestVectorData(vec1);
    size_t cap = TestVectorCapacity(vec1);

    TestVectorReserve(vec1, 20);
    TestVectorResize(vec1, 10);
    TestVectorPushBack(vec1, 100);

    int front = TestVectorFront(vec1);
    int back = TestVectorBack(vec1);
    int indexed = TestVectorIndexing(vec1, 2);
    int iter_sum = TestVectorIterators(vec1);

    TestVectorPopBack(vec1);
    TestVectorShrinkToFit(vec1);
    TestVectorSwap(vec1, vec2);

    std::vector<int> vec3 = TestVectorAssignment(vec1);
    int complex_result = TestComplexOperations(vec1);

    VectorContainer container;
    container.data = {10, 20, 30};
    int nested_result = TestNestedVectorAccess(container);

    TestVectorClear(vec1);

    // Use variables to prevent dead code elimination
    return static_cast<int>(size + cap + front + back + indexed +
                           iter_sum + complex_result + nested_result +
                           (empty ? 0 : 1));
}
