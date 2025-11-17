#include <vector>
#include <iostream>
#include <cstdint>
#include <cstring>
#include "vector_realistic_helpers.h"

// Prevent optimization by using volatile and extern
extern "C" {
    // External functions that compiler can't inline or optimize away
    void consume_int(int x);
    void consume_ptr(void* p);
    int get_runtime_value();
}

// Dummy implementations (won't be called in Ghidra analysis, just prevent optimization)
void consume_int(int x) {
    volatile int tmp = x;
}
void consume_ptr(void* p) {
    volatile void* tmp = p;
}
int get_runtime_value() {
    return 42;
}

// Helper functions in separate compilation unit (vector_realistic_helpers.cpp)
// This prevents inlining and preserves vector type information

// Test 1: std::vector<int> - 4-byte elements
// Uses helper functions to preserve type information
int test_vector_int() {
    std::vector<int> vec;

    // Runtime-dependent size to prevent optimization
    int n = get_runtime_value();

    // Reserve capacity - direct call
    vec.reserve(n);

    // Call helper to test capacity (preserves type info)
    int cap = get_capacity_int(vec);
    consume_int(cap);

    // Test push_back and size
    for (int i = 0; i < n; i++) {
        vec.push_back(i * 2);
    }

    // Test empty via helper function (preserves type)
    if (!check_empty_int(vec)) {
        // Test size via helper (preserves type)
        int sz = get_size_int(vec);
        consume_int(sz);

        // Test data() via helper (preserves type)
        int* data = get_data_int(vec);
        consume_ptr(data);

        // Modify vector (non-const operation)
        modify_vector_int(vec, 999);

        // Test element access
        int sum = 0;
        for (int i = 0; i < sz && i < 100; i++) {
            sum += vec[i];
        }
        consume_int(sum);
    }

    return get_size_int(vec);
}

// Test 2: std::vector<int64_t> - 8-byte elements
// Uses helper functions to preserve type information
int64_t test_vector_int64() {
    std::vector<int64_t> vec;

    int n = get_runtime_value();

    // Reserve capacity
    vec.reserve(100);

    // Test capacity via helper (preserves type for 8-byte elements)
    int cap = get_capacity_int64(vec);
    consume_int(cap);

    // Test size calculations with 8-byte elements
    for (int i = 0; i < n; i++) {
        vec.push_back(static_cast<int64_t>(i) * 1000000);
    }

    // Test empty via helper
    if (!check_empty_int64(vec)) {
        // Test data pointer via helper
        int64_t* ptr = get_data_int64(vec);
        consume_ptr(ptr);

        // Modify (non-const)
        modify_vector_int64(vec, 12345678);

        // Calculate sum to force usage
        int64_t total = 0;
        int sz = get_size_int64(vec);
        for (int i = 0; i < sz && i < 100; i++) {
            total += vec[i];
        }
        return total;
    }

    return 0;
}

// Test 3: std::vector<double> - 8-byte elements, different type
// Uses helper functions to preserve type information
double test_vector_double() {
    std::vector<double> vec;

    int n = get_runtime_value();

    // Reserve to test capacity calculations
    vec.reserve(50);

    // Test capacity via helper
    int cap = get_capacity_double(vec);
    consume_int(cap);

    // Add elements
    for (int i = 0; i < n; i++) {
        vec.push_back(i * 3.14);
    }

    // Test empty via helper
    if (check_empty_double(vec)) {
        return 0.0;
    }

    // Test data via helper
    double* data = get_data_double(vec);
    consume_ptr(data);

    // Modify (non-const)
    modify_vector_double(vec, 2.718);

    // Compute average
    double sum = 0.0;
    int sz = get_size_double(vec);
    for (int i = 0; i < sz && i < 100; i++) {
        sum += data[i];
    }

    return sum / sz;
}

// Test 4: std::vector<char> - 1-byte elements
int test_vector_char() {
    std::vector<char> vec;

    const char* msg = "Test string with runtime length";
    int len = get_runtime_value() % 100;

    // Test capacity with 1-byte elements
    if (vec.capacity() < static_cast<size_t>(len)) {
        vec.reserve(len);
    }

    // Fill with data
    for (int i = 0; i < len; i++) {
        vec.push_back(msg[i % strlen(msg)]);
    }

    // Test size/empty/data
    if (!vec.empty()) {
        char* ptr = vec.data();
        consume_ptr(ptr);

        // Count specific character
        int count = 0;
        for (size_t i = 0; i < vec.size(); i++) {
            if (vec[i] == 'e') count++;
        }
        consume_int(count);
    }

    return static_cast<int>(vec.size());
}

// Test 5: std::vector<int16_t> - 2-byte elements
int test_vector_int16() {
    std::vector<int16_t> vec;

    int n = get_runtime_value();

    // Test reserve
    vec.reserve(200);

    // Add elements
    for (int i = 0; i < n; i++) {
        vec.push_back(static_cast<int16_t>(i % 32767));
    }

    // Test all operations
    if (vec.empty()) {
        return 0;
    }

    size_t cap = vec.capacity();
    size_t sz = vec.size();
    int16_t* data = vec.data();

    consume_ptr(data);
    consume_int(static_cast<int>(cap));
    consume_int(static_cast<int>(sz));

    return static_cast<int>(vec.size());
}

// Test 6: std::vector<void*> - pointer elements (8-byte on x64)
int test_vector_pointers() {
    std::vector<void*> vec;

    int n = get_runtime_value();

    // Test capacity
    if (vec.capacity() < 10) {
        vec.reserve(10);
    }

    // Add pointers
    int dummy_data[100];
    for (int i = 0; i < n && i < 100; i++) {
        vec.push_back(&dummy_data[i]);
    }

    // Test size/empty/data
    if (!vec.empty()) {
        void** ptr_array = vec.data();
        consume_ptr(ptr_array);

        // Access elements
        for (size_t i = 0; i < vec.size(); i++) {
            consume_ptr(vec[i]);
        }
    }

    return static_cast<int>(vec.size());
}

// Test 7: Complex structure - 16-byte elements
struct Point {
    double x;
    double y;
};

int test_vector_struct() {
    std::vector<Point> vec;

    int n = get_runtime_value();

    // Reserve capacity
    vec.reserve(50);

    // Add points
    for (int i = 0; i < n; i++) {
        Point p;
        p.x = i * 1.5;
        p.y = i * 2.5;
        vec.push_back(p);
    }

    // Test operations
    if (vec.empty()) {
        return 0;
    }

    Point* data = vec.data();
    consume_ptr(data);

    // Calculate distance sum
    double total_dist = 0.0;
    for (size_t i = 0; i < vec.size(); i++) {
        total_dist += vec[i].x + vec[i].y;
    }

    return static_cast<int>(total_dist);
}

// Test 8: Vector resizing operations
int test_vector_resize_operations() {
    std::vector<int> vec;

    int n = get_runtime_value();

    // Initial reserve
    vec.reserve(20);

    // Add elements
    for (int i = 0; i < n; i++) {
        vec.push_back(i);
    }

    size_t original_size = vec.size();

    // Resize larger
    vec.resize(original_size + 10);

    // Check size and capacity
    if (vec.size() > original_size && vec.capacity() >= vec.size()) {
        int* data = vec.data();
        consume_ptr(data);
    }

    // Resize smaller
    vec.resize(5);

    // Check empty
    if (!vec.empty()) {
        return static_cast<int>(vec.size());
    }

    return 0;
}

// Test 9: Vector with capacity checks
int test_capacity_management() {
    std::vector<int> vec;

    // Multiple reserve calls
    vec.reserve(10);
    size_t cap1 = vec.capacity();

    vec.reserve(50);
    size_t cap2 = vec.capacity();

    vec.reserve(100);
    size_t cap3 = vec.capacity();

    consume_int(static_cast<int>(cap1));
    consume_int(static_cast<int>(cap2));
    consume_int(static_cast<int>(cap3));

    // Fill to capacity
    int n = get_runtime_value();
    for (int i = 0; i < n && i < 100; i++) {
        vec.push_back(i);
    }

    // Check relationship
    if (vec.size() <= vec.capacity()) {
        return static_cast<int>(vec.capacity() - vec.size());
    }

    return 0;
}

// Test 10: Multiple vectors in same function
int test_multiple_vectors() {
    std::vector<int> vec1;
    std::vector<int> vec2;
    std::vector<int64_t> vec3;

    int n = get_runtime_value();

    // Operate on all three
    for (int i = 0; i < n; i++) {
        vec1.push_back(i);
        vec2.push_back(i * 2);
        vec3.push_back(static_cast<int64_t>(i) * 3);
    }

    // Check all three
    int result = 0;

    if (!vec1.empty()) {
        result += static_cast<int>(vec1.size());
        consume_ptr(vec1.data());
    }

    if (!vec2.empty()) {
        result += static_cast<int>(vec2.size());
        consume_ptr(vec2.data());
    }

    if (!vec3.empty()) {
        result += static_cast<int>(vec3.size());
        consume_ptr(vec3.data());
    }

    return result;
}

// ============================================================================
// Complex Structure Tests
// ============================================================================

// Test 11: std::vector<Point2D> - 16-byte elements
int test_vector_point2d() {
    std::vector<Point2D> vec;
    int n = get_runtime_value();

    vec.reserve(20);
    int cap = get_capacity_point2d(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 10; i++) {
        Point2D p;
        p.x = i * 1.5;
        p.y = i * 2.5;
        vec.push_back(p);
    }

    if (!check_empty_point2d(vec)) {
        int sz = get_size_point2d(vec);
        consume_int(sz);

        Point2D* data = get_data_point2d(vec);
        consume_ptr(data);

        Point2D newPoint = {10.0, 20.0};
        modify_vector_point2d(vec, newPoint);
    }

    return get_size_point2d(vec);
}

// Test 12: std::vector<BoundingBox> - 32-byte nested structure
int test_vector_bbox() {
    std::vector<BoundingBox> vec;
    int n = get_runtime_value();

    vec.reserve(15);
    int cap = get_capacity_bbox(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 8; i++) {
        BoundingBox box;
        box.min.x = i * 1.0;
        box.min.y = i * 1.0;
        box.max.x = (i + 1) * 10.0;
        box.max.y = (i + 1) * 10.0;
        vec.push_back(box);
    }

    if (!check_empty_bbox(vec)) {
        int sz = get_size_bbox(vec);
        consume_int(sz);

        BoundingBox* data = get_data_bbox(vec);
        consume_ptr(data);
    }

    return get_size_bbox(vec);
}

// Test 13: std::vector<Node> - structure with pointers
int test_vector_node() {
    std::vector<Node> vec;
    int n = get_runtime_value();

    vec.reserve(12);
    int cap = get_capacity_node(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 6; i++) {
        Node node;
        node.value = i * 100;
        node.next = nullptr;
        node.prev = nullptr;
        vec.push_back(node);
    }

    if (!check_empty_node(vec)) {
        int sz = get_size_node(vec);
        consume_int(sz);

        Node* data = get_data_node(vec);
        consume_ptr(data);
    }

    return get_size_node(vec);
}

// Test 14: std::vector<Transform> - structure with arrays (40 bytes)
int test_vector_transform() {
    std::vector<Transform> vec;
    int n = get_runtime_value();

    vec.reserve(10);
    int cap = get_capacity_transform(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 5; i++) {
        Transform t;
        for (int j = 0; j < 9; j++) {
            t.matrix[j] = static_cast<float>(i + j);
        }
        for (int j = 0; j < 3; j++) {
            t.translation[j] = static_cast<float>(i * j);
        }
        vec.push_back(t);
    }

    if (!check_empty_transform(vec)) {
        int sz = get_size_transform(vec);
        consume_int(sz);
    }

    return get_size_transform(vec);
}

// Test 15: std::vector<CacheBlock> - large 64-byte structure
int test_vector_cache() {
    std::vector<CacheBlock> vec;
    int n = get_runtime_value();

    vec.reserve(8);
    int cap = get_capacity_cache(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 4; i++) {
        CacheBlock block;
        block.tag = static_cast<uint64_t>(i);
        for (int j = 0; j < 7; j++) {
            block.data[j] = static_cast<uint64_t>(i * j);
        }
        vec.push_back(block);
    }

    if (!check_empty_cache(vec)) {
        int sz = get_size_cache(vec);
        consume_int(sz);
    }

    return get_size_cache(vec);
}

// Test 16: std::vector<AlignedData> - aligned structure
int test_vector_aligned() {
    std::vector<AlignedData> vec;
    int n = get_runtime_value();

    vec.reserve(10);
    int cap = get_capacity_aligned(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 5; i++) {
        AlignedData data;
        for (int j = 0; j < 4; j++) {
            data.values[j] = static_cast<double>(i * j);
        }
        vec.push_back(data);
    }

    if (!check_empty_aligned(vec)) {
        int sz = get_size_aligned(vec);
        consume_int(sz);
    }

    return get_size_aligned(vec);
}

// Test 17: std::vector<Circle*> - vector of pointers to polymorphic objects
int test_vector_shapes() {
    std::vector<Circle*> vec;
    int n = get_runtime_value();

    vec.reserve(10);
    int cap = get_capacity_shapes(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 5; i++) {
        Circle* c = new Circle();
        c->id = i;
        c->radius = static_cast<double>(i + 1) * 5.0;
        vec.push_back(c);
    }

    if (!check_empty_shapes(vec)) {
        int sz = get_size_shapes(vec);
        consume_int(sz);
    }

    // Cleanup
    for (size_t i = 0; i < vec.size(); i++) {
        delete vec[i];
    }

    return get_size_shapes(vec);
}

// Test 18: std::vector<Container> - structure containing vectors
int test_vector_container() {
    std::vector<Container> vec;
    int n = get_runtime_value();

    vec.reserve(8);
    int cap = get_capacity_container(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 4; i++) {
        Container c;
        for (int j = 0; j < i; j++) {
            c.items.push_back(j);
        }
        vec.push_back(c);
    }

    if (!check_empty_container(vec)) {
        int sz = get_size_container(vec);
        consume_int(sz);
    }

    return get_size_container(vec);
}

// Test 19: std::vector<IntPair> - template instantiation (8 bytes)
int test_vector_intpair() {
    std::vector<IntPair> vec;
    int n = get_runtime_value();

    vec.reserve(20);
    int cap = get_capacity_intpair(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 10; i++) {
        IntPair p;
        p.first = i;
        p.second = i * 2;
        vec.push_back(p);
    }

    if (!check_empty_intpair(vec)) {
        int sz = get_size_intpair(vec);
        consume_int(sz);
    }

    return get_size_intpair(vec);
}

// Test 20: std::vector<DoublePair> - template instantiation (16 bytes)
int test_vector_doublepair() {
    std::vector<DoublePair> vec;
    int n = get_runtime_value();

    vec.reserve(15);
    int cap = get_capacity_doublepair(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 8; i++) {
        DoublePair p;
        p.first = i * 1.5;
        p.second = i * 2.5;
        vec.push_back(p);
    }

    if (!check_empty_doublepair(vec)) {
        int sz = get_size_doublepair(vec);
        consume_int(sz);
    }

    return get_size_doublepair(vec);
}

// Test 21: std::vector<std::vector<int>> - nested vectors
int test_vector_nested() {
    std::vector<std::vector<int>> vec;
    int n = get_runtime_value();

    vec.reserve(10);
    int cap = get_capacity_nested(vec);
    consume_int(cap);

    for (int i = 0; i < n && i < 5; i++) {
        std::vector<int> inner;
        for (int j = 0; j < i + 2; j++) {
            inner.push_back(j * i);
        }
        vec.push_back(inner);
    }

    if (!check_empty_nested(vec)) {
        int sz = get_size_nested(vec);
        consume_int(sz);
    }

    return get_size_nested(vec);
}

// Main function that calls all tests
int main(int argc, char* argv[]) {
    int result = 0;

    // Call original test functions
    result += test_vector_int();
    result += static_cast<int>(test_vector_int64() & 0xFF);
    result += static_cast<int>(test_vector_double());
    result += test_vector_char();
    result += test_vector_int16();
    result += test_vector_pointers();
    result += test_vector_struct();
    result += test_vector_resize_operations();
    result += test_capacity_management();
    result += test_multiple_vectors();

    // Call complex structure tests
    result += test_vector_point2d();
    result += test_vector_bbox();
    result += test_vector_node();
    result += test_vector_transform();
    result += test_vector_cache();
    result += test_vector_aligned();
    result += test_vector_shapes();
    result += test_vector_container();
    result += test_vector_intpair();
    result += test_vector_doublepair();
    result += test_vector_nested();

    // Print result to prevent optimization
    std::cout << "Result: " << result << std::endl;

    return result & 0xFF;
}
