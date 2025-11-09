// Demonstrates aggressive optimization vector P-code pattern
// This demo exhibits the pattern found in heavily optimized MSVC binaries
//
// Key characteristics:
// 1. LOAD operations where address is pre-computed (stored in register/unique)
// 2. Vector member accesses through this pointer parameter
// 3. Operations: size calculation, capacity check, reallocate logic
//
// Compile with MSVC 2019+ with optimizations to get the pattern:
// cl /O2 /std:c++17 vector_optimized_pattern.cpp

#include <vector>
#include <iostream>

// This demonstrates how aggressive optimization creates complex P-code patterns
// The key is using vector as a parameter and accessing its internals
template<typename T>
void process_vector_with_reallocation(std::vector<T>* vec, const T& value) {
    // Force size calculation - this should compile to: (mylast - myfirst) >> N
    size_t current_size = vec->size();

    // Force capacity check - this should compile to: (myend - myfirst) >> N
    size_t current_capacity = vec->capacity();

    // Force empty check - this should compile to: myfirst == mylast
    if (vec->empty()) {
        std::cout << "Vector is empty\n";
    }

    // Check if reallocation needed
    if (current_size >= current_capacity) {
        std::cout << "Need to reallocate\n";
    }

    // Access data pointer - this should compile to: *myfirst (when dereferenced)
    if (!vec->empty()) {
        T* data_ptr = vec->data();
        std::cout << "First element: " << *data_ptr << "\n";
    }

    // Add element (will trigger reallocation if needed)
    vec->push_back(value);
}

// Specialized version for int to demonstrate typical optimized pattern
void process_int_vector(std::vector<int>* vec, const int& value) {
    // This demonstrates the _Emplace_reallocate pattern

    // Calculate size using member access
    // Compiler should optimize to: (vec->_Mylast - vec->_Myfirst) >> 2
    size_t sz = vec->size();

    // Calculate capacity using member access
    // Compiler should optimize to: (vec->_Myend - vec->_Myfirst) >> 2
    size_t cap = vec->capacity();

    // Check if empty
    // Compiler should optimize to: vec->_Myfirst == vec->_Mylast
    bool is_empty = vec->empty();

    // Use the values to prevent optimization away
    if (sz < cap && !is_empty) {
        vec->push_back(value);
    } else {
        // Force reallocation path
        vec->reserve(cap * 2 + 1);
        vec->push_back(value);
    }
}

// Function that passes vector by pointer to force this-pointer access pattern
int test_vector_operations() {
    std::vector<int> my_vector;

    // Populate vector
    for (int i = 0; i < 10; i++) {
        process_int_vector(&my_vector, i);
    }

    // More operations to create varied patterns
    process_vector_with_reallocation(&my_vector, 42);

    return my_vector.size();
}

int main() {
    int result = test_vector_operations();
    std::cout << "Result: " << result << "\n";
    return 0;
}
