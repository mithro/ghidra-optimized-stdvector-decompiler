#include <vector>
#include <iostream>

// Test function 1: Uses vector.size() - should trigger SIZE pattern
int GetVectorSize(const std::vector<int>& vec) {
    return vec.size();
}

// Test function 2: Uses vector.empty() - should trigger EMPTY pattern
bool IsVectorEmpty(const std::vector<int>& vec) {
    return vec.empty();
}

// Test function 3: Multiple size checks
int SumIfNotEmpty(const std::vector<int>& vec) {
    if (vec.empty()) {
        return 0;
    }

    int sum = 0;
    for (size_t i = 0; i < vec.size(); i++) {
        sum += vec[i];
    }
    return sum;
}

// Test function 4: Uses vector.data() - should trigger DATA pattern
const int* GetVectorData(const std::vector<int>& vec) {
    return vec.data();
}

// Test function 5: Complex usage with multiple patterns
void ProcessVector(std::vector<int>& vec) {
    if (!vec.empty()) {
        std::cout << "Vector size: " << vec.size() << std::endl;

        const int* data = vec.data();
        for (size_t i = 0; i < vec.size(); i++) {
            data[i];  // Access data
        }
    }
}

// Test function 6: Resize triggers size checks
void ResizeVector(std::vector<int>& vec, size_t new_size) {
    if (vec.size() < new_size) {
        vec.resize(new_size);
    }
}

// Main function to prevent optimization removal
int main() {
    std::vector<int> test_vec = {1, 2, 3, 4, 5};

    int size = GetVectorSize(test_vec);
    bool empty = IsVectorEmpty(test_vec);
    int sum = SumIfNotEmpty(test_vec);
    const int* data = GetVectorData(test_vec);

    ProcessVector(test_vec);
    ResizeVector(test_vec, 10);

    return size + sum + (empty ? 0 : 1);
}
