#include "vector_realistic_helpers.h"

// Separate compilation unit prevents inlining
// All helper function implementations preserve vector type information

// ============================================================================
// std::vector<int> helpers - 4-byte elements
// ============================================================================

int check_empty_int(std::vector<int>& vec) {
    if (vec.empty()) {
        return 1;
    }
    return 0;
}

int get_size_int(std::vector<int>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_int(std::vector<int>& vec) {
    return static_cast<int>(vec.capacity());
}

int* get_data_int(std::vector<int>& vec) {
    return vec.data();
}

void modify_vector_int(std::vector<int>& vec, int value) {
    if (!vec.empty()) {
        vec[0] = value;
    }
    vec.push_back(value);
}

// ============================================================================
// std::vector<int64_t> helpers - 8-byte elements
// ============================================================================

int check_empty_int64(std::vector<int64_t>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_int64(std::vector<int64_t>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_int64(std::vector<int64_t>& vec) {
    return static_cast<int>(vec.capacity());
}

int64_t* get_data_int64(std::vector<int64_t>& vec) {
    return vec.data();
}

void modify_vector_int64(std::vector<int64_t>& vec, int64_t value) {
    if (!vec.empty()) {
        vec[0] = value;
    }
    vec.push_back(value);
}

// ============================================================================
// std::vector<double> helpers - 8-byte elements, floating point
// ============================================================================

int check_empty_double(std::vector<double>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_double(std::vector<double>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_double(std::vector<double>& vec) {
    return static_cast<int>(vec.capacity());
}

double* get_data_double(std::vector<double>& vec) {
    return vec.data();
}

void modify_vector_double(std::vector<double>& vec, double value) {
    if (!vec.empty()) {
        vec[0] = value;
    }
    vec.push_back(value);
}

// ============================================================================
// Heap-allocated std::vector<int>* helpers
// Tests with pointer-to-vector (heap allocated)
// ============================================================================

int check_empty_heap_int(std::vector<int>* vec) {
    if (!vec) return 1;
    return vec->empty() ? 1 : 0;
}

int get_size_heap_int(std::vector<int>* vec) {
    if (!vec) return 0;
    return static_cast<int>(vec->size());
}

int get_capacity_heap_int(std::vector<int>* vec) {
    if (!vec) return 0;
    return static_cast<int>(vec->capacity());
}

int* get_data_heap_int(std::vector<int>* vec) {
    if (!vec) return nullptr;
    return vec->data();
}

void modify_heap_int(std::vector<int>* vec, int value) {
    if (!vec) return;
    if (!vec->empty()) {
        (*vec)[0] = value;
    }
    vec->push_back(value);
}

// ============================================================================
// Complex structure vector helper implementations
// ============================================================================

// std::vector<Point2D> helpers - 16-byte elements
int check_empty_point2d(std::vector<Point2D>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_point2d(std::vector<Point2D>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_point2d(std::vector<Point2D>& vec) {
    return static_cast<int>(vec.capacity());
}

Point2D* get_data_point2d(std::vector<Point2D>& vec) {
    return vec.data();
}

void modify_vector_point2d(std::vector<Point2D>& vec, const Point2D& value) {
    if (!vec.empty()) {
        vec[0] = value;
    }
    vec.push_back(value);
}

// std::vector<BoundingBox> helpers - 32-byte elements (nested structure)
int check_empty_bbox(std::vector<BoundingBox>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_bbox(std::vector<BoundingBox>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_bbox(std::vector<BoundingBox>& vec) {
    return static_cast<int>(vec.capacity());
}

BoundingBox* get_data_bbox(std::vector<BoundingBox>& vec) {
    return vec.data();
}

// std::vector<Node> helpers - 24-byte elements (structure with pointers)
int check_empty_node(std::vector<Node>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_node(std::vector<Node>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_node(std::vector<Node>& vec) {
    return static_cast<int>(vec.capacity());
}

Node* get_data_node(std::vector<Node>& vec) {
    return vec.data();
}

// std::vector<Transform> helpers - 40-byte elements (structure with arrays)
int check_empty_transform(std::vector<Transform>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_transform(std::vector<Transform>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_transform(std::vector<Transform>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<CacheBlock> helpers - 64-byte elements (large structure)
int check_empty_cache(std::vector<CacheBlock>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_cache(std::vector<CacheBlock>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_cache(std::vector<CacheBlock>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<AlignedData> helpers - 32-byte aligned elements
int check_empty_aligned(std::vector<AlignedData>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_aligned(std::vector<AlignedData>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_aligned(std::vector<AlignedData>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<Circle*> helpers - vector of pointers to polymorphic types
int check_empty_shapes(std::vector<Circle*>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_shapes(std::vector<Circle*>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_shapes(std::vector<Circle*>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<Container> helpers - structure containing vectors
int check_empty_container(std::vector<Container>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_container(std::vector<Container>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_container(std::vector<Container>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<IntPair> helpers - template instantiation (8 bytes)
int check_empty_intpair(std::vector<IntPair>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_intpair(std::vector<IntPair>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_intpair(std::vector<IntPair>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<DoublePair> helpers - template instantiation (16 bytes)
int check_empty_doublepair(std::vector<DoublePair>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_doublepair(std::vector<DoublePair>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_doublepair(std::vector<DoublePair>& vec) {
    return static_cast<int>(vec.capacity());
}

// std::vector<std::vector<int>> helpers - nested vectors
int check_empty_nested(std::vector<std::vector<int>>& vec) {
    return vec.empty() ? 1 : 0;
}

int get_size_nested(std::vector<std::vector<int>>& vec) {
    return static_cast<int>(vec.size());
}

int get_capacity_nested(std::vector<std::vector<int>>& vec) {
    return static_cast<int>(vec.capacity());
}
