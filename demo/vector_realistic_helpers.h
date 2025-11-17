#pragma once
#include <vector>
#include <cstdint>
#include <string>

// Helper functions in separate compilation unit
// These cannot be inlined since compiler doesn't see implementation

// ============================================================================
// Complex structure definitions for testing
// ============================================================================

// Simple 2D point (16 bytes)
struct Point2D {
    double x;
    double y;
};

// Nested structure (32 bytes)
struct BoundingBox {
    Point2D min;
    Point2D max;
};

// Structure with pointers (24 bytes on x64)
struct Node {
    int value;
    Node* next;
    Node* prev;
};

// Structure with array member (40 bytes)
struct Transform {
    float matrix[9];  // 3x3 matrix
    float translation[3];
};

// Large structure (64 bytes)
struct CacheBlock {
    uint64_t tag;
    uint64_t data[7];
};

// Structure with alignment requirements (32 bytes, 16-byte aligned)
struct alignas(16) AlignedData {
    double values[4];
};

// Polymorphic structure with vtable (16+ bytes)
struct Shape {
    virtual ~Shape() {}
    virtual double area() const = 0;
    int id;
};

struct Circle : public Shape {
    double radius;
    virtual double area() const override { return 3.14159 * radius * radius; }
};

// Structure containing a vector (24 bytes on x64)
struct Container {
    std::vector<int> items;
};

// Template structure instantiation
template<typename T>
struct Pair {
    T first;
    T second;
};

using IntPair = Pair<int>;      // 8 bytes
using DoublePair = Pair<double>; // 16 bytes

// ============================================================================
// std::vector<int> helpers
int check_empty_int(std::vector<int>& vec);
int get_size_int(std::vector<int>& vec);
int get_capacity_int(std::vector<int>& vec);
int* get_data_int(std::vector<int>& vec);
void modify_vector_int(std::vector<int>& vec, int value);

// std::vector<int64_t> helpers
int check_empty_int64(std::vector<int64_t>& vec);
int get_size_int64(std::vector<int64_t>& vec);
int get_capacity_int64(std::vector<int64_t>& vec);
int64_t* get_data_int64(std::vector<int64_t>& vec);
void modify_vector_int64(std::vector<int64_t>& vec, int64_t value);

// std::vector<double> helpers
int check_empty_double(std::vector<double>& vec);
int get_size_double(std::vector<double>& vec);
int get_capacity_double(std::vector<double>& vec);
double* get_data_double(std::vector<double>& vec);
void modify_vector_double(std::vector<double>& vec, double value);

// Heap-allocated vector helpers (pointers to vectors)
int check_empty_heap_int(std::vector<int>* vec);
int get_size_heap_int(std::vector<int>* vec);
int get_capacity_heap_int(std::vector<int>* vec);
int* get_data_heap_int(std::vector<int>* vec);
void modify_heap_int(std::vector<int>* vec, int value);

// ============================================================================
// Complex structure vector helpers
// ============================================================================

// std::vector<Point2D> helpers - 16-byte elements
int check_empty_point2d(std::vector<Point2D>& vec);
int get_size_point2d(std::vector<Point2D>& vec);
int get_capacity_point2d(std::vector<Point2D>& vec);
Point2D* get_data_point2d(std::vector<Point2D>& vec);
void modify_vector_point2d(std::vector<Point2D>& vec, const Point2D& value);

// std::vector<BoundingBox> helpers - 32-byte elements (nested structure)
int check_empty_bbox(std::vector<BoundingBox>& vec);
int get_size_bbox(std::vector<BoundingBox>& vec);
int get_capacity_bbox(std::vector<BoundingBox>& vec);
BoundingBox* get_data_bbox(std::vector<BoundingBox>& vec);

// std::vector<Node> helpers - 24-byte elements (structure with pointers)
int check_empty_node(std::vector<Node>& vec);
int get_size_node(std::vector<Node>& vec);
int get_capacity_node(std::vector<Node>& vec);
Node* get_data_node(std::vector<Node>& vec);

// std::vector<Transform> helpers - 40-byte elements (structure with arrays)
int check_empty_transform(std::vector<Transform>& vec);
int get_size_transform(std::vector<Transform>& vec);
int get_capacity_transform(std::vector<Transform>& vec);

// std::vector<CacheBlock> helpers - 64-byte elements (large structure)
int check_empty_cache(std::vector<CacheBlock>& vec);
int get_size_cache(std::vector<CacheBlock>& vec);
int get_capacity_cache(std::vector<CacheBlock>& vec);

// std::vector<AlignedData> helpers - 32-byte aligned elements
int check_empty_aligned(std::vector<AlignedData>& vec);
int get_size_aligned(std::vector<AlignedData>& vec);
int get_capacity_aligned(std::vector<AlignedData>& vec);

// std::vector<Circle*> helpers - vector of pointers to polymorphic types
int check_empty_shapes(std::vector<Circle*>& vec);
int get_size_shapes(std::vector<Circle*>& vec);
int get_capacity_shapes(std::vector<Circle*>& vec);

// std::vector<Container> helpers - structure containing vectors
int check_empty_container(std::vector<Container>& vec);
int get_size_container(std::vector<Container>& vec);
int get_capacity_container(std::vector<Container>& vec);

// std::vector<IntPair> helpers - template instantiation (8 bytes)
int check_empty_intpair(std::vector<IntPair>& vec);
int get_size_intpair(std::vector<IntPair>& vec);
int get_capacity_intpair(std::vector<IntPair>& vec);

// std::vector<DoublePair> helpers - template instantiation (16 bytes)
int check_empty_doublepair(std::vector<DoublePair>& vec);
int get_size_doublepair(std::vector<DoublePair>& vec);
int get_capacity_doublepair(std::vector<DoublePair>& vec);

// std::vector<std::vector<int>> helpers - nested vectors
int check_empty_nested(std::vector<std::vector<int>>& vec);
int get_size_nested(std::vector<std::vector<int>>& vec);
int get_capacity_nested(std::vector<std::vector<int>>& vec);
