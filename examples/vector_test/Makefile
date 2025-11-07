# Makefile for vector test program

CXX = g++
# Use -O2 to force inlining, keep debug symbols
CXXFLAGS = -std=c++11 -g -O2 -m64
TARGET = vector_test
SRC = vector_test.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
