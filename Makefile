TARGET := hydra-cli
SRC := $(wildcard src/*.cpp)

CXX ?= g++
CXXFLAGS_COMMON := -std=c++17 -Wall -Wextra -Wpedantic
CXXFLAGS_DEBUG := -g -O0 -DDEBUG=1
CXXFLAGS_RELEASE := -O2 -DNDEBUG

.PHONY: all debug release run clean

all: release

debug: CXXFLAGS := $(CXXFLAGS_COMMON) $(CXXFLAGS_DEBUG)
debug: $(TARGET)

release: CXXFLAGS := $(CXXFLAGS_COMMON) $(CXXFLAGS_RELEASE)
release: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -Iinclude $(SRC) -o $@

run: debug
	./$(TARGET)

clean:
	rm -f $(TARGET)
