# Makefile for secp256k1 JNI ECRECOVER implementation

# Directories
SECP256K1_DIR = ../bitcoin-core-secp256k1
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
LIB_DIR = $(BUILD_DIR)/lib

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O3 -fPIC -std=c99
INCLUDES = -I$(SECP256K1_DIR)/include -I$(SECP256K1_DIR)/src
LDFLAGS = -shared
LDFLAGS_STATIC =
LIBS = -L$(SECP256K1_DIR)/.libs -lsecp256k1
LIBS_STATIC = $(SECP256K1_DIR)/.libs/libsecp256k1.a

# Platform-specific settings
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    PLATFORM = darwin
    SHARED_EXT = dylib
    STATIC_EXT = a
    LDFLAGS += -undefined dynamic_lookup
else ifeq ($(UNAME_S),Linux)
    PLATFORM = linux-gnu
    SHARED_EXT = so
    STATIC_EXT = a
    LDFLAGS += -Wl,-soname,libsecp256k1_ecrecover.$(SHARED_EXT)
else
    $(error Unsupported platform: $(UNAME_S))
endif

ifeq ($(UNAME_M),x86_64)
    ARCH = x86_64
else ifeq ($(UNAME_M),aarch64)
    ARCH = aarch64
else ifeq ($(UNAME_M),arm64)
    ARCH = aarch64
else
    ARCH = $(UNAME_M)
endif

TARGET_DIR = $(BUILD_DIR)/$(PLATFORM)-$(ARCH)
TARGET_LIB_DIR = $(TARGET_DIR)/lib
TARGET_LIB = $(TARGET_LIB_DIR)/libsecp256k1_ecrecover.$(SHARED_EXT)
TARGET_STATIC_LIB = $(TARGET_LIB_DIR)/libsecp256k1_ecrecover.$(STATIC_EXT)
TARGET_HEADER = $(TARGET_LIB_DIR)/secp256k1_ecrecover.h

# Source files
SOURCES = secp256k1_ecrecover.c
OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)

# Default target
all: $(TARGET_LIB) $(TARGET_STATIC_LIB) $(TARGET_LIB_DIR)/libsecp256k1.a $(TARGET_HEADER) $(TARGET_LIB_DIR)/secp256k1.h $(TARGET_LIB_DIR)/secp256k1_recovery.h

# Create directories
$(OBJ_DIR) $(TARGET_LIB_DIR):
	mkdir -p $@

# Compile source files
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link shared library
$(TARGET_LIB): $(OBJECTS) | $(TARGET_LIB_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

# Create static library (JNI wrapper only, not including libsecp256k1.a)
$(TARGET_STATIC_LIB): $(OBJECTS) | $(TARGET_LIB_DIR)
	ar rcs $@ $(OBJECTS)

# Copy libsecp256k1.a from bitcoin-core-secp256k1
$(TARGET_LIB_DIR)/libsecp256k1.a: $(SECP256K1_DIR)/.libs/libsecp256k1.a | $(TARGET_LIB_DIR)
	cp $(SECP256K1_DIR)/.libs/libsecp256k1.a $@

# Copy header files
$(TARGET_HEADER): secp256k1_ecrecover.h | $(TARGET_LIB_DIR)
	cp secp256k1_ecrecover.h $@

# Copy bitcoin-core-secp256k1 headers
$(TARGET_LIB_DIR)/secp256k1.h: $(SECP256K1_DIR)/include/secp256k1.h | $(TARGET_LIB_DIR)
	cp $(SECP256K1_DIR)/include/secp256k1.h $@

$(TARGET_LIB_DIR)/secp256k1_recovery.h: $(SECP256K1_DIR)/include/secp256k1_recovery.h | $(TARGET_LIB_DIR)
	cp $(SECP256K1_DIR)/include/secp256k1_recovery.h $@

# Build secp256k1 dependency if needed
$(SECP256K1_DIR)/libsecp256k1.la:
	cd $(SECP256K1_DIR) && ./autogen.sh && ./configure --enable-module-recovery --enable-shared && make

secp256k1: $(SECP256K1_DIR)/libsecp256k1.la

# Clean
clean:
	rm -rf $(BUILD_DIR)

# Rebuild
rebuild: clean all

# Test target (placeholder)
test: $(TARGET_LIB)
	@echo "Test target not implemented yet"

.PHONY: all clean rebuild test secp256k1

# Print build information
info:
	@echo "Platform: $(PLATFORM)"
	@echo "Architecture: $(ARCH)"
	@echo "Target library: $(TARGET_LIB)"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"