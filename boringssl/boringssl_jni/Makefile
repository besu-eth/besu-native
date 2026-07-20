# Detect platform and architecture
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Determine shared library extension and dynamic link flags
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = dylib
    JNI_OS_DIR = darwin
    CC ?= clang
    # Use MACOSX_DEPLOYMENT_TARGET from environment or default to 11.0 (first Apple Silicon support)
    MACOSX_DEPLOYMENT_TARGET ?= 11.0
    LDFLAGS = -dynamiclib -undefined dynamic_lookup -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
    CFLAGS_EXTRA = -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
else
    LIB_EXT = so
    JNI_OS_DIR = linux
    CC ?= gcc
    LDFLAGS = -shared
    CFLAGS_EXTRA =
endif

# Directories
BUILD_DIR = build
BSSL_DIR = ../google-boringssl
BSSL_BUILD_DIR = $(BSSL_DIR)/build
INCLUDES = -I$(BSSL_DIR)/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(JNI_OS_DIR)

# Flags
CFLAGS = -O2 -fPIC $(INCLUDES) $(CFLAGS_EXTRA)
LIBS = $(BSSL_BUILD_DIR)/libcrypto.a

# Files
LIB_NAME = libboringssl_precompiles.$(LIB_EXT)
STATIC_LIB_NAME = libboringssl_precompiles.a
SRCS = p256_verify.c ecrecover.c
OBJS = $(SRCS:.c=.o)
BUILD_OBJS = $(addprefix $(BUILD_DIR)/, $(OBJS))
BUILD_LIB = $(BUILD_DIR)/$(LIB_NAME)
BUILD_STATIC_LIB = $(BUILD_DIR)/$(STATIC_LIB_NAME)

# Default target
all: $(BUILD_DIR) $(BUILD_LIB) $(BUILD_STATIC_LIB)

$(BUILD_DIR):
	mkdir -p $@

# Dynamic library
$(BUILD_LIB): $(BUILD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Static library - properly merge libcrypto.a object files instead of nesting
$(BUILD_STATIC_LIB): $(BUILD_OBJS)
	@mkdir -p $(BUILD_DIR)/merge_tmp
	@cd $(BUILD_DIR)/merge_tmp && ar x ../../$(BSSL_BUILD_DIR)/libcrypto.a
	ar rcs $@ $^ $(BUILD_DIR)/merge_tmp/*.o
	@rm -rf $(BUILD_DIR)/merge_tmp

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
