#makefile for cpass

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = 

# dirs
SRC_DIR = src
LIB_DIR = lib
BUILD_DIR = build
INSTALL_DIR = /usr/local/bin

#files' paths
SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/cpass.c $(LIB_DIR)/monocypher.c $(LIB_DIR)/aes.c
OBJECTS = $(BUILD_DIR)/main.o $(BUILD_DIR)/cpass.o $(BUILD_DIR)/monocypher.o $(BUILD_DIR)/aes.o
TARGET = cpass

# target
all: $(BUILD_DIR) $(TARGET)

# create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# compiling 
$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/cpass.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/main.c -o $(BUILD_DIR)/main.o

$(BUILD_DIR)/cpass.o: $(SRC_DIR)/cpass.c $(SRC_DIR)/cpass.h $(LIB_DIR)/monocypher.h $(LIB_DIR)/aes.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/cpass.c -o $(BUILD_DIR)/cpass.o

$(BUILD_DIR)/monocypher.o: $(LIB_DIR)/monocypher.c $(LIB_DIR)/monocypher.h
	$(CC) $(CFLAGS) -c $(LIB_DIR)/monocypher.c -o $(BUILD_DIR)/monocypher.o

$(BUILD_DIR)/aes.o: $(LIB_DIR)/aes.c $(LIB_DIR)/aes.h
	$(CC) $(CFLAGS) -c $(LIB_DIR)/aes.c -o $(BUILD_DIR)/aes.o

#link to executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)
	@echo "Build complete! Binary: ./$(TARGET)"

# install func
install: $(TARGET)
	@echo "Installing $(TARGET) to $(INSTALL_DIR)..."
	@install -m 755 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "Installation complete!"
	@echo "You can now use 'cpass' from anywhere."

# uninstall func
uninstall:
	@echo "Removing $(TARGET) from $(INSTALL_DIR)..."
	@rm -f $(INSTALL_DIR)/$(TARGET)
	@echo "Uninstall complete."

# clean build garbage
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(TARGET)
	@echo "Clean complete."

# CLEAN EVERYTHING, BE CAREFUL
clean-all: clean
	@echo "WARNING: This will delete all password data!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		rm -rf ~/.cpass; \
		echo "User data removed."; \
	else \
		echo "User data preserved."; \
	fi

#compile with debug
debug: CFLAGS += -g -DDEBUG
debug: clean all

# run test
test: $(TARGET)
	@echo "Running tests..."
	@./test.sh

# help func
help:
	@echo "cpass - C Password Manager by mcadario"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Compile the program (may need sudo)"
	@echo "  make install  - Install to $(INSTALL_DIR) (may need sudo)"
	@echo "  make uninstall- Remove from $(INSTALL_DIR) (may need sudo)"
	@echo "  make clean    - Remove build files"
	@echo "  make clean-all- Remove build files AND user data"
	@echo "  make debug    - Compile with debug symbols"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Installation:"
	@echo "  1. Run: make"
	@echo "  2. Run: sudo make install"
	@echo "  3. Use: cpass add <site> <user> <pass>"

.PHONY: all install uninstall clean clean-all debug test help