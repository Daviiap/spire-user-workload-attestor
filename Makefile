# Makefile for building the Go application

# Define the name of the output binary
BINARY_NAME := user_wl_attestor
# Define the directory to place the compiled binary
DIST_DIR := dist

# Target to build the application
build:
	@echo "Building the application..."
	GOOS=linux GOARCH=amd64 go build -o $(DIST_DIR)/$(BINARY_NAME) main.go

# Create the dist directory if it doesn't exist
$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

# Clean the dist directory
clean:
	@echo "Cleaning up..."
	@rm -rf $(DIST_DIR)

# Default target
all: $(DIST_DIR) build

.PHONY: all build clean