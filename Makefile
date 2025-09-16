# Simplified Port Scan Detector Makefile
# Educational version for teaching network security concepts

CC = gcc
CFLAGS = -Wall -O2 -std=c99
LDFLAGS = -lpcap

TARGET = scanlogd-simple
SOURCES = scanlogd-simple.c

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

# Clean build files
clean:
	rm -f $(TARGET) *.o

# Install (optional, requires root)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Uninstall
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Help target
help:
	@echo "Simplified Port Scan Detector"
	@echo "============================"
	@echo "Available targets:"
	@echo "  all       - Build the program (default)"
	@echo "  clean     - Remove build files"
	@echo "  install   - Install to /usr/local/bin (requires root)"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  help      - Show this help"
	@echo ""
	@echo "To run: sudo ./scanlogd-simple [interface]"
	@echo "Example: sudo ./scanlogd-simple en0"

.PHONY: all clean install uninstall help
