# Simplified Port Scan Detector Makefile
# Educational version for teaching network security concepts
# Cross-platform: Windows (Npcap), Linux, macOS

# Detect platform
ifeq ($(OS),Windows_NT)
    PLATFORM = WINDOWS
    CC = gcc
    CFLAGS = -Wall -O2 -std=c99 -D_WIN32
    LDFLAGS = -lpcap -lws2_32 -liphlpapi
    TARGET = pcap-win.exe
    RM = del /Q
else
    PLATFORM = UNIX
    CC = gcc
    CFLAGS = -Wall -O2 -std=c99
    LDFLAGS = -lpcap
    TARGET = pcap-win
    RM = rm -f
endif

SOURCES = pcap-win.c

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SOURCES)
	@echo "Building for $(PLATFORM)..."
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Clean build files
clean:
	$(RM) $(TARGET) *.o

# Install (optional, Unix-like systems only)
ifndef PLATFORM_WINDOWS
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
endif

# Help target
help:
	@echo "Simplified Port Scan Detector"
	@echo "============================"
	@echo "Cross-platform build system"
	@echo "Platform detected: $(PLATFORM)"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build the program (default)"
	@echo "  clean     - Remove build files"
ifndef PLATFORM_WINDOWS
	@echo "  install   - Install to /usr/local/bin (Unix only)"
	@echo "  uninstall - Remove from /usr/local/bin (Unix only)"
endif
	@echo "  help      - Show this help"
	@echo ""
	@echo "To run:"
ifdef PLATFORM_WINDOWS
	@echo "  pcap-win.exe [interface]"
	@echo "  Example: pcap-win.exe \\Device\\NPF_{GUID}"
else
	@echo "  sudo ./pcap-win [interface]"
	@echo "  Example: sudo ./pcap-win en0"
endif
	@echo ""
	@echo "Prerequisites:"
ifdef PLATFORM_WINDOWS
	@echo "  - Npcap: https://nmap.org/npcap/"
	@echo "  - MinGW-w64 or Visual Studio"
else
	@echo "  - libpcap development headers"
	@echo "  - GCC compiler"
endif

.PHONY: all clean install uninstall help
