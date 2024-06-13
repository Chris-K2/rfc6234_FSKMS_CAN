# Define the compiler
CC=gcc

# Define compilation options
CFLAGS=-I. -Wall -lrt

# Define the name of the target executable
TARGET=test

# Define the object files required
OBJS=hkdf.o hmac.o sha1.o sha224-256.o sha384-512.o usha.o test.o 

# Default target: compile everything
all: $(TARGET)

# Rule: how to build the target from the object files
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

# Rule: how to build object files from C source files
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

# Clean up generated files
clean:
	rm -rf $(OBJS) $(TARGET)
