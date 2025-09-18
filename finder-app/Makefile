# finder-app/Makefile

# CC will be provided by Buildroot (e.g., aarch64-buildroot-linux-gnu-gcc)
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Werror -std=c11 -g
LDFLAGS ?=

TARGET  := writer
SRCS    := writer.c
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean artifacts
clean:
	rm -f $(TARGET) $(OBJS)

