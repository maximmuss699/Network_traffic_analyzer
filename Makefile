# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap -lncurses

SOURCES = isa-top.c utils.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = isa-top.h
TARGET = isa-top

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
