
TARGET = isa-top


CC = gcc


CFLAGS = -Wall -Wextra -O2


LDFLAGS = -lpcap -lncurses


SRC = isa-top.c


all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)  


clean:
	rm -f $(TARGET)  
