# Имя исполняемого файла
TARGET = isa-top

# Компилятор
CC = gcc

# Флаги компиляции
CFLAGS = -Wall -Wextra -O2

# Библиотеки для линковки
LDFLAGS = -lpcap -lncurses

# Исходный файл
SRC = isa-top.c

# Правило для компиляции
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)  

# Правило для очистки скомпилированных файлов
clean:
	rm -f $(TARGET)  # Здесь тоже 
