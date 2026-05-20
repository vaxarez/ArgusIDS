CC = gcc
CFLAGS = -Wall -g -I/usr/include/yaml-0.1

SRC = main.c network_monitor.c log_utils.c config.c signatures.c
OBJ = $(SRC:.c=.o)
TARGET = ids

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lyaml

clean:
	rm -f $(OBJ) $(TARGET) ids.log

.PHONY: all clean
