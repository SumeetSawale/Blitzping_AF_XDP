# Makefile

CC = gcc
CFLAGS = -Wall -O2
TARGET = mytraceroute
SRC = mytraceroute.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
