CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic -Iinclude
TARGET = dns_proxy
SOURCES = src/main.c src/config.c src/dns_utils.c
HEADERS = include/config.h include/dns_utils.h
OBJS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install test

TEST_TARGET = test_dns_utils
TEST_SOURCES = test/test_dns_utils.c src/dns_utils.c src/config.c
TEST_FLAGS = -Iinclude -Wall -Wextra -std=c99

test: $(TEST_SOURCES)
	$(CC) $(TEST_FLAGS) -o $(TEST_TARGET) $(TEST_SOURCES)
	./$(TEST_TARGET)

