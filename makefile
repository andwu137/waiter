FLAGS = -Wall -Wpedantic

ifneq ($(STATIC),)
	FLAGS += -static
endif

all: debug

release:
	$(CC) $(FLAGS) -O3 -march=native waiter.c -lssl -lcrypto -o waiter

debug:
	$(CC) $(FLAGS) -O0 -g -DDEBUG waiter.c -lssl -lcrypto -o waiter
