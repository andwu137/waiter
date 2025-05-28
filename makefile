FLAGS = -Wall -Wpedantic

ifneq ($(STATIC),)
	FLAGS += -static
endif

all:
	$(CC) $(FLAGS) -O2 waiter.c -lssl -lcrypto -o waiter
