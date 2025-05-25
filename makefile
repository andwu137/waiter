FLAGS = -Wall -Wpedantic

ifneq ($(STATIC),)
	FLAGS += -static
endif

all:
	$(CC) $(FLAGS) -lssl -lcrypto -O2 waiter.c -o waiter
