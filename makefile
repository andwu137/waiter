FLAGS = -Wall -Wpedantic

ifneq ($(STATIC),)
	FLAGS += -static
endif

all:
	gcc $(FLAGS) -lssl -lcrypto -O2 waiter.c -o waiter
