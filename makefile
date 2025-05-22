FLAGS = -Wall -Wpedantic

ifneq ($(STATIC),)
	FLAGS += -static
endif

all:
	gcc $(FLAGS) -O2 waiter.c -o waiter
