FLAGS = -Wall -Wpedantic

all:
	gcc $(FLAGS) -O2 waiter.c -o waiter

static:
	gcc $(FLAGS) -static -O2 waiter.c -o waiter
