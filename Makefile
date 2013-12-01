.PHONY: default
default: ungeli

ungeli: ungeli.c
	$(CC) -O -std=gnu99 $^ -lcrypto -Wall -g -o $@
