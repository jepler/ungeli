.PHONY: default
default: ungeli

ungeli: ungeli.c
	$(CC) -std=gnu99 $^ -lcrypto -Wall -g -o $@
