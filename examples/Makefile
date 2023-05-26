CC = gcc

CFLAGS = -no-pie -fno-pic -fno-stack-protector

test_2: test_2.c
	$(CC) $(CFLAGS) -o $@ $^

test: test.c
	$(CC) $(CFLAGS) -o $@ $^

test2: test2.c
	$(CC) $(CFLAGS) -o $@ $^

test3: test3.c
	$(CC) $(CFLAGS) -o $@ $^

indirect_call: indirect_call.c
	$(CC) $(CFLAGS) -o $@ $^

recursive_call: recursive_call.c
	$(CC) $(CFLAGS) -o $@ $^
