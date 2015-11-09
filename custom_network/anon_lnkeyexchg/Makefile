CC = gcc
CFLAGS = -O2 -Wall
LFLAGS = -lcrypto
PTHREADFLAGS = -pthread

lnkeyexchg: main.o interface.o server.o client.o rsa.o
	$(CC) $(CFLAGS) $(PTHREADFLAGS) -o lnkeyexchg main.o interface.o server.o client.o rsa.o $(LFLAGS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

interface.o: ../interface.h ../interface.c
	$(CC) $(CFLAGS) -c ../interface.c

server.o: server.h server.c
	$(CC) $(CFLAGS) -c server.c

client.o: client.h client.c
	$(CC) $(CFLAGS) -c client.c

rsa.o: rsa.h rsa.c
	$(CC) $(CFLAGS) -c rsa.c

clean:
	rm -f *.o lnkeyexchg
