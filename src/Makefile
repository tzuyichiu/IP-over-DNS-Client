IDIR =../include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj

_DEPS = DNS_Client.h DNS_Encode.h DNS_Listen.h DNS_Query.h DNS_Packet.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = DNS_Client.o DNS_Encode.o DNS_Listen.o DNS_Query.o DNS_flag.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

DNS_Client: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -pthread

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*
