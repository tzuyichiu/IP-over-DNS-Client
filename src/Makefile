IDIR =../include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj

_DEPS = DNS_Client.h DNS_Constructor.h DNS_Encode.h DNS_Packet.h DNS_flag.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = DNS_Client.o DNS_Constructor.o DNS_Encode.o DNS_Packet.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

DNS_Client: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o
