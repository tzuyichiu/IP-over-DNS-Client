IDIR =./include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=./obj
SDIR=./src
BDIR=./build

SCRIPT=DNS_Test

_DEPS = DNS_Client.h DNS_Constructor.h DNS_Encode.h DNS_Packet.h DNS_flag.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = $(SCRIPT).o DNS_Constructor.o DNS_Encode.o DNS_Packet.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BDIR)/$(SCRIPT): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o
	rm -f $(BDIR)/*
