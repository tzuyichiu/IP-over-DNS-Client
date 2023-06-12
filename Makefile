IDIR =./include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=./obj
SDIR=./src
BDIR=./build

SCRIPT=test

_DEPS = $(SCRIPT).h encoder.h packet.h flag.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = $(SCRIPT).o encoder.o packet.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	@mkdir -p $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BDIR)/$(SCRIPT): $(OBJ)
	@mkdir -p $(@D)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o
	rm -f $(BDIR)/*
