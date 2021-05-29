ARCH=$(shell uname -m)

CXX=g++
CFLAGS=-O0 -ggdb -std=c++11
CPPFLAGS=
LDFLAGS=-lpthread

OBJS=main.o sandbox.o path.o wakeup.o config.o
BINDIR=bin

all: $(BINDIR)/sandbox

clean:
	rm -f $(BINDIR)/sandbox $(OBJS) arch.h
	rm -rf $(BINDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/sandbox: $(BINDIR) $(OBJS)
	$(CXX) -o $@ $(filter %.o,$+) $(CFLAGS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

main.o: arch.h sandbox.h fs.h wakeup.h config.h

arch.h:
	echo '#define ARCH $(ARCH)' > $@
	echo '#include "arch/$(ARCH).h"' >> $@

.PHONY: all clean
