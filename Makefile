include $(GOROOT)/src/Make.inc

TARG=pcap2json
GOFILES=pcap2json.go
CLEANFILES=pcap2json

include $(GOROOT)/src/Make.pkg

all: pcap2json.go install
	$(GC) pcap2json.go
	$(LD) -o pcap2json pcap2json.$(O)

