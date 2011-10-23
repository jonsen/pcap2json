package main

import (
	"github.com/akrennmair/gopcap"
	"fmt"
	"os"
	"bufio"
	"bytes"
	"json"
)

var out *bufio.Writer
var errout *bufio.Writer

func main() {
	expr := "not port 22"
	out = bufio.NewWriter(os.Stdout)
	errout = bufio.NewWriter(os.Stderr)

	devs, err := pcap.Findalldevs()
	if err != "" {
		fmt.Fprintf(errout, "pcap2json: couldn't find any devices: %s\n", err)
	}
	if 0 == len(devs) {
		os.Exit(1)
	}

	h, err := pcap.Openlive(devs[0].Name, 65535, true, 0)
	if h == nil {
		fmt.Fprintf(errout, "pcap2json: %s\n", err)
		errout.Flush()
		return
	}

	ferr := h.Setfilter(expr)
	if ferr != "" {
		fmt.Fprintf(out, "pcap2json: %s\n", ferr)
		out.Flush()
	}

	type JsonPacket struct {
		SrcIp    string
		DestIp   string
		SrcPort  uint16
		DestPort uint16
		Data     string
		Time     string
		Flags    string
	}

	enc := json.NewEncoder(os.Stdout)
	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		if hdr, ok := pkt.Headers[0].(*pcap.Iphdr); ok {
			if tcp_hdr, ok := pkt.Headers[1].(*pcap.Tcphdr); ok {
				jp := JsonPacket{hdr.SrcAddr(), hdr.DestAddr(), tcp_hdr.SrcPort, tcp_hdr.DestPort, data_as_string(pkt), pkt.TimeString(), tcp_hdr.FlagsString()}
				enc.Encode(jp)
				out.Flush()
			}
		}
	}
}

func data_as_string(pkt *pcap.Packet) string {
	buf := bytes.NewBufferString("")
	for i := uint32(0); i < pkt.Caplen; i++ {
		if i%32 == 0 {
			fmt.Fprintf(buf, "\n")
		}
		if 32 <= pkt.Data[i] && pkt.Data[i] <= 126 {
			fmt.Fprintf(buf, "%c", pkt.Data[i])
		} else {
			fmt.Fprintf(buf, ".")
		}
	}
	return string(buf.Bytes())
}
