package main

import (
	"github.com/akrennmair/gopcap"
	"fmt"
	"os"
	"bufio"
	"bytes"
	"json"
	"strings"
	"http"
)

var out *bufio.Writer
var errout *bufio.Writer

// structure of JSON-serialised packets 
type RequestPacket struct {
	SrcIp    string
	DestIp   string
	SrcPort  uint16
	DestPort uint16
	Time     string
	Flags    string
	// TODO: consider providing alternate for serialisation
	Request  *http.Request
}

// Begin capturing network traffic, returning a handle on the capture which can
// be used to process captured packets.
func OpenCaptureOrDie() *pcap.Pcap {
	devs, err := pcap.Findalldevs()
	if err != "" {
		fmt.Fprintf(errout, "pcap2json: couldn't find any devices: %s\n", err)
	}
	if 0 == len(devs) {
		os.Exit(1)
	}

	// TODO: support passing preferred device through on the cmd-line
	h, err := pcap.Openlive(devs[0].Name, 65535, true, 0)
	if h == nil {
		fmt.Fprintf(errout, "pcap2json: %s\n", err)
		errout.Flush()
	}

	// TODO: support passing filter through on the cmd-line
	expr := "not port 22"
	ferr := h.Setfilter(expr)
	if ferr != "" {
		fmt.Fprintf(out, "pcap2json: %s\n", ferr)
		out.Flush()
	}
	return h
}

// Return the string representation of the provided packet.
func PacketAsString(pkt *pcap.Packet) string {
	buf := bytes.NewBufferString("")
	for i := uint32(0); i < pkt.Caplen; i++ {
		fmt.Fprintf(buf, "%c", pkt.Data[i])
	}
	return string(buf.Bytes())
}

// Attempt to extract an HTTP request from the packet and serialise with the
// provided encoder.
func SerialisePacket(pkt *pcap.Packet, enc *json.Encoder) {
	// TODO: serialise packet details for non-HTTP packets

	// TODO: naively assumes requests are contained in a single packet and
	// HTTP verbs are not otherwise contained in a request

	// rfc 2616
	httpMethods := [...]string{"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"}

	// TODO: IPv6
	if hdr, ok := pkt.Headers[0].(*pcap.Iphdr); ok {
		if tcpHdr, ok := pkt.Headers[1].(*pcap.Tcphdr); ok {
			// TODO: Consider peeking at other ports
			if tcpHdr.DestPort == 80 {
				pktString := PacketAsString(pkt)
				for _, verb := range httpMethods {
					if strings.Contains(pktString, verb) {
						unparsedReqs := strings.Split(pktString, verb)
						for _, unparsed := range unparsedReqs {
							req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(verb + unparsed)))
							// TODO: serialise details of packets we fail to parse
							if err == nil {
								rp := RequestPacket{hdr.SrcAddr(), hdr.DestAddr(), tcpHdr.SrcPort, tcpHdr.DestPort, pkt.TimeString(), tcpHdr.FlagsString(), req}
								enc.Encode(rp)
							}
						}
					}
				}
			}
			out.Flush()
		}
	}

}

// Open a capture session, attempt to parse any requests to port 80 and 
// serialise to stdout as JSON.
func main() {
	out = bufio.NewWriter(os.Stdout)
	errout = bufio.NewWriter(os.Stderr)

	c := OpenCaptureOrDie()
	enc := json.NewEncoder(os.Stdout)
	for pkt := c.Next(); pkt != nil; pkt = c.Next() {
		pkt.Decode()
		SerialisePacket(pkt, enc)
	}
}
