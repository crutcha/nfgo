package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/spf13/viper"
	"golang.org/x/net/ipv4"
	"net"
	"strconv"
	"strings"
)

// For the collector itself we can use golang's standard net library. This
// Provides us with the easiest way to create a UDP socket and parse paylods,
// But it does not give us a raw socket so we can not spoof the source address to
// Be the original senders address. In order to this, we must construct our
// Own ipv4 headers and payloads with RawConn in a seperate connection.
// If we used a raw socket for everything, the underlying kernel would send
// ICMP unreachable messages to endpoints sending datagrams to us on our configured
// Listening port. This may or may not cause problems but for now we will use
// Two seperate connections to accomplish forwarding. We will create a socket
// with UDPConn but read the payload from the raw socket.

// UDP header format for parsing raw socket packet
type udpHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// Interface for parsing flow records into database entries. This allows us to
// Implement methods on different flow type structs(netflow/ipfix/sflow)
// And use a general parse function as opposed to create a parse function for
// Each type.
type FlowRecord interface {
	unpackFlowRecord(*bytes.Buffer, int) error
}

// This function will forward flow datagram payloads to all configured flow
// destinations with a manually crafted ipv4 header.
func forwardFlow(rc *ipv4.RawConn, h *ipv4.Header, p []byte, cm *ipv4.ControlMessage, s []string) {

	// Loop over provided forwarding destinations and rewrite headers with
	// Spoofed source and new destination
	for _, v := range s {

		// Split the string to grab IP address and port info
		destIP := strings.Split(v, ":")[0]
		// destPort := string.Split(s, ":")[1]

		// Rewrite passed in headers
		h.Dst = net.ParseIP(destIP)
		if err := rc.WriteTo(h, p, nil); err != nil {
			fmt.Println("Rawconn Write Error.")
		}

	}
}

func unpackRawPacket(datagram []byte) {
	var nfheader NetflowHeader
	var udpheader udpHeader

	// Since binary.Read() method uses io.Reader interface as an
	// argument, need to create new buffer which implements that
	// interface.
	buf := bytes.NewBuffer(datagram)

	// I THINK I can index this byte slice like datagram[udpheaderlen:] and
	// Disregard the UDP header but for now let's just unpack it too.
	if udperr := binary.Read(buf, binary.BigEndian, &udpheader); udperr != nil {
		fmt.Println(udperr)
	}

	// Here we'll check to see which socket it was received on.
	// NetFlow will come in on different ports than SFlow
	// Match version number found in header, unpack flow records to appropriate
	// struct type,  and call it's interface parse method. Ideally
	// We don't care which protocol it is since each header struct will
	// Contain a version and also satisfy FlowRecord interface.
	if udpheader.DstPort == 2055 {
		_ = binary.Read(buf, binary.BigEndian, &nfheader)
		// nfheader.Records = make([]FlowRecord, 0, nfheader.Count)

		// This if block here checking for version is temporary. If interfaces
		// Works for this then we don't care about version only that each struct
		// Implements the interface.
		fmt.Println(nfheader)
		if nfheader.Version == 5 {
			for i, v := range nfheader.Records {
				v.unpackFlowRecord(buf, i)
			}
			// unpackFlowRecords(record, buf, int(nfheader.Count))
		} else if nfheader.Version == 9 {
			fmt.Println("Got V9 packet, can't handle that yet.")
		} else {
			fmt.Println("Unrecognized datagram received in netflow port.")
		}
	}

}

// Collector is the main function of this package. It will spin up a simple
// UDP server that listens on a user-defined UDP port. Once data is received,
// flow packets will be both forwarded dumped to database. If forwarding is
// enabled and configured, flow data will also be forwarded to configured
// destinations.
func Collector() {
	var conn_port string
	// var forward_servers []string

	// Load up config from viper TOML file. Look for config file in project's
	// root directory.
	viper.SetConfigName("nfgo")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err)
		fmt.Println("Configuration file not found.")
	} else {
		conn_port = strconv.Itoa(viper.GetInt("collector.server_port"))
		// forward_servers = viper.GetStringSlice("collector.forwarding_servers")
	}

	// Spin up UDP listener on port from config
	serv, err := net.ResolveUDPAddr("udp", ":"+conn_port)
	if err != nil {
		//handle error somehow
		fmt.Println("Hit error I guess...")
		fmt.Println(err.Error())
	}
	conn, err := net.ListenUDP("udp", serv)

	// Spin up raw socket for spoofing forwarded datagrams
	rawserv, err := net.ListenPacket("ip4:17", "0.0.0.0")
	rawconn, err := ipv4.NewRawConn(rawserv)

	// I guess defer will wait for function return before executing
	defer conn.Close()
	defer rawconn.Close()

	// make byte slice to hold incoming data
	buf := make([]byte, 1514)

	for {
		// Read incoming connection in buffer.
		_, p, _, _ := rawconn.ReadFrom(buf)

		// Pass raw socket data along with forwarding servers to forwarding function
		// forwardFlow(rawconn, h, p, cm, forward_servers)

		// Here is where some byte decoding needs to happen so we can forward
		// And also dump to database. Since we're not using UDPConn and instead using
		// A raw socket, need to account for 8 byte UDP header.
		unpackRawPacket(p)

		// Dump records to database
		// unpackFlowRecords(records)
	}
}
