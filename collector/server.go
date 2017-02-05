package collector

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"github.com/tehmaze/netflow"
	"github.com/tehmaze/netflow/netflow5"
	"github.com/tehmaze/netflow/netflow9"
	"github.com/tehmaze/netflow/session"
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

	// Create decoder map
	decoders := make(map[string]*netflow.Decoder)

	for {
		// make byte slice to hold incoming data
		buf := make([]byte, 8192)

		// Read incoming UDP connection in buffer.
		count, endpoint, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading from:", endpoint)
		}

		d, found := decoders[endpoint.String()]
		if !found {
			s := session.New()
			d = netflow.NewDecoder(s)
			decoders[endpoint.String()] = d
		}

		// TODO: When server starts, this buffer read produceds
		// EOF error for about 30-45 seconds before starting to
		// work. Needs some debugging.
		m, err := d.Read(bytes.NewBuffer(buf[:count]))
		if err != nil {
			fmt.Println("Decoder error:", err)
			continue
		}

		// Only going to support v5/v9 for now.
		switch p := m.(type) {
		case *netflow5.Packet:
			netflow5.Dump(p)
		case *netflow9.Packet:
			netflow9.Dump(p)
		}

	}
}
