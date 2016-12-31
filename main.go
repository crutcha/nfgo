package main

import (
	"fmt"
	"net"
)

const CONN_PORT = "2055"

func main() {
	// Open simple UDP server that outputs packets received to stdout
	serv, err := net.ResolveUDPAddr("udp", ":"+CONN_PORT)
	if err != nil {
		//handle error somehow
		fmt.Println("Hit error I guess...")
		fmt.Println(err.Error())
	}
	conn, err := net.ListenUDP("udp", serv)

	// I guess defer will wait for function return before executing
	defer conn.Close()

	// make buffer for incoming data
	buf := make([]byte, 8960)

	for {
		// Read incoming connection in buffer
		_, endpoint, _ := conn.ReadFromUDP(buf)
		fmt.Println(endpoint)

		// Here is where some byte decoding needs to happen so we can forward
		// and also dump to database
	}
}
