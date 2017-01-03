package collector

import (
	"fmt"
)

// Representation of a v5 NetFlow datagram.
// Netflow v5 headers are 24 bytes in length.
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       Version Number          |            Count              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           sysUpTime                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           UNIX Secs                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       UNIX Nanoseconds                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         Sequence Number                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Engine Type   |  Engine ID    |      Sampling Interval        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   Bytes  Contents          Description
//   ------------------------------------
//   0-1    Version           Export version number
//   2-3    Count             Number of exported flows
//   4-7    SysUptime         Time in milliseconds since device boot
//   8-11   unix_secs         Count of seconds in Epoch time
//   12-15  unix_nsecs        Residual nanoseconds - Epoch
//   16-19  flow_sequence     Sequence counter of total flows seen
//   20     engine_type       Type of flow-switching engine
//   20     engine_id         Slow number of flow-switching engine
//   22-23  sampling_interval First 2 bits hold sampling mode, remaining
//                            14 bits hold value of sampling interval
//
//   Some documentation shows the last 2 bytes as being 'reserved', but
//   PCAPs of actual v5 exports show this being a sampling interval field.

type V5Header struct {
	Version          uint16
	Count            uint16
	SysUpTime        uint32
	UnixSecs         uint32
	UnixNanoSeconds  uint32
	SequenceNumber   uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

// Netflow v5 flow records are 48 bytes in length.
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Source Address                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                      Destination Address                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Next Hop Address                       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Input Interface        |        Output Interface       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                            Packets                            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             Bytes                             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                           Start Time                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                            End Time                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Source Port           |        Destination Port       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |      Pad      |   TCP Flags   |   Protocol    |     ToS       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Source AS            |        Destination AS         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Src Netmask  |  Dest Netmask |           Padding             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   Bytes  Contents    Description
//   ------------------------------
//   0-3    SrcAddr     Source IP Address
//   4-7    DstAddr     Destination IP Address
//   8-11   NextHop     IP Address of next hop router
//   12-13  Input       SNMP index of input interface
//   14-15  Output      SNMP index of output interface
//   16-19  dPkts       Packets in the flow record
//   20-23  dOctets     Total numbers of bytes in flow
//   24-27  First       SysUpTime at start of flow
//   28-31  Last        SysUpTime at end of flow
//   32-33  SrcPort     Source Port of flow
//   34-35  DstPort     Destination Port of flow
//   36     Pad1        Junk/Blank Space
//   37     TcpFlags    Cumulative OR of TCP flags
//   38     Proto       IP Protocol number
//   39     ToS         IP Type of Service
//   40-41  SrcAs       Origin BGP AS
//   42-43  DstAs       Destination BGP AS
//   44     SrcMask     Source addressp prefix mask bits
//   45     DstMask     Destination address prefix mask bits
//   46-47  Pad2        Junk/Blank Space

type V5Record struct {
	SrcAddr  uint32
	DstAddr  uint32
	NextHop  uint32
	Input    uint16
	Output   uint16
	Dpkts    uint32
	Doctects uint32
	First    uint32
	Last     uint32
	SrcPort  uint16
	DstPort  uint16
	Pad1     uint8
	TcpFlags uint8
	Proto    uint8
	ToS      uint8
	SrcAs    uint16
	DstAs    uint16
	SrcMask  uint8
	DstMask  uint8
	Pad2     uint16
}

// Function to parse version 5 flows. Once the header has been parsed,
// This function can be passed the remainer of the payload slice along
// With flow count from the header and returns a slice of records. It is
// Up to the caller to either inject into database or forward.
func parseV5Flow(records []byte, count int) []V5Record {
	var recslice []V5Record

	// Should we verify that the length of the byte slice is legit and
	// Doesn't contain extra data? We could check for remainer of
	// []byte divided by count from header....
	if len(records)%count != 0 {
		fmt.Println("Payload received by parseV5Flow not of correct len")
	}

	// Loop over passed in count and unpack into flow struct
	for i := 0; i < count; i++ {
		fmt.Println("") // Need some thought on DB model before doing this
	}

	return recslice
}
