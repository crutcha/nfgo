// Representation of a v5 NetFlow datagram.
//
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

package collector

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

type V5Record struct{}
