// Package traceroute provides functions for executing a tracroute to a remote
// host.
package traceroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const DEFAULT_PORT = 33434
const DEFAULT_MAX_HOPS = 64
const DEFAULT_TIMEOUT_MS = 1000
const DEFAULT_RETRIES = 2
const DEFAULT_PACKET_SIZE = 52

type TracerouteRet struct {
	Domain  string `json:"domain"`
	Errcode int    `json:"errcode"`
	Content string `json:"content"`
}

type HotPoint struct {
	Avg string `json:"avg"`
	Ip  string `json:"ip"`
}

type TracerouteParam struct {
	Domain string `json:"domain"`
	Maxttl int    `json:"maxttl"`
	Retry  int    `json:"retry"`
}

// Return the  outbound ip address as a 4 byte IP address. This address
// is used for sending packets out.
func socketAddr() (addr [4]byte, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		err = errors.New("You do not appear to be connected to the Internet")
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	copy(addr[:], localAddr.IP.To4())
	return

}

// Given a host name convert it to a 4 byte IP address.
func destAddr(dest string) (destAddr [4]byte, err error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return
	}
	addr := addrs[0]

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return
	}
	copy(destAddr[:], ipAddr.IP.To4())
	return
}

// TracrouteOptions type
type TracerouteOptions struct {
	port       int
	maxHops    int
	timeoutMs  int
	retries    int
	packetSize int
}

func (options *TracerouteOptions) Port() int {
	if options.port == 0 {
		options.port = DEFAULT_PORT
	}
	return options.port
}

func (options *TracerouteOptions) SetPort(port int) {
	options.port = port
}

func (options *TracerouteOptions) MaxHops() int {
	if options.maxHops == 0 {
		options.maxHops = DEFAULT_MAX_HOPS
	}
	return options.maxHops
}

func (options *TracerouteOptions) SetMaxHops(maxHops int) {
	options.maxHops = maxHops
}

func (options *TracerouteOptions) TimeoutMs() int {
	if options.timeoutMs == 0 {
		options.timeoutMs = DEFAULT_TIMEOUT_MS
	}
	return options.timeoutMs
}

func (options *TracerouteOptions) SetTimeoutMs(timeoutMs int) {
	options.timeoutMs = timeoutMs
}

func (options *TracerouteOptions) Retries() int {
	if options.retries == 0 {
		options.retries = DEFAULT_RETRIES
	}
	return options.retries
}

func (options *TracerouteOptions) SetRetries(retries int) {
	options.retries = retries
}

func (options *TracerouteOptions) PacketSize() int {
	if options.packetSize == 0 {
		options.packetSize = DEFAULT_PACKET_SIZE
	}
	return options.packetSize
}

func (options *TracerouteOptions) SetPacketSize(packetSize int) {
	options.packetSize = packetSize
}

// TracerouteHop type
type TracerouteHop struct {
	Success     bool
	Address     [4]byte
	Host        string
	N           int
	ElapsedTime time.Duration
	TTL         int
}

func (hop *TracerouteHop) AddressString() string {
	return fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
}

func (hop *TracerouteHop) HostOrAddressString() string {
	hostOrAddr := hop.AddressString()
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	return hostOrAddr
}
func linkHop(hop TracerouteHop, origin *string) {
	addr := fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
	//hostOrAddr := addr
	/*if hop.Host != "" {
		hostOrAddr = hop.Host
	}*/
	if hop.Success {
		*origin += fmt.Sprintf("%-3d %v %.3fms\n", hop.TTL, addr, float64(hop.ElapsedTime)/1000000)
	} else {
		*origin += fmt.Sprintf("%-3d *\n", hop.TTL)
	}
}

// TracerouteResult type
type TracerouteResult struct {
	DestinationAddress [4]byte
	Hops               []TracerouteHop
}

// Traceroute uses the given dest (hostname) and options to execute a traceroute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Returns a TracerouteResult which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func traceroute(dest string, options *TracerouteOptions) (result TracerouteResult, err error) {
	result.Hops = []TracerouteHop{}
	destAddr, err := destAddr(dest)
	result.DestinationAddress = destAddr
	socketAddr, err := socketAddr()
	if err != nil {
		return
	}

	timeoutMs := (int64)(options.TimeoutMs())
	tv := syscall.NsecToTimeval(1000 * 1000 * timeoutMs)

	ttl := 1
	retry := 0
	for {
		//log.Println("TTL: ", ttl)
		start := time.Now()

		// Set up the socket to receive inbound packets
		recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			return result, err
		}

		// Set up the socket to send packets out.
		sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			return result, err
		}
		// This sets the current hop TTL
		syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
		// This sets the timeout to wait for a response from the remote host
		syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		defer syscall.Close(recvSocket)
		defer syscall.Close(sendSocket)

		// Bind to the local socket to listen for ICMP packets
		syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: options.Port(), Addr: socketAddr})

		// Send a single null byte UDP packet
		syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: options.Port(), Addr: destAddr})

		var p = make([]byte, options.PacketSize())
		n, from, err := syscall.Recvfrom(recvSocket, p, 0)
		elapsed := time.Since(start)
		if err == nil {
			currAddr := from.(*syscall.SockaddrInet4).Addr

			hop := TracerouteHop{Success: true, Address: currAddr, N: n, ElapsedTime: elapsed, TTL: ttl}
			result.Hops = append(result.Hops, hop)

			ttl += 1
			retry = 0

			if ttl > options.MaxHops() || currAddr == destAddr {
				return result, nil
			}
		} else {
			retry += 1
			if retry > options.Retries() {
				hop := TracerouteHop{Success: false, TTL: ttl}
				result.Hops = append(result.Hops, hop)
				ttl += 1
				retry = 0
			}

			if ttl > options.MaxHops() {
				return result, nil
			}
		}
	}
}

type TraceParam struct {
	Domain string
	Maxttl int
	Retry  int
}

func (args *TraceParam) Run() (string, error) {
	options := TracerouteOptions{}
	options.SetRetries(args.Retry)
	options.SetMaxHops(args.Maxttl)
	var result TracerouteResult
	var err error
	if err != nil {
		return "", err
	}
	result, err = traceroute(args.Domain, &options)
	if err != nil {
		return "", err
	}
	hotList := []HotPoint{}
	for _, hop := range result.Hops {
		addr := fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
		if hop.Success {
			x := HotPoint{
				Avg: fmt.Sprintf("%.4fms", float64(hop.ElapsedTime)/1000000),
				Ip:  addr,
			}
			hotList = append(hotList, x)
		} else {
			x := HotPoint{}
			hotList = append(hotList, x)
		}
	}
	data, _ := json.Marshal(hotList)
	return string(data), nil
}

func NewTrace(args string) (*TraceParam, error) {
	tempTrace := new(TraceParam)
	if err := json.Unmarshal([]byte(args), tempTrace); err != nil {
		return nil, err
	}
	return tempTrace, nil
}
