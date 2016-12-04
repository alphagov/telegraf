package client

import (
	"fmt"
	"io"
	"net"
)

const (
	// UDPPayloadSize is a reasonable default payload size for UDP packets that
	// could be travelling over the internet.
	UDPPayloadSize = 512
)

// UDPConfig is the config data needed to create a UDP Client
type UDPConfig struct {
	// Addr should be of the form "host:port"
	// or "[ipv6-host%zone]:port".
	Addr string

	// PayloadSize is the maximum size of a UDP client message, optional
	// Tune this based on your network. Defaults to UDPPayloadSize.
	PayloadSize int
}

func NewUDP(config UDPConfig) (Client, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", config.Addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}

	size := config.PayloadSize
	if size == 0 {
		size = UDPPayloadSize
	}
	buf := make([]byte, size)
	return &udpClient{conn: conn, buffer: buf}, nil
}

type udpClient struct {
	conn   *net.UDPConn
	buffer []byte
}

func (c *udpClient) Query(command string) error {
	return nil
}

func (c *udpClient) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

// size is ignored by the UDP client.
func (c *udpClient) WriteStream(b io.Reader, size int) (int, error) {
	n, err := io.CopyBuffer(c.conn, b, c.buffer)
	if int(n) != size {
		return int(n), fmt.Errorf("Expected to write %d bytes, only wrote %d", size, n)
	}
	return int(n), err
}

func (c *udpClient) Close() error {
	return c.conn.Close()
}
