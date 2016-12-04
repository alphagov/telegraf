package client

import "io"

type Client interface {
	Query(command string) error

	Write(b []byte) (int, error)
	WriteStream(b io.Reader, size int) (int, error)
	//WriteWithParams(b []byte, params WriteParams) (int, error)

	Close() error
}
