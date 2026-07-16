package grpcservice

import (
	"fmt"
	"net"
)

type Config struct {
	Port uint32
}

func (c Config) Validate() error {
	lis, err := net.Listen("tcp", c.address())
	if err != nil {
		return fmt.Errorf("invalid port: %s", err)
	}
	// nolint:all
	defer lis.Close()

	return nil
}

func (c Config) address() string {
	return fmt.Sprintf(":%d", c.Port)
}

func (c Config) gatewayAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", c.Port)
}
