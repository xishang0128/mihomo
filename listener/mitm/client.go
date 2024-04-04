package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func getServerConn(serverConn *N.BufferedConn, srcConn net.Conn, request *http.Request, tunnel C.Tunnel, additions ...inbound.Addition) (*N.BufferedConn, error) {
	if serverConn != nil {
		return serverConn, nil
	}

	address := request.URL.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if request.TLS != nil {
			port = "443"
		}
		address = net.JoinHostPort(address, port)
	}

	dstAddr := socks5.ParseAddr(address)
	if dstAddr == nil {
		return nil, socks5.ErrAddressNotSupported
	}

	left, right := net.Pipe()

	go tunnel.HandleTCPConn(inbound.NewMitm(dstAddr, srcConn, request.Header.Get("User-Agent"), request.URL.String(), right, additions...))

	if request.TLS != nil {
		tlsConn := tls.Client(left, &tls.Config{
			ServerName: request.TLS.ServerName,
		})

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		serverConn = N.NewBufferedConn(tlsConn)
	} else {
		serverConn = N.NewBufferedConn(left)
	}

	return serverConn, nil
}
