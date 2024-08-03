package mitm

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/cert"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
)

type Handler interface {
	HandleRequest(*Session) (*http.Request, *http.Response) // Session.Response maybe nil
	HandleResponse(*Session) *http.Response
	HandleApiRequest(*Session) bool
	HandleError(*Session, error) // Session maybe nil
}

type Option struct {
	Addr    string
	ApiHost string

	TLSConfig  *tls.Config
	CertConfig *cert.Config

	Handler Handler
}

type Listener struct {
	*Option

	listener net.Listener
	addr     string
	closed   bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

// New the MITM proxy actually is a type of HTTP proxy
func New(option *Option, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithAuthenticate(option, tunnel, authStore.Authenticator(), additions...)
}

func NewWithAuthenticate(option *Option, tunnel C.Tunnel, authenticator auth.Authenticator, additions ...inbound.Addition) (*Listener, error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HTTP"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := inbound.Listen("tcp", option.Addr)
	if err != nil {
		return nil, err
	}

	hl := &Listener{
		listener: l,
		addr:     option.Addr,
		Option:   option,
	}
	go func() {
		for {
			conn, err := hl.listener.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}
			if isDefault { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(conn.RemoteAddr()) {
					_ = conn.Close()
					continue
				}
			}
			go HandleConn(conn, option, tunnel, authenticator, additions...)
		}
	}()

	return hl, nil
}
