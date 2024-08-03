package mitm

import (
	"crypto/tls"
	"net"
	"net/http"

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
func New(option *Option, tunnel C.Tunnel) (*Listener, error) {
	return NewWithAuthenticate(option, tunnel, authStore.Authenticator())
}

func NewWithAuthenticate(option *Option, tunnel C.Tunnel, authenticator auth.Authenticator) (*Listener, error) {
	l, err := net.Listen("tcp", option.Addr)
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
			conn, err1 := hl.listener.Accept()
			if err1 != nil {
				if hl.closed {
					break
				}
				continue
			}
			go HandleConn(conn, option, tunnel, authenticator)
		}
	}()

	return hl, nil
}
