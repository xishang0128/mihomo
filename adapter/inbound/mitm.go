package inbound

import (
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

// NewMitm receive mitm request and return MitmContext
func NewMitm(target socks5.Addr, srcConn net.Conn, userAgent string, conn net.Conn, additions ...Addition) (net.Conn, *C.Metadata) {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = C.MITM
	metadata.UserAgent = userAgent
	metadata.RawSrcAddr = srcConn.RemoteAddr()
	metadata.RawDstAddr = srcConn.LocalAddr()
	ApplyAdditions(metadata, WithSrcAddr(srcConn.RemoteAddr()), WithInAddr(conn.LocalAddr()))
	ApplyAdditions(metadata, additions...)
	return conn, metadata
}
