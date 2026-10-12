package kuaifan

import "github.com/oshinop/chinadapter/internal/provider"

// KuaiFan WIFIIN supports UDP-over-TCP; losing this method must fail the build
// rather than silently turning UDP ASSOCIATE into a 0x07 reply.
var _ provider.DatagramTransport = (*Transport)(nil)
