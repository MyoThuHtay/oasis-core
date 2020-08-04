package p2p

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// CfgP2PEnabled enables the P2P worker (automatically enabled if compute worker enabled).
	CfgP2PEnabled = "worker.p2p.enabled"

	// CfgP2pPort configures the P2P port.
	CfgP2pPort = "worker.p2p.port"

	cfgP2pAddresses = "worker.p2p.addresses"
)

// Enabled reads our enabled flag from viper.
func Enabled() bool {
	return viper.GetBool(CfgP2PEnabled)
}

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

func init() {
	Flags.Bool(CfgP2PEnabled, false, "Enable P2P worker (automatically enabled if compute worker enabled).")
	Flags.Uint16(CfgP2pPort, 9200, "Port to use for incoming P2P connections")
	Flags.StringSlice(cfgP2pAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")

	_ = viper.BindPFlags(Flags)
}
