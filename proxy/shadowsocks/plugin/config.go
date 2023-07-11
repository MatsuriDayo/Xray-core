package plugin

import (
	"io"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/xtls/xray-core/common/protocol"
	obfs "github.com/xtls/xray-core/proxy/shadowsocks/plugin/simple-obfs"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type ObfsFunc func(c stat.Connection) stat.Connection

type V2rayPlugin struct {
	LocalPort uint16
	Core      io.Closer
}

var NewV2rayPlugin func(pluginOpts Args, s *protocol.ServerSpec) (V2rayPlugin, error)

func NewPlugin(name, opts string, s *protocol.ServerSpec) (obfsFunc ObfsFunc, v2ray *V2rayPlugin, err error) {
	pluginOpts, err := ParsePluginOptions(opts)
	if err != nil {
		return
	}
	switch name {
	case "obfs-local", "simple-obfs":
		obfsFunc, err = NewObfsLocal(pluginOpts, s)
	case "v2ray-plugin":
		if NewV2rayPlugin == nil {
			err = E.New("no newV2rayPlugin")
			return
		}
		var v2ray_ V2rayPlugin
		v2ray_, err = NewV2rayPlugin(pluginOpts, s)
		if err == nil {
			v2ray = &v2ray_
		}
	default:
		err = E.New("unknown plugin: ", name)
	}
	return
}

func NewObfsLocal(pluginOpts Args, s *protocol.ServerSpec) (obfsFunc ObfsFunc, err error) {
	var host string
	var tls bool

	mode := "http"
	if obfsMode, loaded := pluginOpts.Get("obfs"); loaded {
		mode = obfsMode
	}
	if obfsHost, loaded := pluginOpts.Get("obfs-host"); loaded {
		host = obfsHost
	}
	switch mode {
	case "http":
	case "tls":
		tls = true
	default:
		return nil, E.New("unknown obfs mode ", mode)
	}

	if tls {
		obfsFunc = func(c stat.Connection) stat.Connection {
			return obfs.NewTLSObfs(c, host)
		}
	} else {
		obfsFunc = func(c stat.Connection) stat.Connection {
			return obfs.NewHTTPObfs(c, host, s.Destination().Port.String())
		}
	}

	return
}
