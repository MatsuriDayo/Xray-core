package v2ray_plugin

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/shadowsocks/plugin"
	"net"
)

func init() {
	plugin.NewV2rayPlugin = newV2rayPlugin
}

func newV2rayPlugin(pluginOpts plugin.Args, s *protocol.ServerSpec) (p plugin.V2rayPlugin, err error) {
	// create config

	lport, err := GetFreePort()
	if err != nil {
		err = E.Cause(err, "GetFreePort")
		return
	}

	p.LocalPort = uint16(lport)
	config, err := createConfig(pluginOpts, s, lport)
	if err != nil {
		err = E.Cause(err, "createConfig")
		return
	}

	// create core

	instance, err := core.New(config)
	if err != nil {
		err = E.New("create core ", err)
		return
	}

	err = instance.Start()
	if err != nil {
		err = E.New("start core ", err)
		return
	}

	p.Core = instance
	return
}

func GetFreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer common.Close(ln)
	return ln.Addr().(*net.TCPAddr).Port, nil
}
