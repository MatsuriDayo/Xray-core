package v2ray_plugin

//go:generate errorgen

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/shadowsocks/plugin"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"

	"github.com/xtls/xray-core/proxy/freedom"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/quic"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"

	vlog "github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
)

func createConfig(pluginOpts plugin.Args, s *protocol.ServerSpec, lport int) (*core.Config, error) {
	var tls bool
	var cert, certRaw string

	if _, loaded := pluginOpts.Get("tls"); loaded {
		tls = true
	}
	if certPath, certLoaded := pluginOpts.Get("cert"); certLoaded {
		cert = certPath
	}
	if c, certLoaded := pluginOpts.Get("certRaw"); certLoaded {
		certRaw = c
	}

	mode := "websocket"
	if modeOpt, loaded := pluginOpts.Get("mode"); loaded {
		mode = modeOpt
	}

	host := "cloudfront.com"
	path := "/"

	if hostOpt, loaded := pluginOpts.Get("host"); loaded {
		host = hostOpt
	}
	if pathOpt, loaded := pluginOpts.Get("path"); loaded {
		path = pathOpt
	}

	mux := 0
	serviceName := ""
	if a, loaded := pluginOpts.Get("mux"); loaded {
		mux, _ = strconv.Atoi(a)
	}
	if a, loaded := pluginOpts.Get("serviceName"); loaded {
		serviceName = a
	}

	d := s.Destination()
	return generateConfig(lport, int(d.Port), d.Address.String(), mode, path, host, cert, certRaw, mux, tls, serviceName, "info")
}

// from xray-plugin

func logConfig(logLevel string) *vlog.Config {
	config := &vlog.Config{
		ErrorLogLevel: clog.Severity_Warning,
		ErrorLogType:  vlog.LogType_Console,
		AccessLogType: vlog.LogType_Console,
	}
	level := strings.ToLower(logLevel)
	switch level {
	case "debug":
		config.ErrorLogLevel = clog.Severity_Debug
	case "info":
		config.ErrorLogLevel = clog.Severity_Info
	case "error":
		config.ErrorLogLevel = clog.Severity_Error
	case "none":
		config.ErrorLogType = vlog.LogType_None
		config.AccessLogType = vlog.LogType_None
	}
	return config
}

func readCertificate(cert, certRaw string) ([]byte, error) {
	if cert != "" {
		return filesystem.ReadFile(cert)
	}
	if certRaw != "" {
		certHead := "-----BEGIN CERTIFICATE-----"
		certTail := "-----END CERTIFICATE-----"
		fixedCert := certHead + "\n" + certRaw + "\n" + certTail
		return []byte(fixedCert), nil
	}
	panic("thou shalt not reach hear")
}

func generateConfig(lport, rport int, remoteAddr, mode, path, host, cert, certRaw string, mux int, tlsEnabled bool, serviceName, logLevel string) (*core.Config, error) {
	outboundProxy := serial.ToTypedMessage(&freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{
			Server: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.ParseAddress(remoteAddr)),
				Port:    uint32(rport),
			},
		},
	})

	var transportSettings proto.Message
	var connectionReuse bool
	switch mode {
	case "websocket":
		var ed uint32
		if u, err := url.Parse(path); err == nil {
			if q := u.Query(); q.Get("ed") != "" {
				Ed, _ := strconv.Atoi(q.Get("ed"))
				ed = uint32(Ed)
				q.Del("ed")
				u.RawQuery = q.Encode()
				path = u.String()
			}
		}
		transportSettings = &websocket.Config{
			Path: path,
			Header: []*websocket.Header{
				{Key: "Host", Value: host},
			},
			Ed: ed,
		}
		if mux != 0 {
			connectionReuse = true
		}
	case "quic":
		transportSettings = &quic.Config{
			Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE},
		}
		tlsEnabled = true
	case "grpc":
		transportSettings = &grpc.Config{
			ServiceName: serviceName,
		}
	default:
		return nil, newError("unsupported mode:", mode)
	}

	streamConfig := internet.StreamConfig{
		ProtocolName: mode,
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: mode,
			Settings:     serial.ToTypedMessage(transportSettings),
		}},
	}

	if tlsEnabled {
		tlsConfig := tls.Config{ServerName: host}
		if cert != "" || certRaw != "" {
			var err error
			certificate := tls.Certificate{Usage: tls.Certificate_AUTHORITY_VERIFY}
			certificate.Certificate, err = readCertificate(cert, certRaw)
			if err != nil {
				return nil, newError("failed to read cert").Base(err)
			}
			tlsConfig.Certificate = []*tls.Certificate{&certificate}
		}
		streamConfig.SecurityType = serial.GetMessageType(&tlsConfig)
		streamConfig.SecuritySettings = []*serial.TypedMessage{serial.ToTypedMessage(&tlsConfig)}
	}

	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(logConfig(logLevel)),
	}

	senderConfig := proxyman.SenderConfig{StreamSettings: &streamConfig}
	if connectionReuse {
		senderConfig.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: int32(mux)}
	}
	return &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortList: &net.PortList{
					Range: []*net.PortRange{net.SinglePortRange(net.Port(lport))},
				},
				Listen: net.NewIPOrDomain(net.LocalHostIP),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				Address:  net.NewIPOrDomain(net.LocalHostIP),
				Networks: []net.Network{net.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&senderConfig),
			ProxySettings:  outboundProxy,
		}},
		App: apps,
	}, nil
}
