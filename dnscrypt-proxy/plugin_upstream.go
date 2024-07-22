package main

import (
	"math/rand"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginUpstream struct {
	servers []string
}

func (plugin *PluginUpstream) Name() string {
	return "upstream"
}

func (plugin *PluginUpstream) Description() string {
	return "Query the upstream server, it's usually a specified intranet DNS. If no result is obtained, the process will not be terminated."
}

func (plugin *PluginUpstream) Init(proxy *Proxy) error {
	plugin.servers = proxy.UpstreamServers
	return nil
}

func (plugin *PluginUpstream) Drop() error {
	return nil
}

func (plugin *PluginUpstream) Reload() error {
	return nil
}

func (plugin *PluginUpstream) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	servers := plugin.servers
	if len(servers) == 0 {
		return nil
	}

	server := servers[rand.Intn(len(servers))]
	client := dns.Client{Net: pluginsState.serverProto, Timeout: pluginsState.timeout}
	respMsg, _, err := client.Exchange(msg, server)
	if err != nil {
		dlog.Warnf("upstream server error: %v", err)
		return nil
	}
	if respMsg.Truncated {
		client.Net = "tcp"
		respMsg, _, err = client.Exchange(msg, server)
		if err != nil {
			return err
		}
	}
	if edns0 := respMsg.IsEdns0(); edns0 == nil || !edns0.Do() {
		respMsg.AuthenticatedData = false
	}

	if len(respMsg.Answer) == 0 {
		return nil
	}

	respMsg.Id = msg.Id
	pluginsState.serverName = server
	pluginsState.synthResponse = respMsg
	pluginsState.action = PluginsActionSynth
	pluginsState.returnCode = PluginsReturnCodeUpstream
	return nil
}
