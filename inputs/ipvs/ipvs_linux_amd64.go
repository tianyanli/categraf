package ipvs

import (
	_ "embed"
	"fmt"
	"log"
	"math/bits"
	"strconv"
	"syscall"

	"github.com/moby/ipvs"

	"flashcat.cloud/categraf/config"
	"flashcat.cloud/categraf/inputs"
	"flashcat.cloud/categraf/types"
)

const inputName = "ipvs"

type IPVS struct {
	config.PluginConfig

	handle *ipvs.Handle
}

func init() {
	inputs.Add(inputName, func() inputs.Input {
		return &IPVS{}
	})
}

func (i *IPVS) Clone() inputs.Input {
	return &IPVS{}
}

func (i *IPVS) Name() string {
	return inputName
}

// Gather gathers the stats
func (i *IPVS) Gather(slist *types.SampleList) {
	if i.handle == nil {
		h, err := ipvs.New("")
		if err != nil {
			log.Printf("E! Unable to open IPVS handle: %v\n", err)
			return
		}
		i.handle = h
	}

	services, err := i.handle.GetServices()
	if err != nil {
		i.handle.Close()
		i.handle = nil // trigger a reopen on next call to gather
		log.Printf("E! Failed to list IPVS services: %v\n", err)
		return
	}
	for _, s := range services {
		fields := map[string]interface{}{
			"connections": s.Stats.Connections,
			"pkts_in":     s.Stats.PacketsIn,
			"pkts_out":    s.Stats.PacketsOut,
			"bytes_in":    s.Stats.BytesIn,
			"bytes_out":   s.Stats.BytesOut,
			"pps_in":      s.Stats.PPSIn,
			"pps_out":     s.Stats.PPSOut,
			"cps":         s.Stats.CPS,
		}
		slist.PushSamples(inputName, fields, serviceTags(s))

		destinations, err := i.handle.GetDestinations(s)
		if err != nil {
			log.Printf("E! Failed to list destinations for a virtual server: %v\n", err)
			continue // move on to the next virtual server
		}

		for _, d := range destinations {
			fields := map[string]interface{}{
				"active_connections":   d.ActiveConnections,
				"inactive_connections": d.InactiveConnections,
				"connections":          d.Stats.Connections,
				"pkts_in":              d.Stats.PacketsIn,
				"pkts_out":             d.Stats.PacketsOut,
				"bytes_in":             d.Stats.BytesIn,
				"bytes_out":            d.Stats.BytesOut,
				"pps_in":               d.Stats.PPSIn,
				"pps_out":              d.Stats.PPSOut,
				"cps":                  d.Stats.CPS,
			}
			destTags := destinationTags(d)
			if s.FWMark > 0 {
				destTags["virtual_fwmark"] = strconv.Itoa(int(s.FWMark))
			} else {
				destTags["virtual_protocol"] = protocolToString(s.Protocol)
				destTags["virtual_address"] = s.Address.String()
				destTags["virtual_port"] = strconv.Itoa(int(s.Port))
			}
			// acc.AddGauge("ipvs_real_server", fields, destTags)
			slist.PushSamples(inputName, fields, destTags)
		}
	}
}

// helper: given a Service, return tags that identify it
func serviceTags(s *ipvs.Service) map[string]string {
	ret := map[string]string{
		"sched":          s.SchedName,
		"netmask":        strconv.Itoa(bits.OnesCount32(s.Netmask)),
		"address_family": addressFamilyToString(s.AddressFamily),
	}
	// Per the ipvsadm man page, a virtual service is defined "based on
	// protocol/addr/port or firewall mark"
	if s.FWMark > 0 {
		ret["fwmark"] = strconv.Itoa(int(s.FWMark))
	} else {
		ret["protocol"] = protocolToString(s.Protocol)
		ret["address"] = s.Address.String()
		ret["port"] = strconv.Itoa(int(s.Port))
	}
	return ret
}

// helper: given a Destination, return tags that identify it
func destinationTags(d *ipvs.Destination) map[string]string {
	return map[string]string{
		"address":        d.Address.String(),
		"port":           strconv.Itoa(int(d.Port)),
		"address_family": addressFamilyToString(d.AddressFamily),
	}
}

// helper: convert protocol uint16 to human readable string (if possible)
func protocolToString(p uint16) string {
	switch p {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_SCTP:
		return "sctp"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// helper: convert addressFamily to a human readable string
func addressFamilyToString(af uint16) string {
	switch af {
	case syscall.AF_INET:
		return "inet"
	case syscall.AF_INET6:
		return "inet6"
	default:
		return fmt.Sprintf("%d", af)
	}
}
