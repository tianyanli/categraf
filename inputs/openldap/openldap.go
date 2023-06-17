package openldap

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"

	"flashcat.cloud/categraf/config"
	"flashcat.cloud/categraf/inputs"
	"flashcat.cloud/categraf/pkg/tls"
	"flashcat.cloud/categraf/types"
)

const inputName = "openldap"

type OpenLdap struct {
	config.PluginConfig
	Instances []*Instance `toml:"instances"`
}

func init() {
	inputs.Add(inputName, func() inputs.Input {
		return &OpenLdap{}
	})
}

func (pt *OpenLdap) Clone() inputs.Input {
	return &OpenLdap{}
}

func (pt *OpenLdap) Name() string {
	return inputName
}

func (pt *OpenLdap) GetInstances() []inputs.Instance {
	ret := make([]inputs.Instance, len(pt.Instances))
	for i := 0; i < len(pt.Instances); i++ {
		ret[i] = pt.Instances[i]
	}
	return ret
}

type Instance struct {
	config.InstanceConfig
	Host               string `toml:"host"`
	Port               int    `toml:"port"`
	SSL                string `toml:"ssl" deprecated:"1.7.0;use 'tls' instead"`
	TLS                string `toml:"tls"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	SSLCA              string `toml:"ssl_ca" deprecated:"1.7.0;use 'tls_ca' instead"`
	TLSCA              string `toml:"tls_ca"`
	BindDn             string `toml:"bind_dn"`
	BindPassword       string `toml:"bind_password"`
	ReverseMetricNames bool   `toml:"reverse_metric_names"`
}

var searchBase = "cn=Monitor"
var searchFilter = "(|(objectClass=monitorCounterObject)(objectClass=monitorOperation)(objectClass=monitoredObject))"
var searchAttrs = []string{"monitorCounter", "monitorOpInitiated", "monitorOpCompleted", "monitoredInfo"}
var attrTranslate = map[string]string{
	"monitorCounter":     "",
	"monitoredInfo":      "",
	"monitorOpInitiated": "_initiated",
	"monitorOpCompleted": "_completed",
	"olmMDBPagesMax":     "_mdb_pages_max",
	"olmMDBPagesUsed":    "_mdb_pages_used",
	"olmMDBPagesFree":    "_mdb_pages_free",
	"olmMDBReadersMax":   "_mdb_readers_max",
	"olmMDBReadersUsed":  "_mdb_readers_used",
	"olmMDBEntries":      "_mdb_entries",
}

func (ins *Instance) Init() error {
	if len(ins.Host) == 0 {
		return types.ErrInstancesEmpty
	}
	if ins.Port == 0 {
		ins.Port = 389
	}
	return nil
}

// Convert a DN to metric name, eg cn=Read,cn=Waiters,cn=Monitor becomes waiters_read
// Assumes the last part of the DN is cn=Monitor and we want to drop it
func dnToMetric(dn string, ins *Instance) string {
	if ins.ReverseMetricNames {
		var metricParts []string

		dn = strings.Trim(dn, " ")
		dn = strings.ReplaceAll(dn, " ", "_")
		dn = strings.ReplaceAll(dn, "cn=", "")
		dn = strings.ToLower(dn)
		metricParts = strings.Split(dn, ",")
		for i, j := 0, len(metricParts)-1; i < j; i, j = i+1, j-1 {
			metricParts[i], metricParts[j] = metricParts[j], metricParts[i]
		}
		return strings.Join(metricParts[1:], "_")
	}

	metricName := strings.Trim(dn, " ")
	metricName = strings.ReplaceAll(metricName, " ", "_")
	metricName = strings.ToLower(metricName)
	metricName = strings.TrimPrefix(metricName, "cn=")
	metricName = strings.ReplaceAll(metricName, strings.ToLower("cn=Monitor"), "")
	metricName = strings.ReplaceAll(metricName, "cn=", "_")
	return strings.ReplaceAll(metricName, ",", "")
}

// gather metrics
func (ins *Instance) Gather(slist *types.SampleList) {
	if ins.TLS == "" {
		ins.TLS = ins.SSL
	}
	if ins.TLSCA == "" {
		ins.TLSCA = ins.SSLCA
	}

	var err error
	var l *ldap.Conn
	if ins.TLS != "" {
		// build tls config
		clientTLSConfig := tls.ClientConfig{
			TLSCA:              ins.TLSCA,
			InsecureSkipVerify: ins.InsecureSkipVerify,
		}
		tlsConfig, err := clientTLSConfig.TLSConfig()
		if err != nil {
			log.Println("E! Failed to set up TLS:", err)
			return
		}

		switch ins.TLS {
		case "ldaps":
			l, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ins.Host, ins.Port), tlsConfig)
			if err != nil {
				log.Println("E! Failed to connect  LDAP by ldaps:", err)
				return
			}
		case "starttls":
			l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ins.Host, ins.Port))
			if err != nil {
				log.Println("E! Failed to connect  LDAP by starttls:", err)
				return
			}
			err = l.StartTLS(tlsConfig)
			if err != nil {
				log.Println("E! Failed to create a TLS session via StartTLS:", err)
				return
			}
		default:
			log.Printf("E! invalid setting for ssl: %s", ins.TLS)
			return

		}
	} else {
		l, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ins.Host, ins.Port))
	}

	if err != nil {
		log.Println("E! Failed to connect  LDAP:", err)
		return
	}
	defer l.Close()

	// username/password bind
	if ins.BindDn != "" && ins.BindPassword != "" {
		err = l.Bind(ins.BindDn, ins.BindPassword)
		if err != nil {
			log.Println("E! Failed to set BindDn:", err)
			return
		}
	}

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchFilter,
		searchAttrs,
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Println("E! The search failed to execute the given search request:", err)
		return
	}

	gatherSearchResult(sr, ins, slist)

	return
}

func gatherSearchResult(sr *ldap.SearchResult, ins *Instance, slist *types.SampleList) {
	fields := map[string]interface{}{}
	tags := map[string]string{
		"server": ins.Host,
		"port":   strconv.Itoa(ins.Port),
	}
	for _, entry := range sr.Entries {
		metricName := dnToMetric(entry.DN, ins)
		for _, attr := range entry.Attributes {
			if len(attr.Values[0]) >= 1 {
				if v, err := strconv.ParseInt(attr.Values[0], 10, 64); err == nil {
					fields[metricName+attrTranslate[attr.Name]] = v
				}
			}
		}
	}
	slist.PushSamples("openldap", fields, tags)
}
