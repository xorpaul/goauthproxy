package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	h "github.com/xorpaul/gohelper"
	"gopkg.in/yaml.v2"
)

// readConfigfile creates the ConfigSettings struct from the g10k config file
func readConfigfile(configFile string) ConfigSettings {
	h.Debugf("Trying to read goauthproxy config file: " + configFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		h.Fatalf("readConfigfile(): There was an error parsing the config file " + configFile + ": " + err.Error())
	}

	var config ConfigSettings
	err = yaml.Unmarshal([]byte(data), &config)
	if err != nil {
		h.Fatalf("YAML unmarshal error: " + err.Error())
	}

	mainPromCounters = make(map[string]prometheus.Counter)
	mainPromCounters["successful"] = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goauthproxy_endpoint_main_successful_requests",
		Help: "The total number of successful requests for main",
	})
	mainPromCounters["nonexisting"] = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goauthproxy_endpoint_main_nonexisting_requests",
		Help: "The total number of nonexisting endpoint requests for main",
	})
	mainPromCounters["forbidden"] = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goauthproxy_endpoint_main_forbidden_requests",
		Help: "The total number of forbidden requests for main",
	})
	mainPromCounters["error"] = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goauthproxy_endpoint_main_error_requests",
		Help: "The total number of errors for requests for main",
	})
	if len(config.CacheBaseDir) > 0 {
		config.CacheBaseDir, err = h.CheckDirAndCreate(config.CacheBaseDir, "cache base dir")
		if err != nil {
			h.Fatalf("Error while trying to create cache_base_dir " + config.CacheBaseDir + " Error: " + err.Error())
		}
	}

	endpoints = make(map[string]EndpointSettings)
	for epName, ep := range config.Endpoints {

		if !ep.UrlDynamic {
			ep.UrlObject, err = url.Parse(ep.Url)
			if err != nil {
				h.Fatalf("Failed to parse endpoint URL " + ep.Url + " from endpoint " + epName + " Error: " + err.Error())
			}
		} else {
			// make sure arg regexes are ok at startup and not while trying to parse them
			ep.ArgRegexesObjects = make(map[string]*regexp.Regexp)
			for regexNumber, regex := range ep.ArgRegexes {
				ep.ArgRegexesObjects[regexNumber], err = regexp.Compile(regex)
				if err != nil {
					h.Fatalf("Error while parsing endpoint setting " + epName + " argument regex number " + regexNumber + " Error:" + err.Error())
				}
			}
		}

		promCounters := make(map[string]prometheus.Counter)
		promCompatibleEndpointName := strings.ReplaceAll(epName, "-", "_")
		promCounters["successful"] = promauto.NewCounter(prometheus.CounterOpts{
			Name:        "goauthproxy_endpoint_requests_total",
			Help:        "The total number of requests for the respective endpoint",
			ConstLabels: prometheus.Labels{"endpoint": promCompatibleEndpointName, "state": "successful"},
		})
		promCounters["forbidden"] = promauto.NewCounter(prometheus.CounterOpts{
			Name:        "goauthproxy_endpoint_requests_total",
			Help:        "The total number of requests for the respective endpoint",
			ConstLabels: prometheus.Labels{"endpoint": promCompatibleEndpointName, "state": "forbidden"},
		})
		promCounters["error"] = promauto.NewCounter(prometheus.CounterOpts{
			Name:        "goauthproxy_endpoint_requests_total",
			Help:        "The total number of requests for the respective endpoint",
			ConstLabels: prometheus.Labels{"endpoint": promCompatibleEndpointName, "state": "error"},
		})

		ep.PromCounters = promCounters

		if len(ep.CacheTTLString) > 0 {
			if len(config.CacheBaseDir) == 0 {
				h.Fatalf("Error can not set a cache_ttl endpoint setting without setting the general cache_base_dir setting!")
			}
			ep.CacheTTL, err = time.ParseDuration(ep.CacheTTLString)
			if err != nil {
				h.Fatalf("Error while parsing endpoint setting " + epName + " argument cache_ttl" + ep.CacheTTLString + " Error:" + err.Error())
			}
		}
		// fmt.Printf("%+v\n", ep)
		endpoints[epName] = ep
	}

	// add and parse optional client CAs
	for _, clientCAFile := range config.ClientCertCaFiles {
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			h.Fatalf("error while reading CA file " + clientCAFile + " Error: " + err.Error())
		}
		// check if CA file is in PEM or DER format, we need DER in the end
		if strings.Count(string(caCert), "-----BEGIN CERTIFICATE-----") < 2 {
			block, _ := pem.Decode(caCert)
			if block == nil || block.Type != "CERTIFICATE" {
				h.Fatalf("Error while decoding client certificate CA file " + clientCAFile + " got block type " + block.Type + " Error: " + err.Error())
			}
			caCert = block.Bytes
		}
		caCertParsed, err := x509.ParseCertificate(caCert)
		if err != nil {
			h.Fatalf("error while parsing CA file " + clientCAFile + " expected in DER format Error: " + err.Error())
		}
		config.ClientCertCas = append(config.ClientCertCas, caCertParsed)
	}

	config.ProxyNetworks = ParseNetworks(config.ProxyNetworkStrings, "in reverse_proxy_networks")

	// fmt.Printf("%+v\n", config)
	return config
}

func ParseNetworks(networkStrings []string, contextMessage string) []net.IPNet {
	var networks []net.IPNet
	for _, networkString := range networkStrings {
		_, network, err := net.ParseCIDR(networkString)
		if err != nil {
			m := contextMessage + ": failed to parse CIDR '" + networkString + "' " + err.Error()
			h.Fatalf(m)
		}
		networks = append(networks, *network)
	}
	return networks
}
