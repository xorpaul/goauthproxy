package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	h "github.com/xorpaul/gohelper"
	"gopkg.in/yaml.v2"
)

// readConfigfile creates the ConfigSettings struct from the g10k config file
func readConfigfile(configFile string) ConfigSettings {
	h.Debugf("Trying to read goauthproxy config file: " + configFile)
	data, err := ioutil.ReadFile(configFile)
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
					h.Fatalf("Error while parsing argument regex number " + regexNumber + " Error:" + err.Error())
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

		// fmt.Printf("%+v\n", ep)
		endpoints[epName] = ep
	}

	// add and parse optional client CAs
	for _, clientCAFile := range config.ClientCertCaFiles {
		caCert, err := ioutil.ReadFile(clientCAFile)
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

	// fmt.Printf("%+v\n", config)
	return config
}
