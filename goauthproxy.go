package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	h "github.com/xorpaul/gohelper"
)

var start time.Time
var buildtime string
var requestCounter int
var forbiddenRequestCounter int
var failedRequestCounter int
var config ConfigSettings
var buildversion string

// configSettings contains the key value pairs from the config file
type ConfigSettings struct {
	Debug                  bool          `yaml:"debug"`
	Timeout                time.Duration `yaml:"timeout"`
	ListenAddress          string        `yaml:"listen_address"`
	ListenPort             int           `yaml:"listen_port"`
	PrivateKey             string        `yaml:"ssl_private_key"`
	CertificateFile        string        `yaml:"ssl_certificate_file"`
	ClientCertCaFile       string        `yaml:"ssl_client_cert_ca_file"`
	LogBaseDir             string        `yaml:"log_base_dir"`
	RequestsTrustedRootCas []string      `yaml:"requests_trusted_root_cas"`
	Endpoints              map[string]endpointSettings
}

type endpointSettings struct {
	Name        string
	AllowedIps  []string `yaml:"allowed_Ips"`
	AllowedCns  []string `yaml:"allowed_cns"`
	Url         string   `yaml:"url"`
	UrlObject   *url.URL
	Headers     map[string]string `yaml:"headers"`
	PostData    string            `yaml:"post_data"`
	HttpType    string            `yaml:"http_type"`
	PassThrough bool              `yaml:"pass_through"`
	Proxy       string            `yaml:"proxy"`
}

type HttpResult struct {
	Code int
	Body []byte
}

func main() {
	start = time.Now()

	var (
		configFile  = flag.String("config", "/etc/goauthproxy/config.yaml", "which config file to use at startup, defaults to /etc/goauthproxy/config.yaml")
		debugFlag   = flag.Bool("debug", false, "log debug output, defaults to false")
		versionFlag = flag.Bool("version", false, "show build time and version number")
	)

	flag.Parse()

	version := *versionFlag

	if version {
		fmt.Println("goauthproxy", buildversion, "Build time:", buildtime, "UTC")
		os.Exit(0)
	}

	if *debugFlag {
		h.Debug = true
		h.Debugf("starting in DEBUG mode")
	} else {
		h.Info = true
	}

	h.Debugf("using config file " + *configFile)
	config = readConfigfile(*configFile)
	if config.Debug {
		h.Debug = true
		h.Debugf("DEBUG mode set in config file " + *configFile)
	}

	http.HandleFunc("/", httpHandler)

	// TLS stuff
	tlsConfig := &tls.Config{}
	//Use only TLS v1.2
	tlsConfig.MinVersion = tls.VersionTLS12

	//Expect and verify client certificate against a CA cert
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

	if len(config.ClientCertCaFile) > 1 {
		if !h.FileExists(config.ClientCertCaFile) {
			h.Fatalf("could not find client CA file: " + config.ClientCertCaFile)
		} else {
			// Load CA cert
			caCert, err := ioutil.ReadFile(config.ClientCertCaFile)
			if err != nil {
				h.Fatalf("Error while reading client certificate CA file " + config.ClientCertCaFile + " Error: " + err.Error())
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			h.Debugf("Expecting and verifying client certificate against " + config.ClientCertCaFile)
		}
	} else {
		h.Fatalf("A client certificate CA file needs to be specified if client certificate verification is enabled")
	}

	server := &http.Server{
		Addr:      config.ListenAddress + ":" + strconv.Itoa(config.ListenPort),
		TLSConfig: tlsConfig,
	}

	log.Print("Listening on https://" + config.ListenAddress + ":" + strconv.Itoa(config.ListenPort) + "/")
	if err := server.ListenAndServeTLS(config.CertificateFile, config.PrivateKey); err != nil {
		log.Fatal(err)
	}
}
