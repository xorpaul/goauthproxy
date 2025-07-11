package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	h "github.com/xorpaul/gohelper"
)

var (
	start                     time.Time
	buildtime                 string
	requestCounter            int
	forbiddenRequestCounter   int
	failedRequestCounter      int
	nonexistingRequestCounter int
	config                    ConfigSettings
	mainPromCounters          map[string]prometheus.Counter
	endpoints                 map[string]EndpointSettings
	mutex                     sync.Mutex
	buildversion              string
)

// configSettings contains the key value pairs from the config file
type ConfigSettings struct {
	Debug                  bool          `yaml:"debug"`
	Timeout                time.Duration `yaml:"timeout"`
	ListenAddress          string        `yaml:"listen_address"`
	ListenPort             int           `yaml:"listen_port"`
	PrivateKey             string        `yaml:"ssl_private_key"`
	CertificateFile        string        `yaml:"ssl_certificate_file"`
	ClientCertCaFiles      []string      `yaml:"ssl_client_cert_ca_files"`
	ClientCertCas          []*x509.Certificate
	LogBaseDir             string   `yaml:"log_base_dir"`
	CacheBaseDir           string   `yaml:"cache_base_dir"`
	RequestsTrustedRootCas []string `yaml:"requests_trusted_root_cas"`
	Endpoints              map[string]EndpointSettings
	Hostname               string
	ProxyNetworkStrings    []string `yaml:"reverse_proxy_networks"`
	ProxyNetworks          []net.IPNet
}

type EndpointSettings struct {
	Name                      string
	AllowedIps                []string `yaml:"allowed_ips"`
	AllowedDistinguishedNames []string `yaml:"allowed_distinguishednames"`
	Url                       string   `yaml:"url"`
	UrlObject                 *url.URL
	UrlDynamic                bool              `yaml:"url_dynamic"`
	ReqDataDynamic            bool              `yaml:"req_data_dynamic"`
	ArgRegexes                map[string]string `yaml:"argument_regexes"`
	ArgRegexesObjects         map[string]*regexp.Regexp
	Headers                   map[string]string `yaml:"headers"`
	PostData                  string            `yaml:"post_data"`
	HttpType                  string            `yaml:"http_type"`
	PassThrough               bool              `yaml:"pass_through"`
	Proxy                     string            `yaml:"proxy"`
	PromCounters              map[string]prometheus.Counter
	CacheTTLString            string `yaml:"cache_ttl"`
	CacheTTL                  time.Duration
}

type HttpResult struct {
	Code            int
	Body            []byte
	ResponseHeaders map[string]string
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

	hostname, err := os.Hostname()
	if err != nil {
		h.Fatalf("Error: unable to determine hostname to add to each response as a response header. Error: " + err.Error())
	}
	config.Hostname = hostname

	http.HandleFunc("/", httpHandler)

	// TLS stuff
	tlsConfig := &tls.Config{}
	//Use only TLS v1.2
	tlsConfig.MinVersion = tls.VersionTLS12

	//Expect and verify client certificate against a CA cert
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

	caCertPool := x509.NewCertPool()
	for _, clientCAFile := range config.ClientCertCaFiles {
		if !h.FileExists(clientCAFile) {
			h.Fatalf("could not find client CA file: " + clientCAFile)
		} else {
			// Load CA cert
			caCert, err := os.ReadFile(clientCAFile)
			if err != nil {
				h.Fatalf("Error while reading client certificate CA file " + clientCAFile + " Error: " + err.Error())
			}
			caCertPool.AppendCertsFromPEM(caCert)
			h.Debugf("Expecting and verifying client certificate against " + clientCAFile)
		}
	}
	tlsConfig.ClientCAs = caCertPool

	server := &http.Server{
		Addr:      config.ListenAddress + ":" + strconv.Itoa(config.ListenPort),
		TLSConfig: tlsConfig,
	}

	log.Print("Listening on https://" + config.ListenAddress + ":" + strconv.Itoa(config.ListenPort) + "/")
	go func() {
		if err := server.ListenAndServeTLS(config.CertificateFile, config.PrivateKey); err != nil {
			log.Fatal(err)
		}
	}()

	// prometheus metrics server
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe("127.0.0.1:2112", nil)

	select {}
}
