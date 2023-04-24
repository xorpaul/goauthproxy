package main

import (
	"io/ioutil"
	"net/url"
	"regexp"
	"time"

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
	// fmt.Printf("%+v\n", config)
	return config
}
