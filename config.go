package main

import (
	"io/ioutil"
	"net/url"
	"regexp"

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
		// fmt.Printf("%+v\n", ep)
		endpoints[epName] = ep
	}
	// fmt.Printf("%+v\n", config)
	return config
}
