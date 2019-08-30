package main

import (
	"fmt"
	"io/ioutil"

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

	fmt.Printf("%+v\n", config)
	return config
}
