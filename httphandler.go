package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	h "github.com/xorpaul/gohelper"
)

func httpHandler(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	method := r.Method
	rid := h.RandSeq()
	h.Debugf(rid + " Incoming " + method + " request from IP: " + ip)
	h.Debugf(rid + " Request path: " + r.URL.Path)
	r.ParseForm()

	if r.URL.Path == "/" {
		requestCounter++
		response := "uptime=" + strconv.FormatFloat(time.Since(start).Seconds(), 'f', 1, 64) + "s"
		response += " requests=" + strconv.Itoa(requestCounter)
		response += " forbiddenrequests=" + strconv.Itoa(forbiddenRequestCounter)
		response += " failedrequests=" + strconv.Itoa(failedRequestCounter)
		respond(w, HttpResult{Code: 200, Body: []byte(response)})
		return
	}

	for epName, ep := range config.Endpoints {
		if r.URL.Path == epName {
			requestCounter++
			h.Debugf(rid + " found endpoint " + epName)
			if verifyClientCertificate(rid, epName, ep, r) {
				respond(w, issueRequest(rid, ep, r))
				return
			} else {
				respond(w, HttpResult{Code: 403, Body: []byte("No matching client certificate found")})
				return
			}
		}
	}
	forbiddenRequestCounter++
	response := rid + " no matching endpoint found for " + r.URL.Path
	h.Debugf(response)
	respond(w, HttpResult{Code: 404, Body: []byte(response)})
	return
}

func verifyClientCertificate(rid string, epName string, ep endpointSettings, r *http.Request) bool {
	if len(ep.AllowedCns) > 0 {
		for _, peerCertificate := range r.TLS.PeerCertificates {
			pcs := peerCertificate.Subject.String()
			h.Debugf(rid + " checking client cert " + pcs + " for endpoint " + epName)
			for _, cn := range ep.AllowedCns {
				if pcs == cn {
					h.Debugf(rid + " found matching client cert " + pcs + " for endpoint " + epName)
					return true
				}
			}
		}
		return false
	} else {
		return true
	}
}

func issueRequest(rid string, ep endpointSettings, r *http.Request) HttpResult {
	h.Debugf("sending HTTP request " + ep.Url)
	req, err := http.NewRequest(ep.HttpType, ep.Url, strings.NewReader(ep.PostData))
	if err != nil {
		h.Fatalf("Error while creating " + ep.HttpType + " request to " + ep.Url + " Error: " + err.Error())
	}
	req.Header.Add("X-Real-IP", r.RemoteAddr)
	for headerName, header := range ep.Headers {
		req.Header.Add(headerName, header)
	}

	client := setupHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		responseBody := "Error while issuing request to " + ep.Url + " Error: " + err.Error()
		h.Warnf(responseBody)
		failedRequestCounter++
		return HttpResult{Code: 503, Body: []byte(responseBody)}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		responseBody := "Error while reading response body: " + err.Error()
		h.Warnf(responseBody)
		failedRequestCounter++
		return HttpResult{Code: 503, Body: []byte(responseBody)}
	}
	//h.Debugf("Received response: " + string(body))

	return HttpResult{Code: 200, Body: body}

}

func respond(w http.ResponseWriter, hr HttpResult) {
	w.WriteHeader(hr.Code)
	w.Write(hr.Body)

}

func setupHttpClient() *http.Client {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	for _, rootCaFile := range config.RequestsTrustedRootCas {
		// Read in the cert file
		cert, err := ioutil.ReadFile(rootCaFile)
		if err != nil {
			h.Fatalf("Failed to append " + rootCaFile + " to RootCAs Error: " + err.Error())
		}

		// Append our cert to the system pool
		h.Debugf("Appending certificate " + rootCaFile + " to trusted CAs")
		if ok := rootCAs.AppendCertsFromPEM(cert); !ok {
			h.Debugf("No certs appended, using system certs only")
		}
	}

	// Trust the augmented cert pool in our client
	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: tr}
}
