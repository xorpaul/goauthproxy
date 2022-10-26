package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"net/url"
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

func issueRequest(rid string, ep endpointSettings, req *http.Request) HttpResult {
	h.Debugf(rid + " sending HTTP " + req.Method + " request to " + ep.Url)
	nReq, err := http.NewRequest(req.Method, ep.Url, nil)
	if ep.PassThrough {
		h.Debugf(rid + " allowing request method " + req.Method + " and body pass-through")

		nReq, err = http.NewRequest(req.Method, ep.Url, req.Body)
		if err != nil {
			responseBody := "Error while creating " + ep.HttpType + " request to " + ep.Url + " with POST body pass-through Error: " + err.Error()
			h.Warnf(responseBody)
			failedRequestCounter++
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}
	} else {
		h.Debugf(rid + "using request body configured in endpointsettings")

		nReq, err = http.NewRequest(ep.HttpType, ep.Url, strings.NewReader(ep.PostData))
		if err != nil {
			responseBody := "Error while creating " + ep.HttpType + " request to " + ep.Url + " Error: " + err.Error()
			h.Warnf(responseBody)
			failedRequestCounter++
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}

	}

	nReq.Header.Add("X-Real-IP", req.RemoteAddr)
	nReq.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	for headerName, header := range ep.Headers {
		nReq.Header.Add(headerName, header)
	}

	client := setupHttpClient(ep)

	before := time.Now()
	resp, err := client.Do(nReq)
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
	// responseSize := fmt.Printf("%.1f", (len(string(body)) / 1024.0))
	responseSize := float64(len(body)) / 1024.0
	h.Debugf(rid + " sending HTTP " + req.Method + " request to " + ep.Url + " took " + strconv.FormatFloat(time.Since(before).Seconds(), 'f', 1, 64) + "s with " + strconv.FormatFloat(responseSize, 'f', 1, 64) + " kByte response body")

	return HttpResult{Code: 200, Body: body}

}

func respond(w http.ResponseWriter, hr HttpResult) {
	w.WriteHeader(hr.Code)
	w.Write(hr.Body)

}

func setupHttpClient(ep endpointSettings) *http.Client {
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
	if len(ep.Proxy) > 0 {
		proxy, err := url.Parse(ep.Proxy)
		if err != nil {
			h.Fatalf("Failed to parse proxy URL " + ep.Proxy + " from endpoint " + ep.Name + " Error: " + err.Error())
		}
		tr.Proxy = http.ProxyURL(proxy)

	}
	return &http.Client{Transport: tr}
}
