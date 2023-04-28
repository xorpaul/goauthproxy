package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	h "github.com/xorpaul/gohelper"
)

func httpHandler(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]
	method := r.Method
	rid := h.RandSeq()
	// h.Debugf(rid + " Incoming " + method + " request from IP: " + ip)
	// h.Debugf(rid + " Request path: " + r.URL.Path)

	if r.URL.Path == "/" {
		requestCounter++
		response := "uptime=" + strconv.FormatFloat(time.Since(start).Seconds(), 'f', 1, 64) + "s"
		response += " requests=" + strconv.Itoa(requestCounter)
		response += " nonexistingrequests=" + strconv.Itoa(nonexistingRequestCounter)
		response += " forbiddenrequests=" + strconv.Itoa(forbiddenRequestCounter)
		response += " failedrequests=" + strconv.Itoa(failedRequestCounter)
		respond(w, HttpResult{Code: 200, Body: []byte(response)}, mainPromCounters)
		return
	} else {
		h.Debugf(rid + " Incoming " + method + " request from IP: " + ip)
		h.Debugf(rid + " Request path: " + r.URL.Path)
	}

	uri := r.URL.Path
	for epName, ep := range endpoints {
		ep.Name = epName
		if strings.Count(r.URL.Path, "/") > 1 {
			urlParts := strings.Split(r.URL.Path, "/")
			uri = "/" + urlParts[1]
		}
		if uri == epName {
			if uri != "/" {
				requestCounter++
			}
			h.Debugf(rid + " found endpoint " + epName)
			result, err := verifyClientCertificate(rid, ep, r)
			// fmt.Println("verify client result", result)
			if err != nil || !result {
				respond(w, HttpResult{Code: 403, Body: []byte("No matching client certificate found for endpoint " + uri)}, ep.PromCounters)
				return
			} else {
				respond(w, issueRequest(rid, ep, r), ep.PromCounters)
				return
			}
		}
	}
	response := rid + " no matching endpoint found for " + uri
	// h.Debugf(response)
	respond(w, HttpResult{Code: 404, Body: []byte(response)}, mainPromCounters)
}

func issueRequest(rid string, ep EndpointSettings, req *http.Request) HttpResult {
	if ep.UrlDynamic {
		var err error
		ep.Url, err = createDynamicUrl(ep, req.URL.Path)
		if err != nil {
			responseBody := "Error while creating dynamic url for endpoint " + ep.Name + " Error: " + err.Error()
			h.Warnf(responseBody)
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}
	}
	h.Debugf(rid + " sending HTTP " + req.Method + " request to " + ep.Url)
	nReq, err := http.NewRequest(req.Method, ep.Url, nil)
	if ep.PassThrough {
		h.Debugf(rid + " allowing request method " + req.Method + " and body pass-through")

		nReq, err = http.NewRequest(req.Method, ep.Url, req.Body)
		if err != nil {
			responseBody := "Error while creating " + req.Method + " request to " + ep.Url + " with request body pass-through Error: " + err.Error()
			h.Warnf(responseBody)
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}
	} else {
		h.Debugf(rid + "using request body configured in endpointsettings")

		nReq, err = http.NewRequest(ep.HttpType, ep.Url, strings.NewReader(ep.PostData))
		if err != nil {
			responseBody := "Error while creating " + ep.HttpType + " request to " + ep.Url + " Error: " + err.Error()
			h.Warnf(responseBody)
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}

	}

	nReq.Header.Add("X-Real-IP", req.RemoteAddr)
	nReq.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	for headerName, header := range ep.Headers {
		nReq.Header.Add(headerName, header)
	}

	// check if response cache exists and should be used
	cacheFile := ""
	if len(ep.CacheTTLString) > 0 {
		hash := sha256.New()
		hash.Write([]byte(ep.PostData))
		hashSum := hash.Sum(nil)
		hashSumString := hex.EncodeToString(hashSum)
		cacheURI := url.QueryEscape(req.URL.Path)
		cacheDir, err := h.CheckDirAndCreate(filepath.Join(config.CacheBaseDir, cacheURI), "cachedir")
		if err != nil {
			responseBody := "Error while creating cache dir: " + err.Error()
			h.Warnf(responseBody)
			failedRequestCounter++
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}
		cacheFile = filepath.Join(cacheDir, hashSumString)
		if h.FileExists(cacheFile) {
			fi, err := os.Stat(cacheFile)
			if err != nil {
				responseBody := "Error while reading cached response: " + err.Error()
				h.Warnf(responseBody)
				failedRequestCounter++
				return HttpResult{Code: 503, Body: []byte(responseBody)}
			}
			mtime := fi.ModTime()
			validUntil := mtime.Add(ep.CacheTTL)
			if !time.Now().After(validUntil) {
				// cached response is still valid
				// return cached response
				h.Debugf("returning cached response for " + req.URL.Path + " from " + cacheFile)
				cacheContent, err := ioutil.ReadFile(cacheFile)
				if err != nil {
					responseBody := "Error while reading cached response: " + err.Error()
					h.Warnf(responseBody)
					failedRequestCounter++
					return HttpResult{Code: 503, Body: []byte(responseBody)}
				}
				responseHeader := make(map[string]string)
				responseHeader["X-Cached-Response-Mtime"] = mtime.String()
				responseHeader["X-Cached-Response-Valid-Until"] = validUntil.String()
				return HttpResult{Code: 200, Body: cacheContent, ResponseHeaders: responseHeader}

			} else {
				h.Debugf("cached response " + cacheFile + " is older that configured cache TTL at " + validUntil.String())
			}

		}
	}

	client := setupHttpClient(ep)

	before := time.Now()
	resp, err := client.Do(nReq)
	if err != nil {
		responseBody := "Error while issuing request to " + ep.Url + " Error: " + err.Error()
		h.Warnf(responseBody)
		return HttpResult{Code: 503, Body: []byte(responseBody)}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		responseBody := "Error while reading response body: " + err.Error()
		h.Warnf(responseBody)
		return HttpResult{Code: 503, Body: []byte(responseBody)}
	}
	//h.Debugf("Received response: " + string(body))
	// responseSize := fmt.Printf("%.1f", (len(string(body)) / 1024.0))
	responseSize := float64(len(body)) / 1024.0
	h.Debugf(rid + " sending HTTP " + req.Method + " request to " + ep.Url + " took " + strconv.FormatFloat(time.Since(before).Seconds(), 'f', 1, 64) + "s with " + strconv.FormatFloat(responseSize, 'f', 1, 64) + " kByte response body")

	if len(ep.CacheTTLString) > 0 {
		// save response to cache if cache_ttl is set in endpoint settings
		// always write to file
		file, err := os.Create(cacheFile)
		if err != nil {
			responseBody := "Error while caching response: " + err.Error()
			h.Warnf(responseBody)
			failedRequestCounter++
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}

		writer := bufio.NewWriter(file)
		written, err := writer.Write(body)
		if err != nil {
			responseBody := "Error while caching response: " + err.Error()
			h.Warnf(responseBody)
			failedRequestCounter++
			return HttpResult{Code: 503, Body: []byte(responseBody)}
		}
		h.Debugf("written " + strconv.Itoa(written) + " cached response for " + req.URL.Path + " from " + cacheFile)

	}
	return HttpResult{Code: 200, Body: body}

}

func respond(w http.ResponseWriter, hr HttpResult, pc map[string]prometheus.Counter) {
	w.Header().Set("X-goauthproxy-backend-server", config.Hostname)
	for responseHeaderName, responseHeaderValue := range hr.ResponseHeaders {
		// h.Debugf("adding header " + responseHeaderName + " with value: " + responseHeaderValue)
		w.Header().Set(responseHeaderName, responseHeaderValue)
	}
	if hr.Code == 200 {
		mutex.Lock()
		requestCounter++
		pc["successful"].Inc()
		mutex.Unlock()
	} else if hr.Code == 404 {
		mutex.Lock()
		nonexistingRequestCounter++
		pc["nonexisting"].Inc()
		mutex.Unlock()
	} else if hr.Code == 403 {
		mutex.Lock()
		forbiddenRequestCounter++
		pc["forbidden"].Inc()
		mutex.Unlock()
	} else if hr.Code == 503 {
		mutex.Lock()
		failedRequestCounter++
		pc["error"].Inc()
		mutex.Unlock()
	}
	w.Write(hr.Body)
	w.WriteHeader(hr.Code)

}

func setupHttpClient(ep EndpointSettings) *http.Client {
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

func createDynamicUrl(ep EndpointSettings, reqUrl string) (string, error) {
	urlTemplate := ep.Url
	h.Debugf("found request URI " + reqUrl)
	i := 1
	for {
		replacementString := "{{.Arg" + strconv.Itoa(i) + "}}"
		if strings.Contains(urlTemplate, replacementString) {
			uriParts := strings.Split(reqUrl, "/")
			// fmt.Printf("%+v\n", uriParts)
			// fmt.Println(uriParts[1])
			// fmt.Println(uriParts[2])
			h.Debugf("uriparts has " + strconv.Itoa(len(uriParts)) + " items")
			// fmt.Printf("%+v\n", uriParts)
			if len(uriParts)-2 != i {
				return "", errors.New("request URI does not have enough arguments for the dynamic URI configured in endpoint, expected " + strconv.Itoa(i) + ", but received " + strconv.Itoa(len(uriParts)-2))
			}
			if len(uriParts[i+1]) != 0 {
				if regex, ok := ep.ArgRegexesObjects["1"]; ok {
					if !regex.MatchString(uriParts[i+1]) {
						return "", errors.New("request URI argument number " + strconv.Itoa(i) + " does not match argument regex")
					}
				}
				urlTemplate = strings.ReplaceAll(urlTemplate, replacementString, uriParts[i+1])
			} else {
				return "", errors.New("request URI argument number " + strconv.Itoa(i) + " can not be empty")
			}
		} else {
			break
		}
		i += 1
	}
	url := urlTemplate
	return url, nil
}
