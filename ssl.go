package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	h "github.com/xorpaul/gohelper"
	"golang.org/x/crypto/ocsp"
)

func verifyCertificateOcsp(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	dn := cert.Subject.String()
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("no OCSP server found in client certificate %s", dn)
	}

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("error while creating OCSP request for %s with issuer %s Error: %s", dn, cert.Issuer, err.Error())
	}

	for _, ocspServer := range cert.OCSPServer {

		reader := bytes.NewReader(ocspReq)
		req, err := http.Post(ocspServer, "application/ocsp-request", reader)
		if err != nil {
			return nil, fmt.Errorf("error while sending OCSP request for %s with issuer %s to %s Error: %s", dn, cert.Issuer, ocspServer, err.Error())
		}

		ocspResBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("error while reading response from OCSP request for %s with issuer %s to %s Error: %s", dn, cert.Issuer, ocspServer, err.Error())
		}
		resp, err := ocsp.ParseResponse(ocspResBytes, nil)
		if err != nil {
			return nil, fmt.Errorf("error while parsing response from OCSP request for %s with issuer %s to %s Error: %s", dn, cert.Issuer, ocspServer, err.Error())
		}

		// https://pkg.go.dev/golang.org/x/crypto/ocsp#Response
		// fmt.Printf("resp.ThisUpdate %s\n", resp.ThisUpdate)
		// fmt.Printf("resp.NextUpdate %s\n", resp.NextUpdate)
		// fmt.Printf("resp.Status %d\n", resp.Status)
		// TODO: cache OCSP response

		return resp, nil

	}
	return nil, fmt.Errorf("no OCSP response received from %s found in client certificate %s", cert.OCSPServer[0], dn)

}

func verifyClientCertificate(rid string, ep EndpointSettings, r *http.Request) (bool, error) {
	if len(ep.AllowedDistinguishedNames) > 0 {
		for _, peerCertificate := range r.TLS.PeerCertificates {
			pcs := peerCertificate.Subject.String()
			h.Debugf(rid + " checking client cert " + pcs + " for endpoint " + ep.Name)
			for _, cn := range ep.AllowedDistinguishedNames {
				h.Debugf(rid + " comparing client cert " + pcs + " for endpoint " + ep.Name + " against " + cn)
				if pcs == cn {
					h.Debugf(rid + " found matching client cert " + pcs + " for endpoint " + ep.Name)

					// loop over all client CAs and check if we get a valid OCSP response for the received client certificate
					for _, clientCAFile := range config.ClientCertCas {
						ocspResp, err := verifyCertificateOcsp(peerCertificate, clientCAFile)
						if err != nil {
							return false, err
						}
						// fmt.Printf("%+v\n", ocspResp)
						if ocspResp.Status == 0 {
							return true, nil
						}
					}
				}
			}
			return false, nil
		}
	} else {
		return true, nil
	}
	return true, nil
}
