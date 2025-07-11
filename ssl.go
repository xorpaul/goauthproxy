package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	h "github.com/xorpaul/gohelper"
	"golang.org/x/crypto/ocsp"
)

// parsePEMCertificate parses a PEM-encoded certificate and returns the DER bytes
func parsePEMCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err.Error())
	}

	return cert, nil
}

func verifyCertificateOcsp(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	dn := cert.Subject.String()
	issuerDN := issuer.Subject.String()

	h.Debugf("Starting OCSP verification for certificate: " + dn)
	h.Debugf("Using issuer certificate: " + issuerDN)

	if len(cert.OCSPServer) == 0 {
		h.Debugf("No OCSP servers found in client certificate " + dn)
		return nil, fmt.Errorf("no OCSP server found in client certificate %s", dn)
	}

	h.Debugf(fmt.Sprintf("Found %d OCSP servers in certificate %s: %v", len(cert.OCSPServer), dn, cert.OCSPServer))

	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		h.Debugf(fmt.Sprintf("Failed to create OCSP request for %s with issuer %s: %s", dn, issuerDN, err.Error()))
		return nil, fmt.Errorf("error while creating OCSP request for %s with issuer %s Error: %s", dn, cert.Issuer, err.Error())
	}

	h.Debugf(fmt.Sprintf("Created OCSP request for certificate %s (request size: %d bytes)", dn, len(ocspReq)))

	for i, ocspServer := range cert.OCSPServer {
		h.Debugf(fmt.Sprintf("Trying OCSP server %d/%d: %s for certificate %s", i+1, len(cert.OCSPServer), ocspServer, dn))

		reader := bytes.NewReader(ocspReq)
		req, err := http.Post(ocspServer, "application/ocsp-request", reader)
		if err != nil {
			h.Debugf(fmt.Sprintf("Failed to send OCSP request to %s for certificate %s: %s", ocspServer, dn, err.Error()))
			return nil, fmt.Errorf("error while sending OCSP request for %s with issuer %s to %s Error: %s", dn, cert.Issuer, ocspServer, err.Error())
		}

		ocspResBytes, err := io.ReadAll(req.Body)
		if err != nil {
			h.Debugf(fmt.Sprintf("Failed to read OCSP response from %s for certificate %s: %s", ocspServer, dn, err.Error()))
			return nil, fmt.Errorf("error while reading response from OCSP request for %s with issuer %s to %s Error: %s", dn, cert.Issuer, ocspServer, err.Error())
		}

		h.Debugf(fmt.Sprintf("Received OCSP response from %s for certificate %s (response size: %d bytes)", ocspServer, dn, len(ocspResBytes)))

		resp, err := ocsp.ParseResponse(ocspResBytes, nil)
		if err != nil {
			h.Debugf(fmt.Sprintf("Failed to parse OCSP response from %s for certificate %s: %s", ocspServer, dn, err.Error()))
			return nil, fmt.Errorf("error while parsing response from OCSP request for %s with issuer %s to %s Error: %s", dn, cert.Issuer, ocspServer, err.Error())
		}

		// https://pkg.go.dev/golang.org/x/crypto/ocsp#Response
		h.Debugf(fmt.Sprintf("OCSP response for %s: Status=%d, ThisUpdate=%s, NextUpdate=%s", dn, resp.Status, resp.ThisUpdate, resp.NextUpdate))

		// OCSP Status values: 0=Good, 1=Revoked, 2=Unknown
		var statusStr string
		switch resp.Status {
		case ocsp.Good:
			statusStr = "Good"
		case ocsp.Revoked:
			statusStr = "Revoked"
		case ocsp.Unknown:
			statusStr = "Unknown"
		default:
			statusStr = fmt.Sprintf("Invalid(%d)", resp.Status)
		}
		h.Debugf(fmt.Sprintf("OCSP status for certificate %s: %s (%d)", dn, statusStr, resp.Status))

		if resp.Status == ocsp.Good {
			h.Debugf("OCSP verification successful for certificate " + dn)
			return resp, nil
		}

		h.Debugf("OCSP status not good for certificate " + dn + ", trying next server (if any)")
	}

	h.Debugf("No valid OCSP response received from any server for certificate " + dn)
	return nil, fmt.Errorf("no valid OCSP response received from any OCSP server found in client certificate %s", dn)

}

func verifyClientCertificate(rid string, ep EndpointSettings, r *http.Request, cc *ClientCertificate) (bool, error) {
	// First check if we have any TLS connection at all
	if r.TLS == nil {
		h.Debugf(rid + " ERROR: No TLS connection found - request should have been rejected at TLS layer")
		return false, fmt.Errorf("no TLS connection found")
	}

	h.Debugf(rid + " Found client certificate for endpoint " + ep.Name + " - DN: " + cc.DistinguishedName)

	if len(ep.AllowedDistinguishedNames) > 0 {
		h.Debugf(rid + " Checking client certificate against " + fmt.Sprintf("%d", len(ep.AllowedDistinguishedNames)) + " allowed distinguished names for endpoint " + ep.Name)

		h.Debugf(rid + " Checking client cert DN: " + cc.DistinguishedName + " for endpoint " + ep.Name)

		for j, cn := range ep.AllowedDistinguishedNames {
			h.Debugf(rid + " Comparing client cert " + cc.DistinguishedName + " against allowed DN " + fmt.Sprintf("%d", j+1) + "/" + fmt.Sprintf("%d", len(ep.AllowedDistinguishedNames)) + ": " + cn)
			if cc.DistinguishedName == cn {
				h.Debugf(rid + " MATCH: Found matching client cert " + cc.DistinguishedName + " for endpoint " + ep.Name)

				// Check if we have client CA certificates for OCSP verification
				if len(config.ClientCertCas) == 0 {
					h.Debugf(rid + " WARNING: No client CA certificates configured for OCSP verification")
					return true, nil
				}

				// Find the correct issuer CA certificate for this client certificate
				clientCertIssuer := cc.Issuer
				h.Debugf(rid + " Client certificate issuer: " + clientCertIssuer)
				h.Debugf(rid + " Searching for matching issuer among " + fmt.Sprintf("%d", len(config.ClientCertCas)) + " configured client CA certificate(s)")

				var matchingCA *x509.Certificate = nil
				var matchingCAIndex int = -1

				for k, clientCAFile := range config.ClientCertCas {
					clientCAIssuer := clientCAFile.Subject.String()
					h.Debugf(rid + " Comparing against CA " + fmt.Sprintf("%d", k+1) + "/" + fmt.Sprintf("%d", len(config.ClientCertCas)) + ": " + clientCAIssuer)

					if clientCertIssuer == clientCAIssuer {
						h.Debugf(rid + " MATCH: Found matching issuer CA " + fmt.Sprintf("%d", k+1) + " for client certificate " + cc.DistinguishedName)
						matchingCA = clientCAFile
						matchingCAIndex = k + 1
						break
					}
				}

				if matchingCA == nil {
					h.Debugf(rid + " AUTHORIZATION DENIED: No matching issuer CA found for client certificate " + cc.DistinguishedName)
					h.Debugf(rid + " Client certificate issuer '" + clientCertIssuer + "' not found in configured client CAs")
					return false, fmt.Errorf("client certificate issuer not found in configured client CAs")
				}

				// For OCSP verification, we need to parse the certificate from the header
				if cc.Certificate != "" {
					h.Debugf(rid + " Starting OCSP verification with matching issuer CA " + fmt.Sprintf("%d", matchingCAIndex) + " for certificate " + cc.DistinguishedName)

					// Parse the certificate from the header (PEM format)
					certPEM := "-----BEGIN CERTIFICATE-----\n" + cc.Certificate + "\n-----END CERTIFICATE-----"
					certDER, err := parsePEMCertificate(certPEM)
					if err != nil {
						h.Debugf(rid + " Failed to parse certificate from header: " + err.Error())
						return false, fmt.Errorf("failed to parse certificate from header: %s", err.Error())
					}

					// Perform OCSP verification against the specific issuer CA
					ocspResp, err := verifyCertificateOcsp(certDER, matchingCA)
					if err != nil {
						h.Debugf(rid + " OCSP verification failed with matching CA " + fmt.Sprintf("%d", matchingCAIndex) + " for certificate " + cc.DistinguishedName + ": " + err.Error())
						return false, err
					}

					h.Debugf(rid + " OCSP verification completed with matching CA " + fmt.Sprintf("%d", matchingCAIndex) + " for certificate " + cc.DistinguishedName + " - Status: " + fmt.Sprintf("%d", ocspResp.Status))
					if ocspResp.Status == 0 {
						h.Debugf(rid + " AUTHORIZATION GRANTED for certificate " + cc.DistinguishedName + " on endpoint " + ep.Name)
						return true, nil
					} else {
						h.Debugf(rid + " AUTHORIZATION DENIED: OCSP status not 'Good' for certificate " + cc.DistinguishedName + " on endpoint " + ep.Name)
						return false, fmt.Errorf("OCSP verification failed: certificate status is not 'Good'")
					}
				} else {
					h.Debugf(rid + " WARNING: No certificate data available for OCSP verification, skipping OCSP check")
					h.Debugf(rid + " AUTHORIZATION GRANTED for certificate " + cc.DistinguishedName + " on endpoint " + ep.Name)
					return true, nil
				}
			}
		}

		h.Debugf(rid + " AUTHORIZATION DENIED: No matching client certificates found for endpoint " + ep.Name)
		return false, nil
	} else {
		h.Debugf(rid + " No distinguished names configured for endpoint " + ep.Name + " - allowing all requests with valid client certificates")
		return true, nil
	}
}
