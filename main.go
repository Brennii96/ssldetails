package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

func getSSLCertificate(domain string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", domain+":443", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get the first certificate from the chain
	cert := conn.ConnectionState().PeerCertificates[0]
	return cert, nil
}

func printCertificateDetails(cert *x509.Certificate) {
	expiryDate := cert.NotAfter
	daysUntilExpiry := int(expiryDate.Sub(time.Now()).Hours() / 24)
	domains := append(cert.DNSNames, cert.Subject.CommonName)
	fmt.Printf("Common Name: %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("Not Before: %s\n", cert.NotBefore)
	fmt.Printf("Not After: %s\n", expiryDate)
	fmt.Printf("Expires in %d days\n", daysUntilExpiry)
	fmt.Printf("Is Expired: %t\n", cert.NotAfter.Before(time.Now()))
	fmt.Printf("Valid Domains: %v\n", domains)
}

func main() {
	domains := []string{
		"kiteschoolofkenpo.co.uk",
	}

	for _, domain := range domains {
		fmt.Printf("Checking domain: %s\n", domain)
		cert, err := getSSLCertificate(domain)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		printCertificateDetails(cert)
		fmt.Println()
	}
}
