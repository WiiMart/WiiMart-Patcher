package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// YearIssueTime is an issuance of this year's date on January 1 at midnight.
var YearIssueTime = time.Date(
	time.Now().Year(),
	time.January,
	1,
	0, 0, 0, 0,
	time.UTC,
)

// generateSerial generates a random 128-bit certificate serial number.
func generateSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	check(err)

	return serialNumber
}

func createCertificates() []byte {
	////////////////////////////////////
	//        Sanitize domain         //
	////////////////////////////////////

	// baseDomain may originate from fixed-size/binary data and therefore
	// contain trailing NUL bytes. Those MUST NOT reach the certificate.
	domain := strings.TrimSpace(baseDomain)
	domain = strings.TrimRight(domain, "\x00")
	domain = strings.TrimSpace(domain)

	if domain == "" {
		panic("certificate base domain is empty")
	}

	if strings.ContainsRune(domain, '\x00') {
		panic("certificate base domain contains an embedded NUL byte")
	}

	// Be tolerant if somebody supplies a trailing DNS dot.
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		panic("certificate base domain is empty after sanitization")
	}

	issueName := "*." + domain

	fmt.Printf("Certificate base domain: %q\n", domain)
	fmt.Printf("Certificate wildcard:    %q\n", issueName)

	////////////////////////////////////
	//        Generate root CA        //
	////////////////////////////////////

	rootCert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA1WithRSA,
		SerialNumber:       generateSerial(),

		Subject: pkix.Name{
			CommonName: "Open Shop Channel CA",
		},

		NotBefore: YearIssueTime,
		NotAfter:  YearIssueTime.AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)

	rootPublic, err := x509.CreateCertificate(
		rand.Reader,
		rootCert,
		rootCert,
		&rootPriv.PublicKey,
		rootPriv,
	)
	check(err)

	////////////////////////////////////
	//  Issue server TLS certificate  //
	////////////////////////////////////

	serverCert := &x509.Certificate{
		SignatureAlgorithm: x509.SHA1WithRSA,
		SerialNumber:       generateSerial(),

		Subject: pkix.Name{
			CommonName: issueName,
		},

		DNSNames: []string{
			issueName,
			domain,
		},

		NotBefore: YearIssueTime,
		NotAfter:  YearIssueTime.AddDate(10, 0, 0),

		KeyUsage: x509.KeyUsageKeyAgreement |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)

	serverPublic, err := x509.CreateCertificate(
		rand.Reader,
		serverCert,
		rootCert,
		&serverPriv.PublicKey,
		rootPriv,
	)
	check(err)

	////////////////////////////////////
	//     Verify generated cert      //
	////////////////////////////////////

	parsedServerCert, err := x509.ParseCertificate(serverPublic)
	check(err)

	testHostname := "oss-auth." + domain

	if err := parsedServerCert.VerifyHostname(testHostname); err != nil {
		panic(fmt.Sprintf(
			"generated certificate does not validate for %q: %v",
			testHostname,
			err,
		))
	}

	fmt.Printf(
		"Certificate hostname verification succeeded: %s\n",
		testHostname,
	)

	////////////////////////////
	//  Persist certificates  //
	////////////////////////////

	rootCertPem := pemEncode("CERTIFICATE", rootPublic)
	rootKeyPem := pemEncode(
		"RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(rootPriv),
	)

	serverCertPem := pemEncode("CERTIFICATE", serverPublic)
	serverKeyPem := pemEncode(
		"RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(serverPriv),
	)

	writeOut("root.pem", rootCertPem)
	writeOut("root.cer", rootPublic)
	writeOut("root.key", rootKeyPem)
	writeOut("server.pem", serverCertPem)
	writeOut("server.key", serverKeyPem)

	return rootPublic
}

func pemEncode(typeName string, bytes []byte) []byte {
	block := pem.Block{
		Type:  typeName,
		Bytes: bytes,
	}

	return pem.EncodeToMemory(&block)
}
