// certgen 为 server-cost.sh 生成 N 张自签 P-256 证书：DIR/<i>.crt、DIR/<i>.key，CN/SAN=s<i>.example。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: certgen DIR N")
		os.Exit(64)
	}
	count, err := strconv.Atoi(os.Args[2])
	if err != nil || count < 1 {
		fmt.Fprintln(os.Stderr, "invalid N")
		os.Exit(64)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	check(err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("s%d.example", index)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(index) + 1), Subject: pkix.Name{CommonName: name},
			DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		check(err)
		check(os.WriteFile(filepath.Join(os.Args[1], strconv.Itoa(index)+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
		check(os.WriteFile(filepath.Join(os.Args[1], strconv.Itoa(index)+".key"), keyPEM, 0o644))
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
