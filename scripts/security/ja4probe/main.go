// ja4probe sends HTTPS requests with fixed or browser-like TLS ClientHellos
// (uTLS) and prints, per request, the JA4 computed locally from the exact
// ClientHello bytes it sent (an independent Go implementation of the FoxIO
// JA4.md rules) and the response body, which the smoke config sets to the
// server's $cdnca_ja4. Used by scripts/security/ja4-smoke.sh.
//
//	ja4probe -addr 127.0.0.1:8443 -host ja4.example.test -path /ja4 -profile chrome -count 5
//	ja4probe -selftest    FoxIO JA4.md worked example through the local JA4 code
//	ja4probe ... -pcap hellos.pcap   the ClientHellos sent, for tshark -e tls.handshake.ja4
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

type result struct {
	Profile    string `json:"profile"`
	Request    int    `json:"request"`
	Local      string `json:"local_ja4"`
	Server     string `json:"server_ja4"`
	Status     int    `json:"status"`
	Extensions string `json:"extension_order"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "server address")
	host := flag.String("host", "ja4.example.test", "SNI and Host")
	path := flag.String("path", "/ja4", "request path")
	profile := flag.String("profile", "chrome", "chrome|firefox|safari|edge|fixed|fixed-grease-shuffled|fixed-no-sni")
	count := flag.Int("count", 1, "connections")
	selftest := flag.Bool("selftest", false, "check the local JA4 against the FoxIO worked example")
	pcapPath := flag.String("pcap", "", "also write every ClientHello sent into this pcap (TCP port 443), for an independent JA4 reader such as tshark -e tls.handshake.ja4")
	flag.Parse()
	if *selftest {
		if err := selfTest(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("selftest ok t13d1516h2_8daaf6152771_e5627efa2ab1")
		return
	}
	var capture *os.File
	if *pcapPath != "" {
		var err error
		if capture, err = os.OpenFile(*pcapPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer capture.Close()
		// pcap global header: LINKTYPE_RAW (IPv4 without link layer).
		header := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0}
		if _, err := capture.Write(header); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	for index := 0; index < *count; index++ {
		item, hello, err := probe(*addr, *host, *path, *profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "request %d: %v\n", index, err)
			os.Exit(1)
		}
		item.Request = index
		if capture != nil {
			if _, err := capture.Write(pcapRecord(hello, uint16(40000+index))); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		_ = encoder.Encode(item)
	}
}

// pcapRecord wraps one handshake message in a TLS record inside a single
// IPv4/TCP segment to port 443 (checksums zero; dissectors accept that).
func pcapRecord(hello []byte, sourcePort uint16) []byte {
	record := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 1)
	tcp[12], tcp[13] = 5<<4, 0x18
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(record)))
	copy(ip[12:], []byte{192, 0, 2, 1})
	copy(ip[16:], []byte{192, 0, 2, 2})
	packet := append(append(ip, tcp...), record...)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[8:], uint32(len(packet)))
	binary.LittleEndian.PutUint32(header[12:], uint32(len(packet)))
	return append(header, packet...)
}

func probe(addr, host, path, profile string) (result, []byte, error) {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return result{}, nil, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	serverName := host
	if profile == "fixed-no-sni" {
		serverName = ""
	}
	config := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	var conn *tls.UConn
	switch profile {
	case "chrome":
		conn = tls.UClient(raw, config, tls.HelloChrome_Auto)
	case "firefox":
		conn = tls.UClient(raw, config, tls.HelloFirefox_Auto)
	case "safari":
		conn = tls.UClient(raw, config, tls.HelloSafari_Auto)
	case "edge":
		conn = tls.UClient(raw, config, tls.HelloEdge_Auto)
	case "fixed", "fixed-grease-shuffled", "fixed-no-sni":
		conn = tls.UClient(raw, config, tls.HelloCustom)
		if err := conn.ApplyPreset(fixedSpec(profile, host)); err != nil {
			return result{}, nil, err
		}
	default:
		return result{}, nil, fmt.Errorf("unknown profile %q", profile)
	}
	if err := conn.BuildHandshakeState(); err != nil {
		return result{}, nil, err
	}
	hello := conn.HandshakeState.Hello.Raw
	local, order, err := ja4FromHandshake(hello)
	if err != nil {
		return result{}, nil, err
	}
	if err := conn.Handshake(); err != nil {
		return result{}, nil, fmt.Errorf("handshake: %w", err)
	}
	// HTTP/1.1 is forced so the request can be written on the uTLS conn
	// directly; the browser profiles still offer h2 in their ClientHello.
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		return result{}, nil, errors.New("server negotiated h2; the smoke listener must not enable http2")
	}
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(conn, request); err != nil {
		return result{}, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return result{}, nil, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return result{Profile: profile, Local: local, Server: strings.TrimSpace(string(body)), Status: response.StatusCode,
		Extensions: order}, hello, nil
}

// fixedSpec is the FoxIO JA4.md worked example's cipher, extension and
// signature algorithm lists; the "-grease-shuffled" variant adds GREASE
// everywhere and reverses the extension order.
func fixedSpec(profile, host string) *tls.ClientHelloSpec {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
		0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	sigalgs := []tls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	versions := []uint16{tls.VersionTLS13, tls.VersionTLS12}
	shares := []tls.KeyShare{{Group: tls.X25519}}
	curves := []tls.CurveID{tls.X25519, tls.CurveP256}
	grease := profile == "fixed-grease-shuffled"
	if grease {
		ciphers = append([]uint16{tls.GREASE_PLACEHOLDER}, ciphers...)
		versions = append([]uint16{tls.GREASE_PLACEHOLDER}, versions...)
		shares = append([]tls.KeyShare{{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}}}, shares...)
		// A key_share group must also be in supported_groups (OpenSSL 3.5).
		curves = append([]tls.CurveID{tls.CurveID(tls.GREASE_PLACEHOLDER)}, curves...)
	}
	extensions := []tls.TLSExtension{
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}}, // 001b
		&tls.SNIExtension{ServerName: host},                                         // 0000
		&tls.KeyShareExtension{KeyShares: shares},                                   // 0033
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},               // 0010
		&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"http/1.1"}}, // 4469
		&tls.ExtendedMasterSecretExtension{},                                        // 0017
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},           // 002d
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigalgs},    // 000d
		&tls.StatusRequestExtension{},                                               // 0005
		&tls.SessionTicketExtension{},                                               // 0023
		&tls.SCTExtension{},                                                         // 0012
		&tls.SupportedVersionsExtension{Versions: versions},                         // 002b
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, // ff01
		&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},                   // 000b
		&tls.SupportedCurvesExtension{Curves: curves},                               // 000a
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},            // 0015
	}
	if profile == "fixed-no-sni" {
		extensions = append(extensions[:1], extensions[2:]...)
	}
	if grease {
		reversed := make([]tls.TLSExtension, 0, len(extensions)+2)
		reversed = append(reversed, &tls.UtlsGREASEExtension{})
		for index := len(extensions) - 2; index >= 0; index-- {
			reversed = append(reversed, extensions[index])
		}
		// Padding must stay last; a trailing GREASE extension precedes it.
		reversed = append(reversed, &tls.UtlsGREASEExtension{}, extensions[len(extensions)-1])
		extensions = reversed
	}
	return &tls.ClientHelloSpec{CipherSuites: ciphers, CompressionMethods: []byte{0},
		Extensions: extensions, TLSVersMin: tls.VersionTLS12, TLSVersMax: tls.VersionTLS13}
}

func grease(value uint16) bool { return value&0x0f0f == 0x0a0a && value>>8 == value&0xff }

func hash12(value string) string {
	if value == "" {
		return "000000000000"
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:6])
}

func alnum(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

// ja4FromHandshake computes JA4 from a handshake message (type 1 + 3-byte
// length + ClientHello body) and returns the GREASE-free wire extension order.
func ja4FromHandshake(message []byte) (string, string, error) {
	if len(message) < 4 || message[0] != 1 || int(message[1])<<16|int(message[2])<<8|int(message[3]) != len(message)-4 {
		return "", "", errors.New("not one ClientHello handshake message")
	}
	body := message[4:]
	take := func(n int) ([]byte, error) {
		if len(body) < n {
			return nil, errors.New("truncated ClientHello")
		}
		value := body[:n]
		body = body[n:]
		return value, nil
	}
	vector := func(width int) ([]byte, error) {
		header, err := take(width)
		if err != nil {
			return nil, err
		}
		n := int(header[0])
		if width == 2 {
			n = int(binary.BigEndian.Uint16(header))
		}
		return take(n)
	}
	legacy, err := take(2)
	if err != nil {
		return "", "", err
	}
	if _, err := take(32); err != nil {
		return "", "", err
	}
	if _, err := vector(1); err != nil {
		return "", "", err
	}
	cipherBytes, err := vector(2)
	if err != nil {
		return "", "", err
	}
	if _, err := vector(1); err != nil {
		return "", "", err
	}
	extensionBytes, err := vector(2)
	if err != nil || len(body) != 0 {
		return "", "", errors.New("malformed extensions")
	}
	var ciphers, extensions, sigalgs, order []string
	for index := 0; index+1 < len(cipherBytes); index += 2 {
		if value := binary.BigEndian.Uint16(cipherBytes[index:]); !grease(value) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", value))
		}
	}
	version, highest, sni, alpn := binary.BigEndian.Uint16(legacy), uint16(0), "i", "00"
	for len(extensionBytes) >= 4 {
		kind := binary.BigEndian.Uint16(extensionBytes)
		length := int(binary.BigEndian.Uint16(extensionBytes[2:]))
		if len(extensionBytes) < 4+length {
			return "", "", errors.New("truncated extension")
		}
		data := extensionBytes[4 : 4+length]
		extensionBytes = extensionBytes[4+length:]
		if grease(kind) {
			continue
		}
		hexKind := fmt.Sprintf("%04x", kind)
		order = append(order, hexKind)
		switch kind {
		case 0x0000:
			sni = "d"
		case 0x0010:
			if len(data) >= 3 && int(data[2]) > 0 && len(data) >= 3+int(data[2]) {
				first := data[3 : 3+int(data[2])]
				if alnum(first[0]) && alnum(first[len(first)-1]) {
					alpn = string([]byte{first[0], first[len(first)-1]})
				} else {
					alpn = hex.EncodeToString(first[:1])[:1] + hex.EncodeToString(first[len(first)-1:])[1:]
				}
			}
		case 0x002b:
			for index := 1; index+1 < len(data); index += 2 {
				if value := binary.BigEndian.Uint16(data[index:]); !grease(value) && value > highest {
					highest = value
				}
			}
		case 0x000d:
			for index := 2; index+1 < len(data); index += 2 {
				if value := binary.BigEndian.Uint16(data[index:]); !grease(value) {
					sigalgs = append(sigalgs, fmt.Sprintf("%04x", value))
				}
			}
		}
		if kind != 0x0000 && kind != 0x0010 {
			extensions = append(extensions, hexKind)
		}
	}
	if highest != 0 {
		version = highest
	}
	versions := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
		0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}
	code, ok := versions[version]
	if !ok {
		code = "00"
	}
	sort.Strings(ciphers)
	sort.Strings(extensions)
	c := strings.Join(extensions, ",")
	if len(sigalgs) > 0 {
		c += "_" + strings.Join(sigalgs, ",")
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", code, sni, min(len(ciphers), 99), min(len(order), 99), alpn)
	return a + "_" + hash12(strings.Join(ciphers, ",")) + "_" + hash12(c), strings.Join(order, ","), nil
}

func selfTest() error {
	// Build the worked example's ClientHello with the fixed spec (no network).
	client := tls.UClient(nil, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}, tls.HelloCustom)
	spec := fixedSpec("fixed", "example.com")
	if err := client.ApplyPreset(spec); err != nil {
		return err
	}
	if err := client.BuildHandshakeState(); err != nil {
		return err
	}
	got, _, err := ja4FromHandshake(client.HandshakeState.Hello.Raw)
	if err != nil {
		return err
	}
	if got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		return fmt.Errorf("selftest JA4 = %s", got)
	}
	return nil
}
