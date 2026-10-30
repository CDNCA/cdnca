package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	dynamicName = "origin.dynamic.test"
	originPort  = 18081
	dnsTTL      = 1
)

type fixtureState struct {
	mu      sync.RWMutex
	address net.IP
	failing bool
}

func main() {
	dnsListen := flag.String("dns-listen", "127.0.0.1:5300", "authoritative DNS UDP address")
	controlListen := flag.String("control-listen", "0.0.0.0:18090", "control HTTP address")
	flag.Parse()

	state := &fixtureState{address: net.ParseIP("127.0.0.2").To4()}
	dnsConn, err := net.ListenUDP("udp", mustResolveUDP(*dnsListen))
	if err != nil {
		log.Fatal(err)
	}
	defer dnsConn.Close()
	go serveDNS(dnsConn, state)

	servers := make([]*http.Server, 0, 3)
	for _, origin := range []struct{ address, id string }{
		{address: "127.0.0.2:18081", id: "A"},
		{address: "127.0.0.3:18081", id: "B"},
	} {
		server := &http.Server{Addr: origin.address, Handler: originHandler(origin.id)}
		servers = append(servers, server)
		go func() {
			if serveErr := server.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
				log.Fatal(serveErr)
			}
		}()
	}

	control := &http.Server{Addr: *controlListen, Handler: controlHandler(state)}
	servers = append(servers, control)
	go func() {
		if serveErr := control.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatal(serveErr)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	for _, server := range servers {
		_ = server.Close()
	}
}

func mustResolveUDP(address string) *net.UDPAddr {
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Fatal(err)
	}
	return resolved
}

func originHandler(id string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-CDNCA-Fixture-Origin", id)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(id))
	})
}

func controlHandler(state *fixtureState) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/health":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("ok"))
		case "/set-address":
			value := request.URL.Query().Get("value")
			var address net.IP
			switch value {
			case "A":
				address = net.ParseIP("127.0.0.2").To4()
			case "B":
				address = net.ParseIP("127.0.0.3").To4()
			default:
				http.Error(writer, "invalid address", http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			state.address = address
			state.mu.Unlock()
			writer.WriteHeader(http.StatusNoContent)
		case "/set-failure":
			value, err := strconv.ParseBool(request.URL.Query().Get("value"))
			if err != nil {
				http.Error(writer, "invalid failure value", http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			state.failing = value
			state.mu.Unlock()
			writer.WriteHeader(http.StatusNoContent)
		case "/state":
			state.mu.RLock()
			value := struct {
				Address string `json:"address"`
				Failing bool   `json:"failing"`
			}{Address: state.address.String(), Failing: state.failing}
			state.mu.RUnlock()
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(value)
		default:
			http.NotFound(writer, request)
		}
	})
}

func serveDNS(conn *net.UDPConn, state *fixtureState) {
	buffer := make([]byte, 1500)
	for {
		length, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		response, ok := dnsResponse(buffer[:length], state)
		if ok {
			_, _ = conn.WriteToUDP(response, remote)
		}
	}
}

func dnsResponse(query []byte, state *fixtureState) ([]byte, bool) {
	questionEnd, queryType, ok := dnsQuestion(query)
	if !ok {
		return nil, false
	}
	state.mu.RLock()
	address := append(net.IP(nil), state.address...)
	failing := state.failing
	state.mu.RUnlock()

	response := make([]byte, 0, questionEnd+32)
	response = append(response, query[:2]...)
	flags := uint16(0x8180)
	answerCount := uint16(1)
	if failing {
		flags = 0x8182 // SERVFAIL: a resolver failure, not an empty successful answer.
		answerCount = 0
	} else if queryType != 1 {
		flags = 0x8183 // NXDOMAIN for AAAA and any unexpected query type.
		answerCount = 0
	}
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header[0:2], flags)
	binary.BigEndian.PutUint16(header[2:4], 1)
	binary.BigEndian.PutUint16(header[4:6], answerCount)
	response = append(response, header...)
	response = append(response, query[12:questionEnd]...)
	if answerCount == 0 {
		return response, true
	}
	address = address.To4()
	if len(address) != net.IPv4len {
		return nil, false
	}
	answer := make([]byte, 16)
	binary.BigEndian.PutUint16(answer[0:2], 0xc00c)
	binary.BigEndian.PutUint16(answer[2:4], 1)
	binary.BigEndian.PutUint16(answer[4:6], 1)
	binary.BigEndian.PutUint32(answer[6:10], dnsTTL)
	binary.BigEndian.PutUint16(answer[10:12], net.IPv4len)
	copy(answer[12:], address)
	return append(response, answer...), true
}

func dnsQuestion(query []byte) (int, uint16, bool) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return 0, 0, false
	}
	position := 12
	labels := make([]string, 0, 4)
	for {
		if position >= len(query) {
			return 0, 0, false
		}
		length := int(query[position])
		position++
		if length == 0 {
			break
		}
		if length > 63 || position+length > len(query) {
			return 0, 0, false
		}
		labels = append(labels, string(query[position:position+length]))
		position += length
	}
	if position+4 > len(query) {
		return 0, 0, false
	}
	questionEnd := position + 4
	if strings.Join(labels, ".") != dynamicName {
		return 0, 0, false
	}
	return questionEnd, binary.BigEndian.Uint16(query[position : position+2]), true
}
