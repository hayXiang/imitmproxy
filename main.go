// go-mitm-proxy.go
//
// 运行示例:
//   go run go-mitm-proxy.go -listen :8080 -ca-cert ca.pem -ca-key ca.key \
//     -remove-req "User-Agent,Cookie" -remove-resp "Server" -verbose
//

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	listenAddr      = flag.String("listen", ":8080", "listen address")
	caCertPath      = flag.String("ca-cert", "", "path to CA cert (PEM)")
	caKeyPath       = flag.String("ca-key", "", "path to CA private key (PEM)")
	removeReqHeader = flag.String("remove-req", "", "comma-separated request headers to remove")
	removeResHeader = flag.String("remove-resp", "", "comma-separated response headers to remove")
	stripHop        = flag.Bool("strip-hop", true, "strip standard hop-by-hop headers")
	verbose         = flag.Bool("verbose", false, "enable verbose logging")
	readTimeout     = flag.Duration("read-timeout", 10*time.Second, "read timeout")
	idleTimeout     = flag.Duration("idle-timeout", 30*time.Second, "idle timeout")
)

var (
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	certMap sync.Map // cache generated certs keyed by host
)

var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func main() {
	flag.Parse()

	if *caCertPath == "" || *caKeyPath == "" {
		log.Fatal("must specify -ca-cert and -ca-key")
	}

	var err error
	caCert, caKey, err = loadCA(*caCertPath, *caKeyPath)
	if err != nil {
		log.Fatalf("failed to load CA cert/key: %v", err)
	}

	reqRemoves := parseCSV(*removeReqHeader)
	resRemoves := parseCSV(*removeResHeader)

	// Transport used for normal HTTP requests and MITM target connections
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DisableCompression:  false,
		IdleConnTimeout:     *idleTimeout,
		MaxIdleConnsPerHost: 100,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Method, "CONNECT") {
			if *verbose {
				log.Printf("MITM CONNECT %s from %s", r.Host, r.RemoteAddr)
			}
			handleMITM(w, r, transport, reqRemoves, resRemoves)
		} else {
			if *verbose {
				log.Printf("HTTP %s %s from %s", r.Method, r.URL, r.RemoteAddr)
			}
			handleHTTP(w, r, transport, reqRemoves, resRemoves)
		}
	})

	log.Printf("Starting MITM proxy on %s", *listenAddr)
	server := &http.Server{
		Addr:              *listenAddr,
		ReadTimeout:       *readTimeout,
		IdleTimeout:       *idleTimeout,
		ReadHeaderTimeout: 5 * time.Second,
	}
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, nil, fmt.Errorf("invalid CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

func parseCSV(s string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[http.CanonicalHeaderKey(p)] = struct{}{}
	}
	return out
}

func handleHTTP(w http.ResponseWriter, r *http.Request, transport *http.Transport, removeReq, removeResp map[string]struct{}) {
	start := time.Now()

	if *stripHop {
		for _, h := range hopByHop {
			r.Header.Del(h)
		}
	}
	for h := range removeReq {
		r.Header.Del(h)
	}

	// Make sure URL has scheme
	if r.URL.Scheme == "" {
		if r.TLS != nil {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		log.Printf("RoundTrip error: %v", err)
		return
	}
	defer resp.Body.Close()

	if *stripHop {
		for _, h := range hopByHop {
			resp.Header.Del(h)
		}
	}
	for h := range removeResp {
		resp.Header.Del(h)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 32*1024)
	written, err := io.CopyBuffer(w, resp.Body, buf)
	if err != nil {
		log.Printf("copy response body error: %v", err)
	}

	if *verbose {
		log.Printf("HTTP %s %s %d bytes %v", r.Method, r.URL, written, time.Since(start))
	}
}

// MITM handler intercepts CONNECT and performs TLS interception
func handleMITM(w http.ResponseWriter, r *http.Request, transport *http.Transport, removeReq, removeResp map[string]struct{}) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Respond OK to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		return
	}

	// Create TLS config for MITM, generate cert for host
	host := r.Host
	if strings.Index(host, ":") == -1 {
		host += ":443"
	}
	hostname := host
	if colon := strings.Index(host, ":"); colon != -1 {
		hostname = host[:colon]
	}
	cert, err := getOrCreateCert(hostname)
	if err != nil {
		log.Printf("Failed to create cert for %s: %v", hostname, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// Wrap client connection with TLS server (MITM)
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	err = tlsClientConn.Handshake()
	if err != nil {
		log.Printf("TLS handshake error with client: %v", err)
		return
	}
	defer tlsClientConn.Close()

	// Connect to target server with TLS client
	targetConn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true, // skip verify target cert
	})
	if err != nil {
		log.Printf("Failed to connect target %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	// Now we have client and target TLS connections established
	// We must read HTTP requests from tlsClientConn, modify headers, send to targetConn,
	// read response from targetConn, modify headers, send to tlsClientConn

	handleMITMProxy(tlsClientConn, targetConn, transport, removeReq, removeResp)
}

func handleMITMProxy(clientTLS net.Conn, targetTLS net.Conn, transport *http.Transport, removeReq, removeResp map[string]struct{}) {
	clientReader := bufio.NewReader(clientTLS)
	clientWriter := bufio.NewWriter(clientTLS)
	targetReader := bufio.NewReader(targetTLS)
	targetWriter := bufio.NewWriter(targetTLS)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("ReadRequest error: %v", err)
			}
			return
		}

		if *stripHop {
			for _, h := range hopByHop {
				req.Header.Del(h)
			}
		}
		for h := range removeReq {
			req.Header.Del(h)
		}

		// Must rewrite request URL for target
		req.RequestURI = ""
		req.URL.Scheme = "https"
		req.URL.Host = req.Host

		// Write request to target server
		err = req.Write(targetWriter)
		if err != nil {
			log.Printf("Failed to write request to target: %v", err)
			return
		}
		err = targetWriter.Flush()
		if err != nil {
			log.Printf("Failed to flush request to target: %v", err)
			return
		}

		// Read response from target
		resp, err := http.ReadResponse(targetReader, req)
		if err != nil {
			log.Printf("ReadResponse error: %v", err)
			return
		}

		if *stripHop {
			for _, h := range hopByHop {
				resp.Header.Del(h)
			}
		}
		for h := range removeResp {
			resp.Header.Del(h)
		}

		// Write response to client
		err = resp.Write(clientWriter)
		if err != nil {
			log.Printf("Failed to write response to client: %v", err)
			return
		}
		err = clientWriter.Flush()
		if err != nil {
			log.Printf("Failed to flush response to client: %v", err)
			return
		}

		// Important: close response body to avoid leaks
		resp.Body.Close()
	}
}

func getOrCreateCert(host string) (*tls.Certificate, error) {
	if cert, ok := certMap.Load(host); ok {
		return cert.(*tls.Certificate), nil
	}

	// Generate new cert for host signed by CA
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	certMap.Store(host, &tlsCert)
	return &tlsCert, nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
