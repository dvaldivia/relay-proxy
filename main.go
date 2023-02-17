package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/minio/minio/cmd/rest"
	"golang.org/x/net/http2"
)

// ParsePublicCertFile - parses public cert into its *x509.Certificate equivalent.
func ParsePublicCertFile(certFile string) (x509Certs []*x509.Certificate, err error) {
	// Read certificate file.
	var data []byte
	if data, err = ioutil.ReadFile(certFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// Trimming leading and tailing white spaces.
	data = bytes.TrimSpace(data)

	// Parse all certs in the chain.
	current := data
	for len(current) > 0 {
		var pemBlock *pem.Block
		if pemBlock, current = pem.Decode(current); pemBlock == nil {
			return nil, fmt.Errorf("could not read PEM block from file %s", certFile)
		}

		var x509Cert *x509.Certificate
		if x509Cert, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
			return nil, err
		}

		x509Certs = append(x509Certs, x509Cert)
	}

	if len(x509Certs) == 0 {
		return nil, fmt.Errorf("empty public certificate file %s", certFile)
	}

	return x509Certs, nil
}

var (
	targetEndpoint string
	tlsKey         string
	tlsCrt         string
	//globalDNSCache *xhttp.DNSCache
)

func init() {
	targetEndpoint = os.Getenv("TARGET_ENDPOINT")
	flag.StringVar(&tlsCrt, "tls-certificate", "/certs/tls.crt", "TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "/certs/tls.key", "cert key")
	//globalDNSCache = xhttp.NewDNSCache(3*time.Second, 10*time.Second, nil)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func newInternodeHTTPTransport(tlsConfig *tls.Config, dialTimeout time.Duration) func() *http.Transport {
	// For more details about various values used here refer
	// https://golang.org/pkg/net/http/#Transport documentation
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		//DialContext:           xhttp.DialContextWithDNSCache(globalDNSCache, xhttp.NewInternodeDialContext(dialTimeout)),
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       15 * time.Second,
		ResponseHeaderTimeout: 3 * time.Minute, // Set conservative timeouts for MinIO internode.
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 15 * time.Second,
		TLSClientConfig:       tlsConfig,
		// Go net/http automatically unzip if content-type is
		// gzip disable this feature, as we are always interested
		// in raw stream.
		DisableCompression: true,
	}

	if tlsConfig != nil {
		http2.ConfigureTransport(tr)
	}

	return func() *http.Transport {
		return tr
	}
}

// Secure Go implementations of modern TLS ciphers
// The following ciphers are excluded because:
//   - RC4 ciphers:              RC4 is broken
//   - 3DES ciphers:             Because of the 64 bit blocksize of DES (Sweet32)
//   - CBC-SHA256 ciphers:       No countermeasures against Lucky13 timing attack
//   - CBC-SHA ciphers:          Legacy ciphers (SHA-1) and non-constant time
//     implementation of CBC.
//     (CBC-SHA ciphers can be enabled again if required)
//   - RSA key exchange ciphers: Disabled because of dangerous PKCS1-v1.5 RSA
//     padding scheme. See Bleichenbacher attacks.
var secureCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
}

// Go only provides constant-time implementations of Curve25519 and NIST P-256 curve.
var secureCurves = []tls.CurveID{tls.X25519, tls.CurveP256}

// dmt has support for multiple certificates. It expects the following structure:
//
//	/etc/dmt/tls/
//	 ├─ example.com/
//	 │   │
//	 │   ├─ public.crt
//	 │   └─ private.key
//	 └─ foobar.org/
//	    │
//	    ├─ public.crt
//	    └─ private.key
//	 ...
//
// Therefore, we read all filenames in the cert directory and check
// for each directory whether it contains a public.crt and private.key.
// If so, we try to add it to certs in *http.Server* config.
// NOTE: Directories just need to be named there is no requirement
// on the right name or domain related to the certs.
func loadTLSCerts(dirname string) ([]tls.Certificate, error) {
	dirs, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	var certs []tls.Certificate
	for _, dir := range dirs {
		// Regular file types are all ignored.
		if dir.IsDir() {
			cert, err := tls.LoadX509KeyPair(filepath.Join(dirname, dir.Name(), "public.crt"),
				filepath.Join(dirname, dir.Name(), "private.key"))
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func main() {
	flag.Parse()

	//defer globalDNSCache.Stop()

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		// In some systems (like Windows) system cert pool is
		// not supported or no certificates are present on the
		// system - so we create a new cert pool.
		rootCAs = x509.NewCertPool()
	}

	//// Add the global public crts as part of global root CAs
	//for _, publicCrt := range caCerts {
	//	rootCAs.AddCert(publicCrt)
	//}

	transport := newInternodeHTTPTransport(&tls.Config{
		RootCAs:    rootCAs,
		NextProtos: []string{"h2", "http/1.1"},
		// TLS hardening
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             secureCipherSuites,
		CurvePreferences:         secureCurves,
		PreferServerCipherSuites: true,
		InsecureSkipVerify:       true,
	}, rest.DefaultTimeout)()

	fakeOrigin := os.Getenv("FAKE_ORIGIN")
	log.Printf("Fake Origin: %s\n", fakeOrigin)

	r := mux.NewRouter().PathPrefix("/")
	r.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		director := func(r *http.Request) {

			log.Println("############")
			log.Printf("%+v", r.Header)
			log.Println("ORIGINAL destination")
			log.Println("r.URL", r.URL)
			log.Println("r.URL.Host", r.URL.Host)
			log.Println("r.Host", r.Host)
			log.Println("replaced")
			log.Println("############")

			r.Host = targetEndpoint

			r.Header.Add("X-Forwarded-Host", r.Host)
			r.Header.Add("X-Real-IP", r.RemoteAddr)

			r.Header.Del("Origin")
			r.Header.Add("Origin", fakeOrigin)

			//if secureBackend {
			//	r.URL.Scheme = "https"
			//} else {
			//	r.URL.Scheme = "http"
			//}
			r.URL.Scheme = "https"
			r.URL.Host = targetEndpoint

			log.Println("-----------")
			log.Printf("%+v", r.Header)
			log.Println("new routed destination")
			log.Println("targetEndpoint", targetEndpoint)
			log.Println("r.URL", r.URL)
			log.Println("r.URL.Host", r.URL.Host)
			log.Println("r.Host", r.Host)
			log.Println("r.RemoteAddr", r.RemoteAddr)
			log.Println("replaced")
			log.Println("-----------")
		}

		respFunc := func(response *http.Response) error {
			if len(response.Cookies()) > 0 {

				cookiiee := response.Cookies()[0]
				if cookiiee.Name == "authToken" {
					log.Println("-----------------Response--------")

					cooka := response.Header.Get("Set-Cookie")
					log.Println("")
					log.Println(cooka)
					log.Println("")
					cookiiee.Secure = false
					cookiiee.SameSite = http.SameSiteDefaultMode

					response.Header.Del("Set-Cookie")
					response.Header.Add("Set-Cookie", cookiiee.String())

					log.Printf("%+v", response.Header)
					log.Println("")
				}

			}

			return nil
		}

		proxy := &httputil.ReverseProxy{
			Director:       director,
			Transport:      transport,
			ModifyResponse: respFunc,
		}

		proxy.ServeHTTP(w, r)
	})

	loggedRouter := handlers.CombinedLoggingHandler(os.Stdout, r.GetHandler())
	s := &http.Server{
		Handler:        loggedRouter,
		Addr:           ":4233",
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			// TLS hardening
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
			NextProtos:               []string{"h2", "http/1.1"},
			//Certificates:             certs,
			CipherSuites:       secureCipherSuites,
			CurvePreferences:   secureCurves,
			InsecureSkipVerify: true,
		},
	}

	if tlsCrt != "" && tlsKey != "" {
		log.Println("Serving TLS Server")
		log.Fatalln(s.ListenAndServeTLS(tlsCrt, tlsKey))
	} else {
		log.Println("Serving Plain Server")
		log.Fatalln(s.ListenAndServe())
	}

}
