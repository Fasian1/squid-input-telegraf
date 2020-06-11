package squid

import (
	"bufio"
	"fmt"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	// Below used to decouple internals
	"crypto/tls" 
	"crypto/x509"
	"io/ioutil"
)

type Squid struct {
	Url             string
	ResponseTimeout Duration
	ClientConfig

	client *http.Client
}

// Decoupling reliance on internals of telegraf
// Duration just wraps time.Duration
type Duration struct {
	Duration time.Duration
}

// ClientConfig represents the standard client TLS config.
type ClientConfig struct {
	TLSCA              string `toml:"tls_ca"`
	TLSCert            string `toml:"tls_cert"`
	TLSKey             string `toml:"tls_key"`
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`

	// Deprecated in 1.7; use TLS variables above
	SSLCA   string `toml:"ssl_ca"`
	SSLCert string `toml:"ssl_cert"`
	SSLKey  string `toml:"ssl_key"`
}

// TLSConfig returns a tls.Config, may be nil without error if TLS is not
// configured.
func (c *ClientConfig) TLSConfig() (*tls.Config, error) {
	// Support deprecated variable names
	if c.TLSCA == "" && c.SSLCA != "" {
		c.TLSCA = c.SSLCA
	}
	if c.TLSCert == "" && c.SSLCert != "" {
		c.TLSCert = c.SSLCert
	}
	if c.TLSKey == "" && c.SSLKey != "" {
		c.TLSKey = c.SSLKey
	}

	if c.TLSCA == "" && c.TLSKey == "" && c.TLSCert == "" && !c.InsecureSkipVerify {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		Renegotiation:      tls.RenegotiateNever,
	}

	if c.TLSCA != "" {
		pool, err := makeCertPool([]string{c.TLSCA})
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}

	if c.TLSCert != "" && c.TLSKey != "" {
		err := loadCertificate(tlsConfig, c.TLSCert, c.TLSKey)
		if err != nil {
			return nil, err
		}
	}

	return tlsConfig, nil
}

func loadCertificate(config *tls.Config, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf(
			"could not load keypair %s:%s: %v", certFile, keyFile, err)
	}

	config.Certificates = []tls.Certificate{cert}
	config.BuildNameToCertificate()
	return nil
}

func makeCertPool(certFiles []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, certFile := range certFiles {
		pem, err := ioutil.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf(
				"could not read certificate %q: %v", certFile, err)
		}
		ok := pool.AppendCertsFromPEM(pem)
		if !ok {
			return nil, fmt.Errorf(
				"could not parse any PEM certificates %q: %v", certFile, err)
		}
	}
	return pool, nil
}

// End of reliance on internals

const sampleConfig string = `
  ## url of the squid proxy manager counters page
  url = "http://localhost:3128"

  ## Maximum time to receive response.
  response_timeout = "5s"

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false
`

func (s *Squid) SampleConfig() string {
	return sampleConfig
}

func (o *Squid) Description() string {
	return "Squid web proxy cache plugin"
}

// return an initialized Squid
func NewSquid() *Squid {
	return &Squid{
		Url:             "http://localhost:3128",
		ResponseTimeout: Duration{Duration: time.Second * 5},
	}
}

// Gather metrics
func (s *Squid) Gather(acc telegraf.Accumulator) error {
	if s.client == nil {
		tlsCfg, err := s.ClientConfig.TLSConfig()
		if err != nil {
			return err
		}
		s.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
			Timeout: s.ResponseTimeout.Duration,
		}
	}

	acc.AddError(s.gatherCounters(s.Url+"/squid-internal-mgr/counters", acc))

	return nil
}

// gather counters
func (s *Squid) gatherCounters(url string, acc telegraf.Accumulator) error {
	url += "/squid-internal-mgr/counters"
	resp, err := s.client.Get(url)
	if err != nil {
		return fmt.Errorf("unable to GET \"%s\": %s", url, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-OK status code returned from \"%s\": %d", url, resp.StatusCode)
	}

	fields := parseBody(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to parse body from \"%s\": %s", url, err)
	}

	tags := map[string]string{
		"source": s.Url,
	}

	acc.AddFields("squid", fields, tags)

	return nil
}

// parseBody accepts a response body as an io.Reader and uses bufio.NewScanner
// to walk the body. It returns the metric fields expected format is "this.key
// = 0.000\n"
func parseBody(body io.Reader) map[string]interface{} {
	fields := map[string]interface{}{}
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			// skip if this line isn't long enough
			if len(parts) != 2 {
				continue
			}

			// skip sample_time
			if parts[0] == "sample_time" {
				continue
			}

			key := strings.TrimSpace(parts[0])
			key = strings.Replace(key, ".", "_", -1)
			valueStr := strings.TrimSpace(parts[1])

			// src/mgr/CountersAction.h defines these all as double,
			// so turn them into 64-bit floats
			value, err := strconv.ParseFloat(valueStr, 64)
			if err != nil {
				continue
			}

			// store this field
			fields[key] = value
		}
	}
	return fields
}

func init() {
	inputs.Add("squid", func() telegraf.Input { return NewSquid() })
}
