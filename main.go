package main

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

var (
	domainFlag  = flag.String("domain", "", "Filter requests by domain")
	outputURL   = flag.String("url", "", "Target URL to analyze")
	format      = flag.String("format", "csv", "Output format (csv or json)")
	cookieFlag  = flag.String("cookie", "", "Cookies and headers to set before navigating to the URL")
	modeFlag    = flag.String("mode", "all", "Operation mode: extractbody, network, or all")
	outputDir   = flag.String("o", ".", "Output directory for results")
	timeoutFlag = flag.Duration("timeout", 30*time.Second, "Time to wait after navigation to capture requests")
)

type reqResData struct {
	SequenceID      int                    `json:"sequence_id"`
	Domain          string                 `json:"domain"`
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	RequestHeaders  map[string]interface{} `json:"request_headers"`
	RequestBody     string                 `json:"request_body,omitempty"`
	ResponseStatus  float64                `json:"response_status"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	ResponseBody    []byte                 `json:"-"`
	RequestTime     time.Time              `json:"request_time"`
	ResponseTime    time.Time              `json:"response_time"`
	TimeDiff        string                 `json:"time_diff"`
}

func parseCurlCommand(curlCmd string) ([]string, map[string]string, string) {
	cookiePattern := `-H\s+'cookie:\s*(.*?)'`
	cookieRegex := regexp.MustCompile(cookiePattern)
	cookieMatches := cookieRegex.FindStringSubmatch(curlCmd)
	var cookies []string
	if len(cookieMatches) > 1 {
		cookies = strings.Split(cookieMatches[1], ";")
	}

	headerPattern := `-H\s+'([^:]+):\s*([^']+)'`
	headerRegex := regexp.MustCompile(headerPattern)
	headerMatches := headerRegex.FindAllStringSubmatch(curlCmd, -1)
	headers := make(map[string]string)
	for _, match := range headerMatches {
		headers[match[1]] = match[2]
	}

	urlPattern := `https?://([a-zA-Z0-9.-]+)`
	urlRegex := regexp.MustCompile(urlPattern)
	urlMatches := urlRegex.FindStringSubmatch(curlCmd)
	domain := ""
	if len(urlMatches) > 1 {
		fullDomain := urlMatches[1]
		parts := strings.Split(fullDomain, ".")
		if len(parts) > 2 {
			domain = "." + strings.Join(parts[len(parts)-2:], ".")
		} else {
			domain = "." + fullDomain
		}
	}

	return cookies, headers, domain
}

func getRootDomain(domain string) string {
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 2 {
		return "." + strings.Join(domainParts[len(domainParts)-2:], ".")
	}
	return domain
}

func main() {
	flag.Parse()

	if *outputURL == "" {
		log.Fatal("Please provide a URL using the -url flag")
	}

	os.MkdirAll(*outputDir, 0755)

	ctx, cancel := chromedp.NewExecAllocator(context.Background(),
		append(
			chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", false),
			chromedp.Flag("disable-gpu", false),
			chromedp.Flag("start-maximized", true),
		)...,
	)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	var (
		requests   = make(map[network.RequestID]*reqResData)
		finished   []network.RequestID
		requestsMu sync.Mutex
		sequenceID int
	)

	if *cookieFlag != "" {
		cookies, _, domain := parseCurlCommand(*cookieFlag)
		domain = getRootDomain(domain)

		err := chromedp.Run(ctx, network.Enable())
		if err != nil {
			log.Fatalf("Failed to enable network: %v", err)
		}

		err = chromedp.Run(ctx, network.ClearBrowserCookies())
		if err != nil {
			log.Printf("Failed to clear cookies: %v", err)
		}

		for _, cookie := range cookies {
			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) == 2 {
				name, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				err := chromedp.Run(ctx, network.SetCookie(name, value).
					WithDomain(domain).
					WithPath("/").
					WithHTTPOnly(false).
					WithSecure(false))
				if err != nil {
					log.Printf("Failed to set cookie %s: %v", name, err)
				}
			}
		}
	}

	chromedp.ListenTarget(ctx, func(v interface{}) {
		switch ev := v.(type) {
		case *network.EventRequestWillBeSent:
			requestDomain := extractDomain(ev.Request.URL)
			if !isDomainMatch(requestDomain, *domainFlag) {
				return
			}

			requestsMu.Lock()
			defer requestsMu.Unlock()
			if _, exists := requests[ev.RequestID]; !exists {
				sequenceID++
				reqBody := ""
				if ev.Request.HasPostData {
					go func(id network.RequestID) {
						var body string
						err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
							var err error
							body, err = network.GetRequestPostData(id).Do(ctx)
							return err
						}))
						if err == nil {
							requestsMu.Lock()
							if data, ok := requests[id]; ok {
								data.RequestBody = string(body)
							}
							requestsMu.Unlock()
						}
					}(ev.RequestID)
				}

				requests[ev.RequestID] = &reqResData{
					SequenceID:     sequenceID,
					Domain:         extractDomain(ev.Request.URL),
					URL:            ev.Request.URL,
					Method:         ev.Request.Method,
					RequestHeaders: ev.Request.Headers,
					RequestBody:    reqBody,
					RequestTime:    time.Now(),
				}
			}

		case *network.EventResponseReceived:
			requestsMu.Lock()
			defer requestsMu.Unlock()
			if data, exists := requests[ev.RequestID]; exists {
				data.ResponseStatus = float64(ev.Response.Status)
				data.ResponseHeaders = ev.Response.Headers
				data.ResponseTime = time.Now()
				data.TimeDiff = data.ResponseTime.Sub(data.RequestTime).String()
			}

		case *network.EventLoadingFinished:
			requestsMu.Lock()
			defer requestsMu.Unlock()
			finished = append(finished, ev.RequestID)
		}
	})

	if err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(*outputURL),
		chromedp.ActionFunc(autoScroll),
		chromedp.Sleep(*timeoutFlag),
	); err != nil {
		log.Fatal(err)
	}

	requestsMu.Lock()
	finishedIDs := finished
	requestsMu.Unlock()

	var dataList []*reqResData
	for _, id := range finishedIDs {
		var buf []byte
		err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			buf, err = network.GetResponseBody(id).Do(ctx)
			return err
		}))
		if err != nil {
			continue
		}

		requestsMu.Lock()
		if data, exists := requests[id]; exists {
			data.ResponseBody = buf
			dataList = append(dataList, data)
		}
		requestsMu.Unlock()
	}

	var extractedEntries []extractedData
	seen := make(map[string]bool)
	for _, data := range dataList {
		extractData(data.RequestBody, data.URL+"[RequestBody]", &extractedEntries, seen)
		extractData(string(data.ResponseBody), data.URL+"[ResponseBody]", &extractedEntries, seen)
		extractData(fmt.Sprintf("%q", data.ResponseHeaders), data.URL+"[ResponseHeaders]", &extractedEntries, seen)
		extractData(fmt.Sprintf("%q", data.RequestHeaders), data.URL+"[RequestHeaders]", &extractedEntries, seen)
	}

	if *modeFlag == "extractbody" || *modeFlag == "all" {
		writeExtractedCSV(*outputDir, extractedEntries)
	}
	if *modeFlag == "network" || *modeFlag == "all" {
		switch strings.ToLower(*format) {
		case "csv":
			writeCSV(*outputDir, dataList)
		case "json":
			writeJSON(*outputDir, dataList)
		default:
			log.Fatalf("Unsupported format: %s", *format)
		}
	}

	log.Println("Analysis completed")
}

func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	return u.Hostname()
}
func isDomainMatch(requestDomain, filterDomain string) bool {
	if filterDomain == "" {
		return false
	}

	if strings.HasPrefix(filterDomain, "*.") {
		baseDomain := filterDomain[2:]
		return strings.HasSuffix(requestDomain, baseDomain)
	}

	return requestDomain == filterDomain
}
func writeCSV(outputDir string, dataList []*reqResData) {
	path := filepath.Join(outputDir, "requests.csv")
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"SequenceID", "Domain", "URL", "Method", "RequestHeaders", "ResponseStatus", "ResponseHeaders", "RequestTime", "ResponseTime", "TimeDiff"}
	headers = append(headers, "RequestBody", "ResponseBody")

	writer.Write(headers)

	for _, data := range dataList {
		reqHeaders, _ := json.Marshal(data.RequestHeaders)
		resHeaders, _ := json.Marshal(data.ResponseHeaders)
		resBody := base64.StdEncoding.EncodeToString(data.ResponseBody)

		record := []string{
			fmt.Sprintf("%d", data.SequenceID),
			data.Domain,
			data.URL,
			data.Method,
			string(reqHeaders),
			fmt.Sprintf("%.0f", data.ResponseStatus),
			string(resHeaders),
			data.RequestTime.Format(time.RFC3339),
			data.ResponseTime.Format(time.RFC3339),
			data.TimeDiff,
		}

		record = append(record, base64.StdEncoding.EncodeToString([]byte(data.RequestBody)), resBody)

		writer.Write(record)
	}
}

func writeJSON(outputDir string, dataList []*reqResData) {
	type jsonData struct {
		SequenceID      int                    `json:"sequence_id"`
		Domain          string                 `json:"domain"`
		URL             string                 `json:"url"`
		Method          string                 `json:"method"`
		RequestHeaders  map[string]interface{} `json:"request_headers"`
		RequestBody     string                 `json:"request_body,omitempty"`
		ResponseStatus  float64                `json:"response_status"`
		ResponseHeaders map[string]interface{} `json:"response_headers"`
		ResponseBody    string                 `json:"response_body,omitempty"`
		RequestTime     string                 `json:"request_time"`
		ResponseTime    string                 `json:"response_time"`
		TimeDiff        string                 `json:"time_diff"`
	}

	var output []jsonData
	for _, d := range dataList {
		output = append(output, jsonData{
			SequenceID:      d.SequenceID,
			Domain:          d.Domain,
			URL:             d.URL,
			Method:          d.Method,
			RequestHeaders:  d.RequestHeaders,
			RequestBody:     base64.StdEncoding.EncodeToString([]byte(d.RequestBody)),
			ResponseStatus:  d.ResponseStatus,
			ResponseHeaders: d.ResponseHeaders,
			ResponseBody:    base64.StdEncoding.EncodeToString(d.ResponseBody),
			RequestTime:     d.RequestTime.Format(time.RFC3339),
			ResponseTime:    d.ResponseTime.Format(time.RFC3339),
			TimeDiff:        d.TimeDiff,
		})
	}

	path := filepath.Join(outputDir, "requests.json")
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func isImageOrFont(contentType, url string) bool {
	pattern := regexp.MustCompile(`(?i)(image/.*|font/.*|\.png$|\.jpe?g$|\.gif$|\.bmp$|\.webp$|\.woff2?$|\.ttf$|\.otf$|\.eot$)`)
	return pattern.MatchString(contentType) || pattern.MatchString(url)
}

func saveAsset(downloadsDir, url2 string, body []byte, counter *int) {
	parsedURL, err := url.Parse(url2)
	if err != nil {
		return
	}

	fileName := sanitizeFilename(filepath.Base(parsedURL.Path))
	if fileName == "" {
		*counter++
		fileName = fmt.Sprintf("asset_%d", *counter)
	}

	filePath := filepath.Join(downloadsDir, fileName)
	os.WriteFile(filePath, body, 0644)
}

func sanitizeFilename(name string) string {
	return regexp.MustCompile(`[\\/:*?"<>|]`).ReplaceAllString(name, "_")
}

type extractedData struct {
	ExtractType string
	Address     string
	Content     string
}

func writeExtractedCSV(outputDir string, entries []extractedData) {
	path := filepath.Join(outputDir, "extractall.csv")
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"data_type", "source_address", "matched_content"}
	writer.Write(headers)

	for _, entry := range entries {
		writer.Write([]string{entry.ExtractType, entry.Address, entry.Content})
	}
}
func autoScroll(ctx context.Context) error {
	const (
		scrollDelay = time.Second
		maxRetries  = 10
	)

	var (
		stableCount int
	)

	for stableCount < maxRetries {
		var currentHeight int64

		if err := chromedp.Evaluate(`document.documentElement.scrollHeight`, &currentHeight).Do(ctx); err != nil {
			return fmt.Errorf("failed to get scroll height: %w", err)
		}

		if err := chromedp.Evaluate(`window.scrollTo(0, document.documentElement.scrollHeight)`, nil).Do(ctx); err != nil {
			return fmt.Errorf("failed to scroll: %w", err)
		}

		time.Sleep(scrollDelay)

		if err := chromedp.Evaluate(`window.scrollTo({ top: 100, left: 100, behavior: 'smooth' });`, nil).Do(ctx); err != nil {
			return fmt.Errorf("failed to scroll: %w", err)
		}
		time.Sleep(scrollDelay)
		stableCount++

	}

	return nil
}
func extractData(body string, url string, entries *[]extractedData, seen map[string]bool) {
	patterns := map[string]*regexp.Regexp{
		"link":                          regexp.MustCompile(`/(href|src)\s*=\s*["']((https?:\/\/|www\.)[^"'\s>]+)["']/gi`),
		"email":                         regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		"ipv4":                          regexp.MustCompile(`\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b`),
		"file_path":                     regexp.MustCompile(`(?i)([\p{L}\d_\-~/][\p{L}\d_\-~./\\]*\.(?:txt|pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|bmp|svg|woff2?|ttf|eot|otf|zip|tar\.gz))|\b(?:/|\./|\.\./)[\p{L}\d_\-~./\\]+\b`),
		"jwt":                           regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		"password":                      regexp.MustCompile(`(?i)password\s*[=:]\s*["']([^"']+)["']`),
		"token":                         regexp.MustCompile(`(?i)(token\s*[=:]\s*["'][\w-]+["']|bearer\s+[\w-]+\b)`),
		"google_api":                    regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
		"firebase":                      regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
		"google_captcha":                regexp.MustCompile(`6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`),
		"google_oauth":                  regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
		"amazon_aws_access_key_id":      regexp.MustCompile(`A[SK]IA[0-9A-Z]{16}`),
		"amazon_mws_auth_toke":          regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		"amazon_aws_url":                regexp.MustCompile(`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
		"amazon_aws_url2":               regexp.MustCompile(`([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)`),
		"facebook_access_token":         regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
		"authorization_basic":           regexp.MustCompile(`basic [a-zA-Z0-9=:_\+\/-]{5,100}`),
		"authorization_bearer":          regexp.MustCompile(`bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`),
		"authorization_api":             regexp.MustCompile(`api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`),
		"mailgun_api_key":               regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		"twilio_api_key":                regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		"twilio_account_sid":            regexp.MustCompile(`AC[a-zA-Z0-9_\-]{32}`),
		"twilio_app_sid":                regexp.MustCompile(`AP[a-zA-Z0-9_\-]{32}`),
		"paypal_braintree_access_token": regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
		"square_oauth_secret":           regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
		"square_access_token":           regexp.MustCompile(`sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
		"stripe_standard_api":           regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"stripe_restricted_api":         regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
		"github_access_token":           regexp.MustCompile(`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`),
		"rsa_private_key":               regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		"ssh_dsa_private_key":           regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
		"ssh_dc_private_key":            regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
		"pgp_private_block":             regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		"json_web_token":                regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`),
		"slack_token":                   regexp.MustCompile(`\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`),
		"SSH_privKey":                   regexp.MustCompile(`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
		"possible_Creds":                regexp.MustCompile(`(?i)(password\s*[=:\"]+\s*[^\s]+|password is\s*[=:\"]*\s*[^\s]+)`),
	}

	for label, regex := range patterns {
		matches := regex.FindAllString(body, -1)
		for _, match := range matches {
			key := fmt.Sprintf("%s|%s", label, match)
			if !seen[key] {
				*entries = append(*entries, extractedData{
					ExtractType: label,
					Address:     url,
					Content:     match,
				})
				seen[key] = true
			}
		}
	}
}
