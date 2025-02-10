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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/gomutex/godocx"
	"github.com/gomutex/godocx/docx"
)

var (
	domainFlag  = flag.String("domain", "", "Filter requests by domain")
	outputURL   = flag.String("url", "", "Target URL to analyze")
	format      = flag.String("format", "csv", "Output format (csv or json)")
	cookieFlag  = flag.String("cookie", "", "Cookies and headers to set before navigating to the URL")
	modeFlag    = flag.String("mode", "all", "Operation mode: extractbody, network, or all")
	outputDir   = flag.String("o", "./results/results.csv", "Output directory for results")
	timeoutFlag = flag.Duration("timeout", 30*time.Second, "Time to wait after navigation to capture requests")
	excludeFlag = flag.String("exclude", "", "Comma-separated file extensions to exclude (e.g., jpg,png,css,woff,woff2,gif,svg)")
	ignoreFlag  = flag.String("ignore", "", "Comma-separated file extensions to exclude (e.g., jpg,png,css,woff,woff2,gif,svg)")
)

func main() {
	flag.Parse()

	if *outputURL == "" {
		log.Fatal("Please provide a URL using the -url flag")
	}

	dir := filepath.Dir(*outputDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	excludeExts := parseExcludeExtensions(*excludeFlag)
	ignoreExts := parseExcludeExtensions(*ignoreFlag)
	ctx, cancel := setupBrowserContext()
	defer cancel()

	var (
		requests   = make(map[network.RequestID]*reqResData)
		finished   []network.RequestID
		requestsMu sync.Mutex
		sequenceID int
	)

	if *cookieFlag != "" {
		if err := setCookies(ctx, *cookieFlag); err != nil {
			log.Fatalf("Failed to set cookies: %v", err)
		}
	}
	listenNetworkEvents(ctx, &requests, &finished, &requestsMu, &sequenceID, excludeExts, ignoreExts)

	if err := navigateAndCapture(ctx); err != nil {
		log.Fatal(err)
	}

	dataList := processFinishedRequests(ctx, &requests, &finished, &requestsMu)
	extractedEntries := extractAllData(dataList)
	generateOutputs(dataList, extractedEntries)

	log.Println("Analysis completed")
}

func writeDOCX(outputDir string, dataList []*reqResData) error {

	doc, err := godocx.NewDocument()
	if err != nil {
		log.Fatal(err)
	}

	for _, data := range dataList {
		// Add a bold request heading
		doc.AddParagraph("").AddText(fmt.Sprintf("Request #%d: %s %s", data.SequenceID, data.Method, data.URL)).Bold(true)

		// Add fields
		addField(doc, "URL", data.URL)
		addField(doc, "Method", data.Method)
		addField(doc, "Request Headers", data.RequestHeaders)
		addField(doc, "Request Body", data.RequestBody)
		addField(doc, "Response Status", fmt.Sprintf("%.0f", data.ResponseStatus))
		addField(doc, "Response Headers", data.ResponseHeaders)
		addField(doc, "Response Body", string(data.ResponseBody))

		// Add a blank line for spacing
		doc.AddParagraph("")
	}

	// Save DOCX file
	//path := filepath.Join(outputDir, "requests.docx")

	err = doc.SaveTo(outputDir)
	if err != nil {
		return fmt.Errorf("failed to save DOCX: %w", err)
	}

	return nil
}

func writeExtractDOCX(outputDir string, entries []extractedData) error {
	//path := filepath.Join(outputDir, "extractall.docx")
	document, err := godocx.NewDocument()
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range entries {
		document.AddParagraph(" ").AddText(fmt.Sprintf("Type: %s", entry.ExtractType)).Bold(true)
		document.AddParagraph(" ").AddText(fmt.Sprintf("Source: %s", entry.Address))
		document.AddParagraph(" ").AddText(fmt.Sprintf("Content: %s", entry.Content))

		// Add a blank line for spacing
		document.AddParagraph(" ")
	}

	// Save DOCX file
	err = document.SaveTo(outputDir)
	if err != nil {
		return fmt.Errorf("failed to save DOCX: %w", err)
	}

	return nil
}

func addField(doc *docx.RootDoc, label string, value interface{}) {
	doc.AddParagraph(" ").AddText(label + ": ").Bold(true)

	switch v := value.(type) {
	case map[string]interface{}:
		jsonData, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			doc.AddParagraph(" ").AddText(fmt.Sprintf("%v", v))
		} else {
			doc.AddParagraph(" ").AddText(string(jsonData))
		}
	case string:
		doc.AddParagraph(" ").AddText(v)
	case []byte:
		doc.AddParagraph(" ").AddText(string(v))
	default:
		doc.AddParagraph(" ").AddText(fmt.Sprintf("%v", v))
	}
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
	//path := filepath.Join(outputDir, "requests.csv")
	file, err := os.Create(outputDir)
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

	//path := filepath.Join(outputDir, "requests.json")
	file, err := os.Create(outputDir)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func writeExtractedJSON(outputDir string, entries []extractedData) {
	type jsonEntry struct {
		Type    string `json:"type"`
		Source  string `json:"source"`
		Content string `json:"content"`
	}

	var output []jsonEntry
	for _, entry := range entries {
		output = append(output, jsonEntry{
			Type:    entry.ExtractType,
			Source:  entry.Address,
			Content: entry.Content,
		})
	}

	//path := filepath.Join(outputDir, "extractall.json")
	file, err := os.Create(outputDir)
	if err != nil {
		log.Fatalf("Failed to create JSON file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		log.Fatalf("Failed to write JSON data: %v", err)
	}
}

func writeExtractedCSV(outputDir string, entries []extractedData) {
	//path := filepath.Join(outputDir, "extractall.csv")
	file, err := os.Create(outputDir)
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

func extractData(body string, url string, entries *[]extractedData, seen map[string]bool) {
	patterns := map[string]*regexp.Regexp{
		"link":                          regexp.MustCompile(`(?i)(href|src)\s*=\s*["']((https?:\/\/|www\.)[^"'\s>]+)["']|https?:\/\/[^\s<>"']+|www\.[^\s<>"']+`),
		"domain":                        regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|ir|org|br|fr|ai|edu)(?:\.[a-z]{2,})*[/'\"]`),
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
		"username_creds":                regexp.MustCompile(`(?i)(username|login|user)[:=]\S+`),
		"password_creds":                regexp.MustCompile(`(?i)(password|pass|secret)[:=]\S+`),
		"postgresql_error":              regexp.MustCompile(`(?i)(postgresql.*?error|warning.*?\Wpg_|valid postgresql result|npgsql\.|pg::syntaxerror:|org\.postgresql\.util\.psqlexception|error:\s\ssyntax error at or near|error: parser: parse error at or near|postgresql query failed|org\.postgresql\.jdbc|pdo[./_\\]pgsql|psqlexception)`),
		"microsoft_sql_server_error":    regexp.MustCompile(`(?i)(driver.*? sql[\-\_\ ]*server|ole db.*? sql Server|\bsql server[^&lt;&quot;]+driver|warning.*?\W(mssql|sqlsrv)_|\bsql server[^&lt;&quot;]+[0-9a-fA-F]{8}|system\.data\.sqlclient\.sqlException|(?s)exception.*?\broadhouse\.Cms\.|microsoft sql native client error '[0-9a-fA-F]{8}|\[sql Server\]|odbc sql Server Driver|odbc Driver \d+ for SQL Server|sqlserver jdbc Driver|com\.jnetdirect\.jsql|macromedia\.jdbc\.sqlserver|zend_db_(adapter|statement)_sqlsrv_exception|com\.microsoft\.sqlserver\.jdbc|pdo[./_\\](mssql|sqlsrv)|sql(Srv|Server)Exception)`),
		"mysql_error":                   regexp.MustCompile(`(?i)(sql syntax.*?mysql|warning.*?\Wmysqli?_|mysqlsyntaxerrorexception|valid mysql result|check the manual that corresponds to your (mysql|mariadb) server version|unknown column '[^ ]+' in 'field list'|mysqlclient\.|com\.mysql\.jdbc|zend_db_(adapter|statement)_mysqli_exception|pdo[./_\\]mysql|mysqlexception)`),
		"sqlite_error":                  regexp.MustCompile(`(?i)(sql syntax.*?mysql|sqlite/jdbcdriver|sqlite\.exception|(microsoft|system)\.data\.sqlite\.sqliteexception|warning.*?\W(sqlite_|sqlite3::)|\[sqlite_error\]|sqlite error \d+:|sqlite3.operationalerror:|sqlite3::sqlexception|org\.sqlite\.jdbc|pdo[./_\\]sqlite|sqliteexception)`),
	}

	for label, regex := range patterns {
		matches := regex.FindAllString(body, -1)
		for _, match := range matches {
			key := match
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

func parseExcludeExtensions(excludeStr string) map[string]struct{} {
	excludeExts := make(map[string]struct{})
	if excludeStr == "" {
		return excludeExts
	}

	for _, ext := range strings.Split(excludeStr, ",") {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		excludeExts[strings.ToLower(ext)] = struct{}{}
	}
	return excludeExts
}

func setCookies(ctx context.Context, curlCmd string) error {
	cookies, _, domain := parseCurlCommand(curlCmd)
	domain = getRootDomain(domain)

	if err := chromedp.Run(ctx, network.Enable(), network.ClearBrowserCookies()); err != nil {
		return err
	}

	for _, cookie := range cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		err := chromedp.Run(ctx,
			network.SetCookie(name, value).
				WithDomain(domain).
				WithPath("/").
				WithHTTPOnly(false).
				WithSecure(false),
		)
		if err != nil {
			log.Printf("Failed to set cookie %s: %v", name, err)
		}
	}
	return nil
}

func extractAllData(dataList []*reqResData) []extractedData {
	var extractedEntries []extractedData
	seen := make(map[string]bool)

	for _, data := range dataList {
		sources := []struct {
			content string
			prefix  string
		}{
			{data.RequestBody, data.URL + "[RequestBody]"},
			{string(data.ResponseBody), data.URL + "[ResponseBody]"},
			{fmt.Sprintf("%q", data.ResponseHeaders), data.URL + "[ResponseHeaders]"},
			{fmt.Sprintf("%q", data.RequestHeaders), data.URL + "[RequestHeaders]"},
		}

		for _, source := range sources {
			extractData(source.content, source.prefix, &extractedEntries, seen)
		}
	}

	// Sort extractedEntries by ExtractType
	sort.Slice(extractedEntries, func(i, j int) bool {
		return extractedEntries[i].ExtractType < extractedEntries[j].ExtractType
	})

	return extractedEntries
}

func generateOutputs(dataList []*reqResData, extractedEntries []extractedData) {
	if *modeFlag == "extractbody" || *modeFlag == "all" {
		switch strings.ToLower(*format) {
		case "csv":
			writeExtractedCSV(*outputDir, extractedEntries)
		case "doc":
			writeExtractDOCX(*outputDir, extractedEntries)
		case "json":
			writeExtractedJSON(*outputDir, extractedEntries)
		default: // Default to CSV
			log.Fatalf("Unsupported format: %s", *format)
		}
	}

	if *modeFlag == "network" || *modeFlag == "all" {
		switch strings.ToLower(*format) {
		case "csv":
			writeCSV(*outputDir, dataList)
		case "json":
			writeJSON(*outputDir, dataList)
		case "doc":
			writeDOCX(*outputDir, dataList)
		default:
			log.Fatalf("Unsupported format: %s", *format)
		}
	}
}

func getExtension(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Split path to get the last segment
	path := u.Path
	if len(path) == 0 {
		return ""
	}

	// Remove query parameters and fragments
	cleanPath := strings.SplitN(path, "?", 2)[0]
	cleanPath = strings.SplitN(cleanPath, "#", 2)[0]

	// Get base filename and extension
	base := filepath.Base(cleanPath)
	ext := filepath.Ext(base)

	// Return lowercase extension for consistent comparison
	return strings.ToLower(ext)
}
