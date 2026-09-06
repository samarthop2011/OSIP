// idrac_checker.go
// Build: go build -o idrac_checker idrac_checker.go
// Run: ./idrac_checker

package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	DBPath      = "idrac_targets.db"
	WorkerCount = 50
	Timeout     = 10 * time.Second
)

type CVEInfo struct {
	ID          string
	Description string
	Ports       []int
	CheckFunc   func(string, int) (bool, string)
}

type Target struct {
	ID   int
	IP   string
	Port int
}

type Result struct {
	Target      Target
	Vulnerable  bool
	CVE         string
	Details     string
	CheckedAt   time.Time
}

var (
	Red     = "\033[91m"
	Green   = "\033[92m"
	Yellow  = "\033[93m"
	Blue    = "\033[94m"
	Magenta = "\033[95m"
	Cyan    = "\033[96m"
	White   = "\033[97m"
	Bold    = "\033[1m"
	End     = "\033[0m"
)

func printBanner() {
	fmt.Printf("%s%s", Cyan, Bold)
	fmt.Println(`
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██╗██████╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗     ║
║  ██║██╔══██╗    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ║
║  ██║██████╔╝    ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝    ║
║  ██║██╔═══╝     ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ║
║  ██║██║         ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║    ║
║  ╚═╝╚═╝          ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ║
║                    iDRAC CVE Verification Engine v1.0                          ║
║                           Coded by SAM                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝`)
	fmt.Printf("%s", End)
	fmt.Printf("%s[+] Concurrent Workers: %d | Timeout: %v\n", Yellow, WorkerCount, Timeout)
	fmt.Printf("[+] CVE Database: 11 critical iDRAC vulnerabilities%s\n\n", End)
}

func getHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
}

// CVE-2018-1207: Authentication Bypass via /cgi-bin/putfile
func checkCVE_2018_1207(ip string, port int) (bool, string) {
	client := getHTTPClient()
	url := fmt.Sprintf("https://%s:%d/cgi-bin/putfile", ip, port)
	
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 || resp.StatusCode == 405 {
		return true, "Endpoint /cgi-bin/putfile accessible - potential auth bypass"
	}
	return false, "Not vulnerable"
}

// CVE-2018-1211: Path Traversal
func checkCVE_2018_1211(ip string, port int) (bool, string) {
	client := getHTTPClient()
	payloads := []string{
		"/../../../../etc/passwd",
		"/..%2f..%2f..%2f..%2fetc%2fpasswd",
	}
	
	for _, payload := range payloads {
		url := fmt.Sprintf("https://%s:%d%s", ip, port, payload)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		
		if strings.Contains(string(body), "root:") {
			return true, "Path traversal vulnerability confirmed"
		}
	}
	return false, "Not vulnerable"
}

// CVE-2019-3706: iDRAC9 Auth Bypass
func checkCVE_2019_3706(ip string, port int) (bool, string) {
	client := getHTTPClient()
	url := fmt.Sprintf("https://%s:%d/restgui/start.html", ip, port)
	
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	html := string(body)
	
	if strings.Contains(html, "iDRAC9") && strings.Contains(html, "2.60") {
		return true, "iDRAC9 version potentially vulnerable"
	}
	return false, "Not vulnerable"
}

// CVE-2020-5344: Buffer Overflow check via version detection
func checkCVE_2020_5344(ip string, port int) (bool, string) {
	client := getHTTPClient()
	url := fmt.Sprintf("https://%s:%d/restgui/start.html", ip, port)
	
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	html := string(body)
	
	vulnerableVersions := []string{"2.50", "2.52", "2.60", "3.20", "3.21", "3.30"}
	for _, ver := range vulnerableVersions {
		if strings.Contains(html, ver) {
			return true, fmt.Sprintf("Version %s may be vulnerable to buffer overflow", ver)
		}
	}
	return false, "Not vulnerable"
}

// CVE-2021-21538: Virtual Console Auth Bypass
func checkCVE_2021_21538(ip string, port int) (bool, string) {
	client := getHTTPClient()
	url := fmt.Sprintf("https://%s:%d/console/html5.html", ip, port)
	
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		return true, "Virtual Console endpoint accessible without auth"
	}
	return false, "Not vulnerable"
}

// CVE-2022-24422: VNC Console Bypass
func checkCVE_2022_24422(ip string, port int) (bool, string) {
	// Check VNC ports
	vncPorts := []int{5900, 5901, 5902}
	for _, vncPort := range vncPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, vncPort), 5*time.Second)
		if err == nil {
			conn.Close()
			return true, fmt.Sprintf("VNC port %d open - potential bypass", vncPort)
		}
	}
	return false, "VNC not exposed"
}

// CVE-2024-54085: Command Injection
func checkCVE_2024_54085(ip string, port int) (bool, string) {
	client := getHTTPClient()
	
	// Check for iDRAC9 with vulnerable firmware
	url := fmt.Sprintf("https://%s:%d/api/SessionService/Sessions", ip, port)
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		return true, "Session endpoint exposed - potential command injection"
	}
	return false, "Not vulnerable"
}

// CVE-2024-36435: Information Disclosure
func checkCVE_2024_36435(ip string, port int) (bool, string) {
	client := getHTTPClient()
	url := fmt.Sprintf("https://%s:%d/api/Status", ip, port)
	
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body), "iDRAC") && len(body) > 100 {
		return true, "Information disclosure via API endpoint"
	}
	return false, "Not vulnerable"
}

// CVE-2019-3705: Buffer Overflow
func checkCVE_2019_3705(ip string, port int) (bool, string) {
	// Similar version check
	return checkCVE_2020_5344(ip, port)
}

// CVE-2019-3707: WS-MAN Auth Bypass
func checkCVE_2019_3707(ip string, port int) (bool, string) {
	client := getHTTPClient()
	url := fmt.Sprintf("https://%s:%d/wsman", ip, port)
	
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 403 && resp.StatusCode != 401 {
		return true, "WS-MAN endpoint accessible without auth"
	}
	return false, "Not vulnerable"
}

// CVE-2021-21505: Undocumented Account
func checkCVE_2021_21505(ip string, port int) (bool, string) {
	client := getHTTPClient()
	
	// Try common default/undocumented credentials
	url := fmt.Sprintf("https://%s:%d/restgui/start.html", ip, port)
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body), "Azure Stack Hub") {
		return true, "Azure Stack Hub iDRAC - check for undocumented accounts"
	}
	return false, "Not vulnerable"
}

func getCVEChecks() []CVEInfo {
	return []CVEInfo{
		{"CVE-2018-1207", "iDRAC 7/8 Auth Bypass", []int{443, 80}, checkCVE_2018_1207},
		{"CVE-2018-1211", "iDRAC 7/8 Path Traversal", []int{443, 80}, checkCVE_2018_1211},
		{"CVE-2019-3705", "iDRAC Buffer Overflow", []int{443, 80}, checkCVE_2019_3705},
		{"CVE-2019-3706", "iDRAC9 Auth Bypass", []int{443, 80}, checkCVE_2019_3706},
		{"CVE-2019-3707", "iDRAC9 WS-MAN Bypass", []int{443, 80, 623}, checkCVE_2019_3707},
		{"CVE-2020-5344", "iDRAC Buffer Overflow RCE", []int{443, 80}, checkCVE_2020_5344},
		{"CVE-2021-21505", "Undocumented Account", []int{443, 80}, checkCVE_2021_21505},
		{"CVE-2021-21538", "Virtual Console Bypass", []int{443, 80, 5900}, checkCVE_2021_21538},
		{"CVE-2022-24422", "VNC Console Bypass", []int{443, 80, 5900}, checkCVE_2022_24422},
		{"CVE-2024-54085", "iDRAC9 Command Injection", []int{443, 80}, checkCVE_2024_54085},
		{"CVE-2024-36435", "iDRAC9 Info Disclosure", []int{443, 80}, checkCVE_2024_36435},
	}
}

func checkTarget(target Target, cves []CVEInfo, db *sql.DB, wg *sync.WaitGroup, results chan<- Result) {
	defer wg.Done()
	
	fmt.Printf("%s[*] Checking %s:%d%s\n", Blue, target.IP, target.Port, End)
	
	for _, cve := range cves {
		// Check if port matches
		portMatch := false
		for _, p := range cve.Ports {
			if p == target.Port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			continue
		}
		
		vulnerable, details := cve.CheckFunc(target.IP, target.Port)
		result := Result{
			Target:     target,
			Vulnerable: vulnerable,
			CVE:        cve.ID,
			Details:    details,
			CheckedAt:  time.Now(),
		}
		results <- result
		
		if vulnerable {
			fmt.Printf("%s[!] VULNERABLE: %s - %s - %s%s\n", Red, target.IP, cve.ID, cve.Description, End)
			fmt.Printf("%s    Details: %s%s\n", Yellow, details, End)
			
			// Update database
			updateDB(db, target, cve.ID, details)
		}
	}
}

func updateDB(db *sql.DB, target Target, cve, details string) {
	_, err := db.Exec(
		"UPDATE targets SET checked=1, vulnerable=1, details=? WHERE id=?",
		fmt.Sprintf("%s: %s", cve, details), target.ID,
	)
	if err != nil {
		fmt.Printf("%s[-] DB Update error: %v%s\n", Red, err, End)
	}
}

func getUncheckedTargets(db *sql.DB) []Target {
	rows, err := db.Query("SELECT id, ip, port FROM targets WHERE checked=0 LIMIT 100")
	if err != nil {
		fmt.Printf("%s[-] Query error: %v%s\n", Red, err, End)
		return nil
	}
	defer rows.Close()
	
	var targets []Target
	for rows.Next() {
		var t Target
		err := rows.Scan(&t.ID, &t.IP, &t.Port)
		if err == nil {
			targets = append(targets, t)
		}
	}
	return targets
}

func main() {
	printBanner()
	
	db, err := sql.Open("sqlite3", DBPath)
	if err != nil {
		fmt.Printf("%s[-] Failed to open database: %v%s\n", Red, err, End)
		return
	}
	defer db.Close()
	
	cves := getCVEChecks()
	
	fmt.Printf("%s[*] Loaded %d CVE checks%s\n", Cyan, len(cves), End)
	fmt.Printf("%s[*] Starting concurrent verification...%s\n\n", Green, End)
	
	var wg sync.WaitGroup
	results := make(chan Result, 100)
	
	// Result processor
	go func() {
		for r := range results {
			if !r.Vulnerable {
				// Mark as checked even if not vulnerable
				db.Exec("UPDATE targets SET checked=1 WHERE id=?", r.Target.ID)
			}
		}
	}()
	
	// Main loop
	for {
		targets := getUncheckedTargets(db)
		if len(targets) == 0 {
			fmt.Printf("%s[*] No unchecked targets. Waiting...%s\n", Yellow, End)
			time.Sleep(5 * time.Second)
			continue
		}
		
		fmt.Printf("%s[*] Found %d unchecked targets%s\n", Cyan, len(targets), End)
		
		// Process in batches
		semaphore := make(chan struct{}, WorkerCount)
		
		for _, target := range targets {
			wg.Add(1)
			semaphore <- struct{}{}
			
			go func(t Target) {
				defer func() { <-semaphore }()
				checkTarget(t, cves, db, &wg, results)
			}(target)
		}
		
		wg.Wait()
	}
}
