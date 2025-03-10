// Usage:
//   go build -o scan_local scan_local.go
//   ./scan_local
//
// Requirements:
//   - The four Method Security CLIs in $PATH:
//       osintscan, networkscan, webscan, methodwebtest
//   - Code handles color/log lines from both CLIs by parsing only
//     the trailing JSON block.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	domain     = "wayneindustries.xyz"
	resultsDir = "results_local"
)

// SubenumResult for "osintscan dns subenum passive"
type SubenumResult struct {
	Content struct {
		Domain          string   `json:"domain"`
		EnumerationType string   `json:"enumerationType"`
		Subdomains      []string `json:"subdomains"`
	} `json:"content"`
	Status int `json:"status"`
}

// PortScanReport for the final JSON from networkscan
type PortScanReport struct {
	Hosts []struct {
		Host  string `json:"host"`
		IP    string `json:"ip"`
		Ports []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
	} `json:"hosts"`
}

func main() {
	logInfo(fmt.Sprintf("Starting Automated External Assessment for %s", domain))

	os.MkdirAll(resultsDir, 0755)

	// 1) DNS Recon - records
	logInfo("1) DNS: Getting DNS Records")
	dnsRecordsFile := filepath.Join(resultsDir, "dns_records.json")
	runCommand("osintscan", []string{"dns", "records", "--domain", domain}, dnsRecordsFile)

	// 2) DNS Subenum
	logInfo("2) DNS: Subdomain Enumeration (Passive)")
	subenumOutFile := filepath.Join(resultsDir, "dns_subdomains_passive.json")
	subenumRaw, _ := runCommand(
		"osintscan",
		[]string{"dns", "subenum", "passive", "--domain", domain, "-o", "json"},
		subenumOutFile,
	)

	// parse logs => final JSON
	subenumJSON := parseTrailingJSON(subenumRaw)
	var subenumRes SubenumResult
	if err := json.Unmarshal([]byte(subenumJSON), &subenumRes); err != nil {
		logWarn(fmt.Sprintf("subenum parse failed: %v", err))
	}
	subdomains := subenumRes.Content.Subdomains
	logInfo(fmt.Sprintf("Discovered %d subdomains from subenum:", len(subdomains)))
	for _, s := range subdomains {
		fmt.Printf("   + %s\n", s)
	}

	// 3) DNS Zone Transfer
	logInfo("3) DNS: Zone Transfer Attempt")
	zoneFile := filepath.Join(resultsDir, "dns_zonetransfer.json")
	runCommand("osintscan",
		[]string{"dns", "zonetransfer", "--domains", domain},
		zoneFile,
	)

	// 4) Shodan
	logInfo("4) Shodan: Querying Shodan for domain")
	shodanFile := filepath.Join(resultsDir, "shodan_hostname.json")
	runCommand("osintscan",
		[]string{"shodan", "hostname", "--hostname", domain, "--query", "hostname:" + domain},
		shodanFile,
	)

	// 5) Network Scan each subdomain
	logInfo("5) NetworkScan: top 1000 ports for each discovered subdomain")
	for _, sub := range subdomains {
		logInfo(fmt.Sprintf("   -> Scanning %s ...", sub))
		nameForFile := safeName(sub)
		scanFile := filepath.Join(resultsDir, "port_scan_"+nameForFile+".json")

		out, _ := runCommand("networkscan",
			[]string{"port", "scan", "--target", sub, "--topports", "1000", "-o", "json"},
			scanFile,
		)

		parsedJSON := parseTrailingJSON(out)
		if parsedJSON == "" {
			logWarn(fmt.Sprintf("No final JSON from networkscan for %s; ignoring", sub))
			continue
		}
		var wrapper struct {
			Content PortScanReport `json:"content"`
		}
		if err := json.Unmarshal([]byte(parsedJSON), &wrapper); err == nil {
			countHosts := len(wrapper.Content.Hosts)
			logInfo(fmt.Sprintf("   -> JSON parse success for %s; found %d host(s)", sub, countHosts))
			for _, h := range wrapper.Content.Hosts {
				fmt.Printf("       Host: %s  IP: %s  Ports: %d\n", h.Host, h.IP, len(h.Ports))
				for _, p := range h.Ports {
					fmt.Printf("         - Port %d/%s\n", p.Port, p.Protocol)
				}
			}
		} else {
			logWarn(fmt.Sprintf("Could not parse port scan JSON for %s: %v", sub, err))
		}
	}

	// 6) Identify subdomains with open HTTP(80) or HTTPS(443)
	logInfo("6) Identifying subdomains that have port 80 or 443 open")
	var liveWebTargets []string
	files, err := os.ReadDir(resultsDir)
	if err == nil {
		for _, f := range files {
			fName := f.Name()
			if !strings.HasPrefix(fName, "port_scan_") || !strings.HasSuffix(fName, ".json") {
				continue
			}
			scanPath := filepath.Join(resultsDir, fName)
			rawBytes, _ := os.ReadFile(scanPath)
			rawStr := string(rawBytes)

			scanJSON := parseTrailingJSON(rawStr)
			if scanJSON == "" {
				continue
			}
			var wrapper struct {
				Content PortScanReport `json:"content"`
			}
			if err := json.Unmarshal([]byte(scanJSON), &wrapper); err == nil {
				for _, h := range wrapper.Content.Hosts {
					var hasWeb bool
					for _, p := range h.Ports {
						if p.Port == 80 || p.Port == 443 {
							hasWeb = true
							break
						}
					}
					if hasWeb {
						liveWebTargets = append(liveWebTargets, h.Host)
					}
				}
			}
		}
	}
	liveWebTargets = uniqueStrings(liveWebTargets)
	logInfo(fmt.Sprintf("Found %d subdomains with open HTTP/HTTPS ports", len(liveWebTargets)))
	for _, w := range liveWebTargets {
		fmt.Printf("   -> %s\n", w)
	}

	// 7) Web Enumeration (webscan)
	logInfo("7) Web Enumeration via webscan for each web-enabled subdomain")
	for _, sub := range liveWebTargets {
		logInfo(fmt.Sprintf("   => Enumerating %s", sub))
		safe := safeName(sub)

		// webserver probe
		probeHttpFile := filepath.Join(resultsDir, fmt.Sprintf("webserver_probe_http_%s.txt", safe))
		runCommand("webscan",
			[]string{"webserver", "probe", "--targets", "http://" + sub},
			probeHttpFile,
		)

		probeHttpsFile := filepath.Join(resultsDir, fmt.Sprintf("webserver_probe_https_%s.txt", safe))
		runCommand("webscan",
			[]string{"webserver", "probe", "--targets", "https://" + sub},
			probeHttpsFile,
		)

		// spider
		spiderFile := filepath.Join(resultsDir, fmt.Sprintf("spider_%s.json", safe))
		runCommand("webscan",
			[]string{"spider", "--targets", "http://" + sub, "-o", "json"},
			spiderFile,
		)

		// pagecapture
		pagecapHttpFile := filepath.Join(resultsDir, fmt.Sprintf("page_capture_http_%s.json", safe))
		runCommand("webscan",
			[]string{"pagecapture", "html", "request", "--target", "http://" + sub, "--timeout", "20"},
			pagecapHttpFile,
		)

		screenHttpFile := filepath.Join(resultsDir, fmt.Sprintf("screenshot_http_%s.json", safe))
		runCommand("webscan",
			[]string{"pagecapture", "screenshot", "browser", "--target", "http://" + sub, "--timeout", "30"},
			screenHttpFile,
		)
	}

	// 8) Basic Vuln Checks (methodwebtest)
	logInfo("8) Basic Vulnerability Checks via methodwebtest")
	for _, sub := range liveWebTargets {
		logInfo(fmt.Sprintf("   => Testing %s", sub))
		safe := safeName(sub)

		ptFileHttp := filepath.Join(resultsDir, fmt.Sprintf("webtest_path_traversal_http_%s.json", safe))
		runCommand("methodwebtest",
			[]string{
				"general", "path", "traversal",
				"--targets", "http://" + sub,
				"--paths", "/etc/passwd,/.git/config",
				"-o", "json",
			},
			ptFileHttp,
		)

		ptFileHttps := filepath.Join(resultsDir, fmt.Sprintf("webtest_path_traversal_https_%s.json", safe))
		runCommand("methodwebtest",
			[]string{
				"general", "path", "traversal",
				"--targets", "https://" + sub,
				"--paths", "/etc/passwd,/.git/config",
				"-o", "json",
			},
			ptFileHttps,
		)

		corsFileHttp := filepath.Join(resultsDir, fmt.Sprintf("webtest_cors_http_%s.json", safe))
		runCommand("methodwebtest",
			[]string{
				"general", "header", "misconfigured",
				"--targets", "http://" + sub,
				"--event", "CORS",
				"-o", "json",
			},
			corsFileHttp,
		)

		corsFileHttps := filepath.Join(resultsDir, fmt.Sprintf("webtest_cors_https_%s.json", safe))
		runCommand("methodwebtest",
			[]string{
				"general", "header", "misconfigured",
				"--targets", "https://" + sub,
				"--event", "CORS",
				"-o", "json",
			},
			corsFileHttps,
		)
	}

	logInfo("SCAN COMPLETE! Check the results in " + resultsDir)
}

// runCommand runs an external command, capturing stdout/stderr, writing it to a file.
func runCommand(name string, args []string, stdoutFile string) (string, error) {
	logInfo(fmt.Sprintf("[CMD] %s %s", name, strings.Join(args, " ")))
	cmd := exec.Command(name, args...)

	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stdoutBuf

	err := cmd.Run()
	outStr := stdoutBuf.String()

	if stdoutFile != "" {
		os.MkdirAll(filepath.Dir(stdoutFile), 0755)
		_ = os.WriteFile(stdoutFile, stdoutBuf.Bytes(), 0644)
	}

	if err != nil {
		logWarn(fmt.Sprintf("Command '%s' error: %v", name, err))
	}
	return outStr, err
}

// parseTrailingJSON extracts the last line that starts with '{' from a command’s combined output.
// networkscan / osintscan logs end with a final JSON object preceded by logs.
func parseTrailingJSON(fullOutput string) string {
	lines := strings.Split(fullOutput, "\n")
	// search from bottom up
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	return ""
}

// uniqueStrings deduplicates a slice of strings
func uniqueStrings(arr []string) []string {
	set := make(map[string]struct{})
	var result []string
	for _, s := range arr {
		if _, ok := set[s]; !ok {
			set[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// safeName cleans a subdomain name for use in filenames
func safeName(s string) string {
	return strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(s)
}

// logInfo prints a timestamped "INFO" line
func logInfo(msg string) {
	fmt.Printf("[%s] [INFO] %s\n", time.Now().Format("15:04:05"), msg)
}

// logWarn prints a timestamped "WARN" line
func logWarn(msg string) {
	fmt.Printf("[%s] [WARN] %s\n", time.Now().Format("15:04:05"), msg)
}
