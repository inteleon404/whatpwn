package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
//  CONSTANTS & VERSION
// ═══════════════════════════════════════════════════════════════════════════════

const (
	toolName    = "WhatPwn"
	toolVersion = "1.1.2"
	toolAuthor  = "Inteleon404"
	toolDesc    = "Advanced Credentials & Secrets Disclosure Hunter"
)

// ═══════════════════════════════════════════════════════════════════════════════
//  TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// Pattern represents a single regex detection pattern
type Pattern struct {
	Name    string         // Human-readable pattern name
	Re      *regexp.Regexp // Compiled regex
	Keyword bool           // true = keyword=value style (relaxed FP)
	Custom  bool           // true = user-supplied via -e flag
}

// Finding represents a single discovered credential/secret
type Finding struct {
	URL   string `json:"url"`
	Type  string `json:"type"`
	Match string `json:"match"`
}

// Stats tracks scanning statistics
type Stats struct {
	URLs     int64
	Found    int64
	Dupes    int64
	Errors   int64
	Bytes    int64
	Requests int64
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════════════════

var (
	patterns []Pattern
	seen     sync.Map
	st       Stats
	outFile  *os.File
	jsonOut  *os.File
	start    time.Time
)

// ═══════════════════════════════════════════════════════════════════════════════
//  FLAGS
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// Connection
	threadsFlag   = flag.Int("t", 25, "concurrent threads")
	timeoutFlag   = flag.Int("timeout", 15, "request timeout in seconds")
	retryFlag     = flag.Int("retry", 1, "retry count on failure")
	uaFlag        = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "user-agent")
	proxyFlag     = flag.String("proxy", "", "http proxy (e.g. http://127.0.0.1:8080)")
	verifyTLSFlag = flag.Bool("verify", false, "verify TLS certificates")
	headerFlag    = flag.String("H", "", "custom header (e.g. 'Cookie: session=abc')")

	// Input/Output
	listFlag   = flag.String("l", "", "input file containing URLs (default: stdin)")
	outputFlag = flag.String("o", "", "output file path")
	jsonFlag   = flag.String("json", "", "JSON output file path")
	extraFlag  = flag.String("e", "", "extra regex file (one regex per line)")

	// Behavior
	silentFlag    = flag.Bool("silent", false, "silent mode (no banner/summary)")
	noColorFlag   = flag.Bool("nc", false, "no color output")
	entropyFlag   = flag.Bool("entropy", false, "entropy-filter keyword matches")
	minEntropyF   = flag.Float64("min-entropy", 3.2, "minimum shannon entropy (with -entropy)")
	maxBodyFlag   = flag.Int("max-body", 5, "max response body size to scan (MB)")
	maxMatchFlag  = flag.Int("mm", 5, "max matches per pattern per page")
	showStatsFlag = flag.Bool("stats", false, "show detailed statistics")
)

// ═══════════════════════════════════════════════════════════════════════════════
//  COLOR CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	C_RESET  = "\033[0m"
	C_BOLD   = "\033[1m"
	C_DIM    = "\033[2m"
	C_ITALIC = "\033[3m"
	C_UNDER  = "\033[4m"

	C_BLACK   = "\033[30m"
	C_RED     = "\033[31m"
	C_GREEN   = "\033[32m"
	C_YELLOW  = "\033[33m"
	C_BLUE    = "\033[34m"
	C_MAGENTA = "\033[35m"
	C_CYAN    = "\033[36m"
	C_WHITE   = "\033[37m"

	C_GRAY = "\033[90m"

	C_BRED = "\033[1;31m"
	C_BGRN = "\033[1;32m"
	C_BYLW = "\033[1;33m"
	C_BBLU = "\033[1;34m"
	C_BMAG = "\033[1;35m"
	C_BCYN = "\033[1;36m"
	C_BWHT = "\033[1;37m"

	C_ORYLW = "\033[0;33m" // orange/yellow for banner
)

// colorize wraps string with color code if enabled
func colorize(enabled bool, code, s string) string {
	if !enabled {
		return s
	}
	return code + s + C_RESET
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CUSTOM USAGE (nuclei/projectdiscovery-style grouped help)
// ═══════════════════════════════════════════════════════════════════════════════

func printUsage() {
	nc := !*noColorFlag
	hdr := func(s string) string { return colorize(nc, C_BBLU, s) }
	// flg pads the raw label to a fixed width BEFORE colorizing, so ANSI
	// escape bytes never get counted toward column width (which would
	// otherwise break alignment when color is enabled).
	flg := func(s string) string { return colorize(nc, C_BYLW, fmt.Sprintf("%-18s", s)) }
	def := func(s string) string { return colorize(nc, C_GRAY, s) }

	fmt.Println(colorize(nc, C_BRED, ` ▓ ▄  ▓ █▄▄▄  ▀▀▓ █▄▄  █▀▀▓ ▓ ▄  ▓ ▓▀▀█`))
	fmt.Println(colorize(nc, C_BRED, ` █ █ ▄█ █  █ █   ▄ █   █   █ █ ▄█ █  █`))
	fmt.Println(colorize(nc, C_BRED, ` ▓▄█▄█  █  ▓ ▓▄▄▓ █▄▄▓ ▓▀▀▀ ▓▄█▄█  █  ▓`))
	fmt.Printf("\n  %s v%s | %s\n\n", colorize(nc, C_BCYN, toolName), toolVersion, toolDesc)

	fmt.Printf("%s\n", hdr("USAGE:"))
	fmt.Printf("  whatpwn [flags]\n\n")

	fmt.Printf("%s\n", hdr("INPUT:"))
	fmt.Printf("  %s stdin (default) or -l for a list of URLs/hosts\n", flg("-l string"))
	fmt.Println()

	fmt.Printf("%s\n", hdr("OUTPUT:"))
	fmt.Printf("  %s write findings to file\n", flg("-o string"))
	fmt.Printf("  %s write findings as JSON lines\n", flg("-json string"))
	fmt.Printf("  %s disable color output %s\n", flg("-nc"), def("(default false)"))
	fmt.Printf("  %s silent mode, no banner/summary %s\n", flg("-silent"), def("(default false)"))
	fmt.Printf("  %s show detailed scan statistics %s\n", flg("-stats"), def("(default false)"))
	fmt.Println()

	fmt.Printf("%s\n", hdr("CONFIG:"))
	fmt.Printf("  %s concurrent threads %s\n", flg("-t int"), def("(default 25)"))
	fmt.Printf("  %s request timeout in seconds %s\n", flg("-timeout int"), def("(default 15)"))
	fmt.Printf("  %s retry count on failure %s\n", flg("-retry int"), def("(default 1)"))
	fmt.Printf("  %s custom user-agent\n", flg("-ua string"))
	fmt.Printf("  %s custom header, e.g. 'Cookie: session=abc'\n", flg("-H string"))
	fmt.Printf("  %s http proxy, e.g. http://127.0.0.1:8080\n", flg("-proxy string"))
	fmt.Printf("  %s verify TLS certificates %s\n", flg("-verify"), def("(default false)"))
	fmt.Println()

	fmt.Printf("%s\n", hdr("FILTER:"))
	fmt.Printf("  %s extra regex file, one pattern per line\n", flg("-e string"))
	fmt.Printf("  %s entropy-filter keyword matches %s\n", flg("-entropy"), def("(default false)"))
	fmt.Printf("  %s minimum shannon entropy %s\n", flg("-min-entropy float"), def("(default 3.2)"))
	fmt.Printf("  %s max response body size to scan, MB %s\n", flg("-max-body int"), def("(default 5)"))
	fmt.Printf("  %s max matches per pattern per page %s\n", flg("-mm int"), def("(default 5)"))
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ASCII BANNER
// ═══════════════════════════════════════════════════════════════════════════════

func printBanner() {
	if *silentFlag {
		return
	}

	nc := !*noColorFlag

	fmt.Println()

	if nc {
		banner := `[0;31;47m▓[0;37m [0;31m▄[0;37m  [0;31m▓[0;37m [0;31m█▄▄▄[0;37m  [0;31m▀▀▓[0;37m [0;31m█▄▄[0;37m  [0;31m█▀▀▓[0;37m [0;31;47m▓[0;37m [0;31m▄[0;37m  [0;31m▓[0;37m [0;31;47m▓[0;31m▀▀█[0m
[0;31m█[0;37m [0;31m█[0;37m [0;31m▄█[0;37m [0;31m█[0;37m  [0;31m█[0;37m [0;31m█▀▀█[0;37m [0;31m█[0;37m  [0;31m▄[0;37m [0;31m█[0;37m  [0;31m█[0;37m [0;31m█[0;37m [0;31m█[0;37m [0;31m▄█[0;37m [0;31m█[0;37m  [0;31m█[0m
[0;31m▓▄█▄█[0;37m  [0;31m█[0;37m  [0;31;47m▓[0;37m [0;31m▓▄▄[0;31;47m▓[0;37m [0;31m█▄▄[0;31;47m▓[0;37m [0;31;47m▓[0;31m▀▀▀[0;37m [0;31m▓▄█▄█[0;37m  [0;31m█[0;37m  [0;31m▓[0m`

		fmt.Println(banner)
	} else {
		fmt.Println(`▓ ▄  ▓ █▄▄▄  ▀▀▓ █▄▄  █▀▀▓ ▓ ▄  ▓ ▓▀▀█`)
		fmt.Println(`█ █ ▄█ █  █ █▀▀█ █  ▄ █  █ █ █ ▄█ █  █`)
		fmt.Println(`▓▄█▄█  █  ▓ ▓▄▄▓ █▄▄▓ ▓▀▀▀ ▓▄█▄█  █  ▓`)
	}

	fmt.Println()

	fmt.Printf("  %s v%s | %s\n",
		colorize(nc, C_BCYN, toolName),
		toolVersion,
		colorize(nc, C_GRAY, toolDesc),
	)

	fmt.Printf("  %s %d patterns loaded | threads: %d | timeout: %ds\n",
		colorize(nc, C_CYAN, "▸"),
		len(patterns),
		*threadsFlag,
		*timeoutFlag,
	)

	fmt.Println(colorize(nc, C_GRAY, "  "+strings.Repeat("─", 56)))
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FALSE POSITIVE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// all-digit detection
	allDigitRe = regexp.MustCompile(`^\d+$`)

	// html tag detection
	htmlTagRe = regexp.MustCompile(`^</?[a-zA-Z]`)

	// url-only detection
	urlOnlyRe = regexp.MustCompile(`^https?://[^\s]+$`)

	// common false positive words/fragments
	fpWords = []string{
		// placeholders
		"example", "sample", "placeholder", "your_", "your-", "<your",
		"my_", "my-", "insert_", "enter_", "replace_", "fill_",
		"type_here", "${", "{{", "%s", "%d", "{token}", "{secret}",
		// documentation
		"todo", "fixme", "lorem", "ipsum", "hackme", "notreal",
		// test values
		"xxxx", "****", "....", "aaaa", "bbbb", "cccc",
		"changeme", "change_me", "dummy", "fake", "mock",
		"redacted", "censored", "hidden", "masked",
		// keyboard patterns
		"qwerty", "asdf", "zxcv", "qazwsx",
		// sequential
		"abcdef", "123456", "000000", "111111",
		"aaaaaa", "test123", "test_123", "testtest",
		"sample_value", "example_value",
		// common FP
		"falsepositive", "false_positive", "notasecret",
		"not_secret", "no_secret", "empty_secret",
	}

	// exact value denies
	denyValues = map[string]bool{
		// booleans
		"true": true, "false": true, "yes": true, "no": true,
		"on": true, "off": true, "enabled": true, "disabled": true,
		// nulls
		"null": true, "none": true, "nil": true, "undefined": true,
		"nan": true, "void": true, "empty": true, "blank": true,
		// numbers
		"0": true, "1": true, "-1": true, "-": true, "_": true,
		// config keys (value == key name means no real value)
		"password": true, "passwd": true, "pwd": true,
		"secret": true, "token": true, "key": true,
		"apikey": true, "api_key": true, "api-key": true,
		"secret_key": true, "secret-key": true, "secretkey": true,
		"access_key": true, "access-key": true, "accesskey": true,
		"auth_token": true, "auth-token": true, "authtoken": true,
		"access_token": true, "access-token": true,
		"client_secret": true, "client-secret": true,
		"private_key": true, "private-key": true,
		"public_key": true, "public-key": true,
		// auth headers
		"bearer": true, "basic": true, "digest": true, "oauth": true,
		// env/config
		"env": true, "config": true, "settings": true, "opts": true,
		"params": true, "headers": true, "options": true,
		// common placeholder values
		"changeme": true, "change_me": true, "change-me": true,
		"your_password": true, "your-password": true, "yourpassword": true,
		"password_here": true, "password-here": true,
		"enter_password": true, "enter-password": true,
		"placeholder": true, "placeholder_value": true,
		"secret_here": true, "token_here": true, "key_here": true,
		"xxx": true, "xxxx": true, "xxxxx": true,
		// sequential numbers
		"12345678": true, "123456789": true, "1234567890": true,
		"00000000": true, "11111111": true, "1234567890123456": true,
		// common weak passwords
		"password123": true, "password1": true, "admin123": true,
		"letmein": true, "welcome": true, "monkey": true,
		"dragon": true, "master": true, "login": true,
		"abc123": true, "qwerty123": true, "root": true,
		"toor": true, "administrator": true, "guest": true,
		// framework defaults
		"changeit": true, "changeit123": true, "default": true,
		"changeme123": true, "changeme_123": true,
	}
)

// calculateEntropy computes Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var e float64
	l := float64(len(s))
	for _, n := range freq {
		p := float64(n) / l
		e -= p * math.Log2(p)
	}
	return e
}

// hasLongRepeatRun reports whether s contains the same byte repeated 5 or
// more times consecutively (e.g. "aaaaa", "11111").
//
// This replaces the RE2-incompatible backreference regex `(.)\1{4,}`.
// Go's regexp package uses RE2, which intentionally does not support
// backreferences, so repeated-character detection is implemented here as
// plain native Go logic instead: a single linear scan over the string
// tracking the current run length.
func hasLongRepeatRun(s string) bool {
	const minRun = 5 // same semantics as the original {4,} after one base char: 1+4 = 5
	if len(s) < minRun {
		return false
	}
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			run++
			if run >= minRun {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// isFPKeyword checks if a keyword=value match is likely a false positive
// (relaxed rules — matches YAML behavior, shows short values like "h")
func isFPKeyword(v string, useEntropy bool) bool {
	if v == "" {
		return true
	}
	low := strings.ToLower(v)

	// exact deny list
	if denyValues[low] {
		return true
	}

	// pure numbers (likely IDs, not secrets)
	if allDigitRe.MatchString(low) && len(low) < 12 {
		return true
	}

	// HTML tags
	if htmlTagRe.MatchString(v) {
		return true
	}

	// pure URLs (not secrets)
	if urlOnlyRe.MatchString(v) && !strings.Contains(v, "@") {
		return true
	}

	// FP word fragments
	for _, w := range fpWords {
		if strings.Contains(low, w) {
			return true
		}
	}

	// repeated characters (e.g. "aaaaaa", "111111")
	if len(v) > 6 && hasLongRepeatRun(v) {
		return true
	}

	// entropy check (optional)
	if useEntropy && len(v) >= 8 {
		if calculateEntropy(v) < *minEntropyF {
			return true
		}
	}

	return false
}

// isFPValue checks if a structured token match is a false positive
// (strict rules — structured tokens should be long and random)
func isFPValue(v string, useEntropy bool) bool {
	if len(v) < 6 {
		return true
	}
	return isFPKeyword(v, useEntropy)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MATCH CLEANING
//  "sentry_key": "this" → sentry_key:this
//  refresh_token = "h"  → refresh_token=h
// ═══════════════════════════════════════════════════════════════════════════════

var (
	sepCleanupRe = regexp.MustCompile(`\s*([=:])\s*`)
	quoteStripRe = regexp.MustCompile(`["'` + "`" + `]`)
	trailingRe   = regexp.MustCompile(`[,;)\]}]+$`)
	leadRe       = regexp.MustCompile(`^[,;\[{(]+`)
)

func cleanMatch(s string) string {
	s = strings.TrimSpace(s)
	s = sepCleanupRe.ReplaceAllString(s, "$1")
	s = quoteStripRe.ReplaceAllString(s, "")
	s = trailingRe.ReplaceAllString(s, "")
	s = leadRe.ReplaceAllString(s, "")
	s = strings.TrimRight(s, ".")
	// collapse whitespace
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PATTERN REGISTRATION
// ═══════════════════════════════════════════════════════════════════════════════

// addP registers a new structured pattern
func addP(name, re string) {
	comp, err := regexp.Compile(re)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] pattern '%s' failed to compile: %v\n", name, err)
		return
	}
	patterns = append(patterns, Pattern{Name: name, Re: comp})
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STRUCTURED PATTERNS — Exact Format Tokens (200+ patterns)
// ═══════════════════════════════════════════════════════════════════════════════

func initStructuredPatterns() {
	/* ────────────────────────────────────────────────────────────────
	   AWS / AMAZON WEB SERVICES
	──────────────────────────────────────────────────────────────── */

	addP("AWS Access Key ID",
		`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`)

	addP("AWS Access Key (Context)",
		`(?i)(?:aws|amazon)[_\-.]?access[_\-.]?key[_\-.]?id\s*[=:]\s*["']?(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}["']?`)

	addP("AWS Secret Key (Context)",
		`(?i)aws[_\-.]?secret[_\-.]?access[_\-.]?key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?`)

	addP("AWS Secret Key (40char near keyword)",
		`(?i)(?:secret|key|token|credential).{0,30}?["']?[A-Za-z0-9/+]{40}["']?`)

	addP("AWS Session Token",
		`(?i)aws[_\-.]?session[_\-.]?token\s*[=:]\s*["']?[A-Za-z0-9/+=]{50,}["']?`)

	addP("AWS MWS Auth Token",
		`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	addP("AWS S3 Error: InvalidAccessKeyId",
		`InvalidAccessKeyId`)

	addP("AWS S3 Error: SignatureDoesNotMatch",
		`SignatureDoesNotMatch`)

	addP("AWS S3 Error: InvalidURI",
		`InvalidURI`)

	addP("AWS S3 Error: InvalidArgument",
		`InvalidArgument`)

	addP("AWS S3 Error: NoSuchBucket",
		`NoSuchBucket`)

	addP("AWS S3 Error: NoSuchKey",
		`NoSuchKey`)

	addP("AWS S3 Error: AccessDenied",
		`AccessDenied.*ListBucketResult|ListBucketResult.*AccessDenied`)

	addP("AWS S3 Error: BucketAlreadyExists",
		`BucketAlreadyExists`)

	addP("AWS S3 Error: PermanentRedirect",
		`PermanentRedirect.*s3\.amazonaws\.com`)

	addP("AWS S3 Open Bucket Listing",
		`<ListBucketResult[\s>]`)

	addP("AWS S3 Bucket Contents",
		`<Contents>.*?<Key>[^<]+</Key>`)

	addP("AWS S3 Bucket URL",
		`[a-zA-Z0-9._\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`)

	addP("AWS S3 Bucket Path",
		`s3://[a-zA-Z0-9._\-]+`)

	addP("AWS S3 Console URL",
		`s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9._\-]+`)

	addP("AWS ARN",
		`arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:\S+`)

	addP("AWS Cognito Identity Pool ID",
		`[a-f0-9]{8}:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)

	addP("AWS Cognito User Pool ID",
		`[a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{9}`)

	addP("AWS CloudFront Distribution",
		`[a-z0-9]+\.cloudfront\.net`)

	addP("AWS ELB URL",
		`[a-zA-Z0-9\-]+\.elb\.amazonaws\.com`)

	addP("AWS EC2 Instance",
		`ec2[_\-.]?\d{1,3}[_\-.]?\d{1,3}[_\-.]?\d{1,3}[_\-.]?\d{1,3}\.compute\.amazonaws\.com`)

	addP("AWS Lambda Function ARN",
		`arn:aws:lambda:[a-z0-9\-]+:\d{12}:function:[a-zA-Z0-9\-_]+`)

	addP("AWS DynamoDB Table",
		`dynamodb\.[a-z0-9\-]+\.amazonaws\.com`)

	addP("AWS SQS Queue",
		`sqs\.[a-z0-9\-]+\.amazonaws\.com/[0-9]+/[a-zA-Z0-9\-_]+`)

	addP("AWS SNS Topic",
		`sns\.[a-z0-9\-]+\.amazonaws\.com/[0-9]+/[a-zA-Z0-9\-_]+`)

	addP("AWS RDS Endpoint",
		`[a-zA-Z0-9\-]+\.rds\.amazonaws\.com`)

	addP("AWS Secrets Manager",
		`arn:aws:secretsmanager:[a-z0-9\-]+:\d{12}:secret:[a-zA-Z0-9/_+=.\-]+`)

	/* ────────────────────────────────────────────────────────────────
	   MICROSOFT AZURE
	──────────────────────────────────────────────────────────────── */

	addP("Azure Storage Account Key",
		`AccountKey=[A-Za-z0-9/+=]{88}`)

	addP("Azure Storage Connection String",
		`(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9/+=]{88}`)

	addP("Azure Client Secret",
		`(?i)azure[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9~._\-]{30,})["']?`)

	addP("Azure Subscription ID",
		`(?i)azure[_\-.]?subscription[_\-.]?id\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Azure Tenant ID",
		`(?i)azure[_\-.]?tenant[_\-.]?id\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Azure AD App ID",
		`(?i)azure[_\-.]?ad[_\-.]?app[_\-.]?id\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Azure Service Principal",
		`(?i)azure[_\-.]?service[_\-.]?principal\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Azure SAS Token",
		`(?i)\?sv=\d{4}-\d{2}-\d{2}&ss=[a-z]&srt=[a-z]&sp=[a-z]+&se=\d{4}-\d{2}-\d{2}T[a-zA-Z0-9:]+&sig=[A-Za-z0-9%]+`)

	addP("Azure Cognitive Services Key",
		`(?i)cognitive[_\-.]?services[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Azure DevOps PAT",
		`(?i)azure[_\-.]?devops[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9]{52})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   GOOGLE CLOUD / FIREBASE
	──────────────────────────────────────────────────────────────── */

	addP("Google Cloud API Key",
		`AIza[0-9A-Za-z\-_]{35}`)

	addP("Google OAuth Access Token",
		`ya29\.[0-9A-Za-z\-_]+`)

	addP("Google OAuth Client ID",
		`[0-9]{8,12}-[0-9a-z_]{32}\.apps\.googleusercontent\.com`)

	addP("Google OAuth Client Secret",
		`(?i)google[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-]{24,})["']?`)

	addP("Google Service Account JSON",
		`"type"\s*:\s*"service_account"`)

	addP("Google Service Account Private Key",
		`"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----`)

	addP("Google Cloud Service Account Email",
		`[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com`)

	addP("Firebase/FCM Server Key",
		`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`)

	addP("Firebase Web API Key",
		`(?i)firebase[_\-.]?api[_\-.]?key\s*[=:]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?`)

	addP("Firebase App ID",
		`\d+:[a-z0-9]+:[a-z]+:[a-f0-9]{24}`)

	addP("Firebase Project ID",
		`(?i)firebase[_\-.]?project[_\-.]?id\s*[=:]\s*["']?([a-z0-9\-]+)["']?`)

	addP("Google reCAPTCHA Site Key",
		`6L[0-9A-Za-z\-_]{38}`)

	addP("Google reCAPTCHA Secret",
		`(?i)recaptcha[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-]{40})["']?`)

	addP("Google Maps API Key",
		`(?i)google[_\-.]?maps[_\-.]?api[_\-.]?key\s*[=:]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?`)

	addP("Google Cloud Storage URL",
		`storage\.googleapis\.com/[a-zA-Z0-9\-_]+`)

	addP("Google Cloud Function URL",
		`[a-z0-9\-]+\.cloudfunctions\.net/[a-zA-Z0-9\-_]+`)

	addP("Google OAuth Refresh Token",
		`1//[0-9A-Za-z\-_]{30,}`)

	addP("Google OAuth Authorization Code",
		`4/[0-9A-Za-z\-_\-]{30,}`)

	/* ────────────────────────────────────────────────────────────────
	   GITHUB / GITLAB / BITBUCKET
	──────────────────────────────────────────────────────────────── */

	addP("GitHub Personal Access Token (ghp_)",
		`ghp_[A-Za-z0-9]{36}`)

	addP("GitHub OAuth Token (gho_)",
		`gho_[A-Za-z0-9]{36}`)

	addP("GitHub App Token (ghu_)",
		`ghu_[A-Za-z0-9]{36}`)

	addP("GitHub App Server Token (ghs_)",
		`ghs_[A-Za-z0-9]{36}`)

	addP("GitHub Refresh Token (ghr_)",
		`ghr_[A-Za-z0-9]{76}`)

	addP("GitHub Fine-grained PAT",
		`github_pat_[A-Za-z0-9_]{82}`)

	addP("GitHub URL with Credentials",
		`https://[A-Za-z0-9_.\-]+:[A-Za-z0-9_\-]+@github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+`)

	addP("GitHub OAuth App Secret",
		`(?i)github[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{40})["']?`)

	addP("GitHub Webhook Secret",
		`(?i)github[_\-.]?webhook[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("GitHub Deploy Key",
		`(?i)github[_\-.]?deploy[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("GitLab Personal Access Token",
		`glpat-[A-Za-z0-9\-_]{20}`)

	addP("GitLab Runner Registration Token",
		`GR1348941[A-Za-z0-9\-_]{20}`)

	addP("GitLab OAuth Token",
		`(?i)gitlab[_\-.]?oauth[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9\-_]{20,})["']?`)

	addP("Bitbucket App Password",
		`(?i)bitbucket[_\-.]?app[_\-.]?password\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Bitbucket OAuth Secret",
		`(?i)bitbucket[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{32,})["']?`)

	addP("Bitbucket OAuth Key",
		`(?i)bitbucket[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{18,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   SLACK / TELEGRAM / DISCORD / TEAMS
	──────────────────────────────────────────────────────────────── */

	addP("Slack Bot Token (xoxb)",
		`xoxb-[0-9A-Za-z\-]{51}`)

	addP("Slack User Token (xoxp)",
		`xoxp-[0-9A-Za-z\-]{72}`)

	addP("Slack App Token (xoxa)",
		`xoxa-[0-9A-Za-z\-]{10,60}`)

	addP("Slack Legacy Token (xoxs)",
		`xoxs-[0-9A-Za-z\-]{10,60}`)

	addP("Slack Refresh Token (xoxr)",
		`xoxr-[0-9A-Za-z\-]{10,60}`)

	addP("Slack Generic OAuth Token",
		`xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`)

	addP("Slack Webhook URL",
		`https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{20,}`)

	addP("Slack Signing Secret",
		`(?i)slack[_\-.]?signing[_\-.]?secret\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Slack Verification Token",
		`(?i)slack[_\-.]?verification[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Telegram Bot Token",
		`\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}`)

	addP("Telegram Bot API URL",
		`https://api\.telegram\.org/bot[0-9]{8,10}:[A-Za-z0-9_\-]{35}`)

	addP("Discord Bot Token",
		`\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`)

	addP("Discord Webhook URL",
		`https://discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_\-]{60,}`)

	addP("Discord Client Secret",
		`(?i)discord[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-]{30,})["']?`)

	addP("Microsoft Teams Webhook",
		`https://[a-z0-9]+\.webhook\.office\.com/[^"'\s]{40,}`)

	/* ────────────────────────────────────────────────────────────────
	   TWILIO
	──────────────────────────────────────────────────────────────── */

	addP("Twilio Account SID (AC)",
		`\bAC[a-f0-9]{32}\b`)

	addP("Twilio API Key SID (SK)",
		`\bSK[a-f0-9]{32}\b`)

	addP("Twilio App SID (AP)",
		`\bAP[a-f0-9]{32}\b`)

	addP("Twilio Auth Token",
		`(?i)twilio[_\-.]?auth[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Twilio API Secret",
		`(?i)twilio[_\-.]?api[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{32})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   PAYMENTS — STRIPE / PAYPAL / SQUARE / RAZORPAY
	──────────────────────────────────────────────────────────────── */

	addP("Stripe Live Secret Key (sk_live)",
		`sk_live_[0-9a-zA-Z]{24,}`)

	addP("Stripe Live Restricted Key (rk_live)",
		`rk_live_[0-9a-zA-Z]{24,}`)

	addP("Stripe Test Secret Key (sk_test)",
		`sk_test_[0-9a-zA-Z]{24,}`)

	addP("Stripe Live Publishable Key (pk_live)",
		`pk_live_[0-9a-zA-Z]{24,}`)

	addP("Stripe Test Publishable Key (pk_test)",
		`pk_test_[0-9a-zA-Z]{24,}`)

	addP("Stripe Webhook Signing Secret",
		`whsec_[A-Za-z0-9]{24,}`)

	addP("PayPal Braintree Access Token",
		`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)

	addP("PayPal Client Secret",
		`(?i)paypal[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-]{60,})["']?`)

	addP("PayPal Identity Token",
		`(?i)paypal[_\-.]?identity[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-]{30,})["']?`)

	addP("Square OAuth Token (EAAA)",
		`EAAA[A-Za-z0-9]{60}`)

	addP("Square Access Token (sq0atp)",
		`sq0atp-[0-9A-Za-z\-_]{22}`)

	addP("Square OAuth Secret (sq0csp)",
		`sq0csp-[0-9A-Za-z\-_]{43}`)

	addP("Razorpay Key ID",
		`rzp_(?:live|test)_[A-Za-z0-9]{14}`)

	addP("Razorpay Secret",
		`(?i)razorpay[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   EMAIL & MARKETING
	──────────────────────────────────────────────────────────────── */

	addP("SendGrid API Key",
		`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`)

	addP("Mailgun API Key",
		`key-[0-9a-zA-Z]{32}`)

	addP("Mailgun Private Key",
		`(?i)mailgun[_\-.]?priv[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Mailchimp API Key",
		`\b[0-9a-f]{32}-us[0-9]{1,2}\b`)

	addP("Mandrill API Key",
		`(?i)mandrill[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9\-_]{22})["']?`)

	addP("Postmark API Token",
		`(?i)postmark[_\-.]?token\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Amazon SES SMTP Password",
		`(?i)ses[_\-.]?smtp[_\-.]?password\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`)

	addP("SMTP Credentials in URL",
		`smtp://[A-Za-z0-9._%~\-]+:[^\s/@:]{1,64}@`)

	addP("Email with Password in Config",
		`(?i)email[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   AI / ML SERVICES
	──────────────────────────────────────────────────────────────── */

	addP("OpenAI API Key (T3BlbkFJ format)",
		`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`)

	addP("OpenAI Project Key",
		`sk-proj-[A-Za-z0-9_\-]{40,}`)

	addP("OpenAI Legacy Key",
		`sk-[A-Za-z0-9]{48}`)

	addP("OpenAI Org ID",
		`org-[A-Za-z0-9]{24,}`)

	addP("Anthropic Claude API Key",
		`sk-ant-[A-Za-z0-9_\-]{24,}`)

	addP("HuggingFace Token",
		`hf_[A-Za-z0-9]{34}`)

	addP("Groq API Key",
		`gsk_[A-Za-z0-9]{52}`)

	addP("Replicate API Key",
		`r8_[A-Za-z0-9]{37}`)

	addP("Perplexity API Key",
		`pplx-[A-Za-z0-9]{48}`)

	addP("Mistral API Key",
		`(?i)mistral[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{32})["']?`)

	addP("Cohere API Key",
		`(?i)cohere[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{40})["']?`)

	addP("Stability AI Key",
		`sk-[A-Za-z0-9]{50}`)

	addP("Together AI Key",
		`(?i)together[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{64})["']?`)

	addP("Deepseek API Key",
		`sk-[a-f0-9]{32}`)

	/* ────────────────────────────────────────────────────────────────
	   AUTH — JWT / OAUTH / KEYS
	──────────────────────────────────────────────────────────────── */

	addP("JWT Token (3 segments)",
		`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)

	addP("JWT Token (2 segments, unsigned)",
		`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\s*$`)

	addP("JWT Token (loose, any structure)",
		`ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*`)

	addP("Basic Auth Header",
		`(?i)basic\s+[a-zA-Z0-9=:_+/\-]{8,100}`)

	addP("Bearer Token",
		`(?i)bearer\s+[A-Za-z0-9\-._~+/]{16,}`)

	addP("Private Key Header (BEGIN)",
		`-----BEGIN ((?:RSA|EC|DSA|PGP|OPENSSH|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----`)

	addP("Private Key Full Block",
		`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{100,}?-----END [A-Z ]*PRIVATE KEY-----`)

	addP("SSH Public Key (RSA)",
		`ssh-rsa\s*AAAAB3NzaC1yc2E[A-Za-z0-9+/=]{100,}`)

	addP("SSH Public Key (Ed25519)",
		`ssh-ed25519\s*AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/=]{40,}`)

	addP("PGP Private Key Block",
		`-----BEGIN PGP PRIVATE KEY BLOCK-----`)

	addP("Credentials in URL (user:pass@host)",
		`(?:ftp|ftps|https?)://[A-Za-z0-9._%~\-]+:[^\s/@:]{1,64}@[A-Za-z0-9.\-]+`)

	addP("Credentials in Generic URL Scheme",
		`(?:ftp|ftps|http|https)://[A-Za-z0-9\-_:.~]+@`)

	addP("Database Connection with Credentials",
		`(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|smtp|mssql)://[^\s:@/]+:[^\s@/]{1,64}@`)

	addP("LDAP Connection with Credentials",
		`ldaps?://[A-Za-z0-9._%~\-]+:[^\s/@:]{1,64}@`)

	addP("OAuth Client Secret",
		`(?i)client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{20,})["']?`)

	addP("API Key Assignment",
		`(?i)api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?`)

	addP("Access Token Assignment",
		`(?i)access[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?`)

	addP("Auth Token Assignment",
		`(?i)auth[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?`)

	addP("Secret Key Assignment",
		`(?i)secret[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{16,})["']?`)

	addP("Refresh Token Assignment",
		`(?i)refresh[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-./+=]{10,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   SOCIAL MEDIA
	──────────────────────────────────────────────────────────────── */

	addP("Facebook Access Token",
		`EAACEdEose0cBA[A-Za-z0-9]+`)

	addP("Facebook App Secret",
		`(?i)facebook[_\-.]?app[_\-.]?secret\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Facebook Access Token in Config",
		`(?i)facebook[_\-.]?access[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9]{50,})["']?`)

	addP("Twitter Consumer Key",
		`(?i)twitter[_\-.]?consumer[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Twitter Consumer Secret",
		`(?i)twitter[_\-.]?consumer[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{45,})["']?`)

	addP("Twitter Access Token",
		`[tT]witter.{0,30}[1-9][0-9]+-[0-9a-zA-Z]{40}`)

	addP("LinkedIn Client Secret",
		`(?i)linkedin[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{16,})["']?`)

	addP("Instagram API Token",
		`IGQ[A-Za-z0-9_\-]{30,}`)

	addP("Pinterest API Key",
		`(?i)pinterest[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   DEVOPS & INFRASTRUCTURE
	──────────────────────────────────────────────────────────────── */

	addP("Heroku API Key",
		`(?i)heroku.{0,40}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	addP("DigitalOcean API Token",
		`dop_v1_[a-f0-9]{64}`)

	addP("DigitalOcean OAuth Token",
		`doo_v1_[a-f0-9]{64}`)

	addP("Shopify Access Token (shpat_)",
		`shpat_[a-fA-F0-9]{32}`)

	addP("Shopify Custom App Token (shpca_)",
		`shpca_[a-fA-F0-9]{32}`)

	addP("Shopify Private App Token (shppa_)",
		`shppa_[a-fA-F0-9]{32}`)

	addP("Shopify Shared Secret (shpss_)",
		`shpss_[a-fA-F0-9]{32}`)

	addP("NPM Access Token",
		`npm_[A-Za-z0-9]{36}`)

	addP("PyPI Upload Token",
		`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`)

	addP("Postman API Key",
		`PMAK-[a-f0-9]{24}-[a-f0-9]{34}`)

	addP("Notion API Token",
		`secret_[A-Za-z0-9]{43}`)

	addP("HashiCorp Vault Token (hvs.)",
		`\bhvs\.[A-Za-z0-9]{20,}`)

	addP("HashiCorp Vault Token (s.)",
		`\bs\.[A-Za-z0-9]{20,}`)

	addP("Mapbox Access Token",
		`pk\.eyJ1[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{30,}`)

	addP("Sentry DSN",
		`https://[a-f0-9]{32}@[a-z0-9.\-]+\.sentry\.(?:io|sentry\.app)/\d+`)

	addP("Sentry Auth Token",
		`(?i)sentry[_\-.]?auth[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{64})["']?`)

	addP("Zapier Webhook",
		`https://hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+/`)

	addP("Netlify Access Token",
		`(?i)netlify[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-]{40,})["']?`)

	addP("Vercel API Token",
		`(?i)vercel[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9]{24})["']?`)

	addP("CircleCI Token",
		`(?i)circle[_\-.]?ci[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{40})["']?`)

	addP("Travis CI Token",
		`(?i)travis[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`)

	addP("Jenkins Secret",
		`(?i)jenkins[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{32})["']?`)

	addP("Kubernetes Service Account Token",
		`eyJhbGciOiJSUzI1NiIs[A-Za-z0-9_\-./=]{100,}`)

	addP("Kubernetes Config Reference",
		`(?i)kubeconfig\s*[=:]\s*["']?([^\s"']{5,})["']?`)

	addP("Terraform Cloud Token",
		`(?i)terraform[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9\-_.]{20,})["']?`)

	addP("Ansible Vault Password",
		`(?i)ansible[_\-.]?vault[_\-.]?pass\s*[=:]\s*["']?([^\s"']{5,})["']?`)

	addP("Docker Hub Password",
		`(?i)docker[_\-.]?password\s*[=:]\s*["']?([^\s"']{8,})["']?`)

	addP("Docker Registry Token",
		`(?i)docker[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{64})["']?`)

	addP("Consul Token",
		`(?i)consul[_\-.]?token\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Chef Client Key",
		`(?i)chef[_\-.]?client[_\-.]?key\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Puppet Agent Cert",
		`(?i)puppet[_\-.]?agent[_\-.]?cert\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Airflow Connection",
		`(?i)airflow[_\-.]?conn[_\-.]?id\s*[=:]\s*["']?([^\s"']{5,})["']?`)

	addP("GitLab CI/CD Variable",
		`(?i)gitlab[_\-.]?ci[_\-.]?variable\s*[=:]\s*["']?([^\s"']{5,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   DATABASES
	──────────────────────────────────────────────────────────────── */

	addP("MySQL Connection String",
		`mysql://[A-Za-z0-9_\-]+:[^\s@]{1,64}@`)

	addP("MySQL Password",
		`(?i)mysql[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("MySQL Root Password",
		`(?i)mysql[_\-.]?root[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("PostgreSQL Connection String",
		`postgres(?:ql)?://[A-Za-z0-9_\-]+:[^\s@]{1,64}@`)

	addP("PostgreSQL Password",
		`(?i)postgres(?:ql)?[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("MongoDB Connection String",
		`mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[^\s@]{1,64}@`)

	addP("MongoDB Password",
		`(?i)mongodb[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Redis Connection String",
		`redis://[A-Za-z0-9_\-]*:[^\s@]{1,64}@`)

	addP("Redis Password",
		`(?i)redis[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Elasticsearch Password",
		`(?i)elastic(?:search)?[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("RabbitMQ Password",
		`(?i)rabbitmq[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("CouchDB Password",
		`(?i)couchdb[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Cassandra Password",
		`(?i)cassandra[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("MSSQL Password",
		`(?i)mssql[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Database URL",
		`(?i)database[_\-.]?url\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("DB Password (Generic)",
		`(?i)db[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Connection String (Generic)",
		`(?i)connection[_\-.]?string\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("JDBC Connection URL",
		`jdbc:[a-z]+://[^\s"']+`)

	/* ────────────────────────────────────────────────────────────────
	   FRAMEWORKS & APPLICATIONS
	──────────────────────────────────────────────────────────────── */

	addP("Laravel APP_KEY",
		`base64:[A-Za-z0-9+/]{43}=`)

	addP("Django SECRET_KEY",
		`(?i)django[_\-.]?secret[_\-.]?key\s*[=:]\s*["']?([^\s"']{20,})["']?`)

	addP("Rails secret_key_base",
		`(?i)secret[_\-.]?key[_\-.]?base\s*[=:]\s*["']?([a-f0-9]{80,})["']?`)

	addP("WordPress DB Password",
		`(?i)wordpress[_\-.]?db[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("WordPress Auth Key Salt",
		`(?i)AUTH[_\s]?KEY['"]?\s*,\s*['"]([^\s"']{20,})['"]`)

	addP("WordPress AUTH_SALT",
		`(?i)AUTH[_\s]?SALT['"]?\s*,\s*['"]([^\s"']{20,})['"]`)

	addP("WordPress LOGGED_IN_SALT",
		`(?i)LOGGED[_\s]?IN[_\s]?SALT['"]?\s*,\s*['"]([^\s"']{20,})['"]`)

	addP("Spring Mail Password",
		`(?i)spring[_\-.]?mail[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Keystore Password",
		`(?i)keystore[_\-.]?pass(?:word)?\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Key Store Password (camelCase)",
		`(?i)keyPassword\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Store Password (camelCase)",
		`(?i)storePassword\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Signing Password",
		`(?i)signing[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("GPG Passphrase",
		`(?i)gpg[_\-.]?pass(?:phrase|word)\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Encryption Key Reference",
		`(?i)encryption[_\-.]?key\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Session Secret",
		`(?i)session[_\-.]?secret\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Webhook Secret",
		`(?i)webhook[_\-.]?secret\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Root Password",
		`(?i)root[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Admin Password",
		`(?i)admin[_\-.]?pass(?:word)?\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Service Account Secret",
		`(?i)service[_\-.]?account[_\-.]?secret\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("App Secret (Generic)",
		`(?i)app[_\-.]?secret\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Consumer Secret (Generic)",
		`(?i)consumer[_\-.]?secret\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Salt Value",
		`(?i)(?:salt|pepper)[_\-.]?value\s*[=:]\s*["']?([^\s"']{8,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   SAAS SERVICES & PLATFORMS
	──────────────────────────────────────────────────────────────── */

	addP("Cloudinary API Secret",
		`(?i)cloudinary[_\-.]?api[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Cloudinary API Key",
		`(?i)cloudinary[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([0-9]{15,})["']?`)

	addP("Cloudinary URL",
		`cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9\-]+`)

	addP("Pusher App Secret",
		`(?i)pusher[_\-.]?app[_\-.]?secret\s*[=:]\s*["']?([a-f0-9]{20})["']?`)

	addP("Pusher App Key",
		`(?i)pusher[_\-.]?app[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{20})["']?`)

	addP("VirusTotal API Key",
		`(?i)virustotal[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{64})["']?`)

	addP("Snyk API Token",
		`(?i)snyk[_\-.]?api[_\-.]?token\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("SonarQube Token",
		`(?i)sonar[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{40})["']?`)

	addP("New Relic License Key",
		`(?i)new[_\-.]?relic[_\-.]?license[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{40})["']?`)

	addP("Datadog API Key",
		`(?i)datadog[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Datadog App Key",
		`(?i)datadog[_\-.]?app[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{40})["']?`)

	addP("Algolia API Key",
		`(?i)algolia[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Algolia Admin Key",
		`(?i)algolia[_\-.]?admin[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Algolia Search Key",
		`(?i)algolia[_\-.]?search[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Segment API Key",
		`(?i)segment[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{32})["']?`)

	addP("Mixpanel API Token",
		`(?i)mixpanel[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("OneSignal API Key",
		`(?i)onesignal[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9_\-]{40,})["']?`)

	addP("PagerDuty API Key",
		`(?i)pagerduty[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9+]{20,})["']?`)

	addP("OpsGenie API Key",
		`(?i)opsgenie[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Airtable API Key",
		`(?i)airtable[_\-.]?api[_\-.]?key\s*[=:]\s*["']?(key[A-Za-z0-9]{14})["']?`)

	addP("Intercom API Token",
		`(?i)intercom[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-]{60,})["']?`)

	addP("Zendesk API Token",
		`(?i)zendesk[_\-.]?api[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{40})["']?`)

	addP("Zendesk Password",
		`(?i)zendesk[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("Spotify Client Secret",
		`(?i)spotify[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9]{60,})["']?`)

	addP("SoundCloud Client Secret",
		`(?i)soundcloud[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([a-f0-9]{32})["']?`)

	addP("Wakatime API Key",
		`(?i)wakatime[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Nexus Repository Password",
		`(?i)nexus[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("OSSRH Password",
		`(?i)ossrh[_\-.]?password\s*[=:]\s*["']?([^\s"']{4,})["']?`)

	addP("NuGet API Key",
		`(?i)nuget[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{50,})["']?`)

	addP("Travis CI API Token",
		`(?i)travis[_\-.]?api[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`)

	addP("Slack OAuth Token",
		`(?i)slack[_\-.]?oauth[_\-.]?token\s*[=:]\s*["']?(xox[a-z]-[A-Za-z0-9\-]{10,})["']?`)

	addP("Firebase Cloud Messaging Key",
		`(?i)fcm[_\-.]?server[_\-.]?key\s*[=:]\s*["']?(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})["']?`)

	addP("Bintray API Key",
		`(?i)bintray[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Codecov Token",
		`(?i)codecov[_\-.]?token\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Coveralls Repo Token",
		`(?i)coveralls[_\-.]?(?:repo[_\-.]?)?token\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Codeclimate Repo Token",
		`(?i)codeclimate[_\-.]?repo[_\-.]?token\s*[=:]\s*["']?([a-f0-9]{64})["']?`)

	addP("Browserstack Access Key",
		`(?i)browser[_\-.]?stack[_\-.]?access[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9]{20,})["']?`)

	addP("Sauce Labs Access Key",
		`(?i)sauce[_\-.]?access[_\-.]?key\s*[=:]\s*["']?([a-f0-9\-]{36})["']?`)

	addP("Auth0 Client Secret",
		`(?i)auth0[_\-.]?client[_\-.]?secret\s*[=:]\s*["']?([A-Za-z0-9_\-]{40,})["']?`)

	addP("Contentful Access Token",
		`(?i)contentful[_\-.]?(?:management[_\-.]?api[_\-.]?)?access[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-.]{20,})["']?`)

	addP("Cloudflare API Key",
		`(?i)cloudflare[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{37})["']?`)

	addP("Cloudflare Auth Key",
		`(?i)cloudflare[_\-.]?auth[_\-.]?key\s*[=:]\s*["']?([a-f0-9]{37})["']?`)

	addP("Okta API Token",
		`(?i)okta[_\-.]?api[_\-.]?token\s*[=:]\s*["']?([A-Za-z0-9_\-]{40,})["']?`)

	addP("NPM Secret Key",
		`(?i)npm[_\-.]?secret[_\-.]?key\s*[=:]\s*["']?([A-Za-z0-9_\-]{30,})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   CRYPTO & BLOCKCHAIN
	──────────────────────────────────────────────────────────────── */

	addP("Ethereum Private Key",
		`(?i)(?:eth|ethereum)[_\-.]?private[_\-.]?key\s*[=:]\s*["']?(0x[a-fA-F0-9]{64})["']?`)

	addP("Bitcoin Private Key (WIF)",
		`(?:5[HJK]|K|L)[1-9A-HJ-NP-Za-km-z]{51}`)

	addP("Bitcoin Address",
		`\b(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}\b`)

	addP("Bitcoin Address (bc1)",
		`\bbc1[a-z0-9]{25,62}\b`)

	addP("Ethereum Address",
		`\b0x[a-fA-F0-9]{40}\b`)

	addP("MetaMask Seed Phrase",
		`(?i)(?:seed|mnemonic|recovery)[_\-.]?phrase\s*[=:]\s*["']?([a-z\s]{40,})["']?`)

	addP("Ropsten/Rinkeby Testnet Private Key",
		`(?i)(?:ropsten|rinkeby)[_\-.]?private[_\-.]?key\s*[=:]\s*["']?(0x[a-fA-F0-9]{64})["']?`)

	/* ────────────────────────────────────────────────────────────────
	   SENSITIVE DATA / PII
	──────────────────────────────────────────────────────────────── */

	addP("Email Address",
		`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

	addP("Credit Card Number (Visa/MC/Amex/Discover)",
		`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)

	addP("SSN (US Format)",
		`\b\d{3}-\d{2}-\d{4}\b`)

	addP("IBAN",
		`\b[A-Z]{2}\d{2}[A-Z0-9]{4}[A-Z0-9]{7}(?:[A-Z0-9]?){0,16}\b`)

	addP("Internal IP Address",
		`\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b`)

	addP("Internal Hostname",
		`(?:internal|intranet|local|staging|dev|test|qa|uat)\.[a-z0-9\-]+\.(?:com|net|org|io|dev|corp|local|internal)`)

	addP("Phone Number (US)",
		`\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)

	/* ────────────────────────────────────────────────────────────────
	   INFO DISCLOSURE / DEBUG / ERRORS
	──────────────────────────────────────────────────────────────── */

	addP("Directory Listing",
		`(?i)index of\s+/[a-z]|directory listing for\s+/`)

	addP("SQL Error Disclosure",
		`(?i)you have an error in your sql syntax|ORA-\d{5}|SQLSTATE\[\w+\]|valid MySQL result|MySqlClient\.|PostgreSQL.*ERROR|SQLite\.Exception|Warning.*mysql_`)

	addP("PHP Error Disclosure",
		`(?i)(?:fatal error|parse error|warning|notice)\s*:\s*.+ in\s+.+\.php on line \d+`)

	addP("PHP Warning",
		`(?i)warning: .+ in .+ on line \d+`)

	addP("PHP Notice",
		`(?i)notice: undefined (?:index|variable|offset): .+ in .+ on line \d+`)

	addP("Java Stack Trace",
		`java\.lang\.\w+Exception|at [\w.$]+\([\w.]+:\d+\)`)

	addP("Python Traceback",
		`Traceback \(most recent call last\):`)

	addP("ASP.NET Error",
		`Server Error in|ASP\.NET is configured|An unhandled exception was generated`)

	addP("Node.js Error",
		`(?i)(?:error|ERR!):\s+.*at\s+.+\(?.+:\d+:\d+\)?`)

	addP("Ruby Error",
		`(?i).+\.rb:\d+:in\s+`)

	addP("Debug Mode Active",
		`(?i)(?:APP_ENV|APP_DEBUG|NODE_ENV|RAILS_ENV|DJANGO_DEBUG|FLASK_ENV)\s*[=:]\s*["']?(?:true|dev|development|debug|local)["']?`)

	addP("phpinfo Exposed",
		`phpinfo\(\)`)

	addP("Git Repository Exposed",
		`\.git/(?:HEAD|config|index)\b`)

	addP("SVN Repository Exposed",
		`\.svn/(?:entries|wc\.db|all-wcprops)\b`)

	addP("Env File Exposed",
		`(?i)(?:APP_KEY|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|SECRET_KEY)\s*=\s*[^\s\n]+`)

	addP("Backup File Reference",
		`(?i)(?:backup|dump|db|database)\.(?:sql|zip|tar\.gz|bak|7z)`)

	addP("Swagger/OpenAPI Exposed",
		`"swagger"\s*:\s*"2\.0"|"openapi"\s*:\s*"3\.\d`)

	addP("GraphQL Introspection Exposed",
		`"__schema"\s*:\s*\{`)

	addP("Source Code Disclosure (PHP)",
		`<\?php|<\?=`)

	addP("Server Signature",
		`(?i)(?:apache|nginx|microsoft-iis)/[\d.]+`)

	addP("Session ID in URL",
		`(?i)[?&](?:session_id|sess_id|sid|sessionid|PHPSESSID|jsessionid)=([a-f0-9]{16,})`)

	addP("API Token in URL Parameter",
		`(?i)[?&](?:api_key|apikey|access_token|token|auth|key|secret)=([A-Za-z0-9_\-]{16,})`)

	addP("Hardcoded Password",
		`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']`)

	addP("Hardcoded Secret",
		`(?i)(?:secret|api_key|api-key|token|auth)\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{16,})["']`)

	addP("Base64 Encoded Credential",
		`(?:[A-Za-z0-9+/]{40,}={0,2})`)

	addP("Certificate Fingerprint",
		`(?:sha256|sha1|md5)[\s:=]+[a-f0-9]{40,}`)

	addP("X-Powered-By Disclosure",
		`(?i)x-powered-by:\s*\S+`)

	addP("Admin Panel Reference",
		`(?i)(?:admin|administrator|dashboard|panel|cpanel|wp-admin)[-_]?(?:login|panel|area|page)`)

	addP("Internal API Key",
		`(?i)internal[_\-.]?api[_\-.]?key\s*[=:]\s*["']?([^\s"']{10,})["']?`)

	addP("Elasticsearch URL",
		`(?:elasticsearch|elastic)\.[a-z0-9\-]+\.(?:com|io|net|aws\.amazon\.com)`)

	addP("Kafka Connection",
		`(?i)(?:kafka|zookeeper)[_\-.]?(?:broker|server|host)\s*[=:]\s*["']?([^\s"']{5,})["']?`)

	addP("Docker Registry URL",
		`(?:docker|registry)\.[a-z0-9\-]+\.(?:com|io|net)[/\w]*`)

	addP("Google Cloud Storage Bucket",
		`storage\.googleapis\.com/[a-zA-Z0-9\-_]+`)

	addP("AWS Secrets Manager ARN",
		`arn:aws:secretsmanager:[a-z0-9\-]+:\d{12}:secret:[a-zA-Z0-9/_+=.\-]+`)

	addP("Configuration File Content",
		`(?i)(?:\.env|config\.(?:json|yml|yaml|php|ini|toml))\s*(?:contents?|source|exposed|leaked)`)

	addP("Windows Integrated Security",
		`(?i)integrated\s*security\s*=\s*(?:sspi|true)`)

	addP("Kafka Admin URL",
		`(?i)kafka[_\-.]?admin[_\-.]?url\s*[=:]\s*["']?([^\s"']{5,})["']?`)

	addP("Vault Secret Path",
		`(?:secret|kv)/[\w\-]+/[\w\-]+`)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KEYWORD PATTERNS — ALL from credentials-disclosure-all.yaml
//  Auto-generated mega-regex grouped by first letter
// ═══════════════════════════════════════════════════════════════════════════════

func buildKeywordPatterns() {
	// special regex-shaped keywords (numbered variants, etc.)
	specials := []string{
		`secret[_\-]?\d*`,
		`widget[_\-]?fb[_\-]?password[_\-]?\d*`,
		`widget[_\-]?basic[_\-]?password[_\-]?\d*`,
		`postgres(?:ql)?[_\-]?pass(?:word)?`,
		`strip[e]?[_\-]?secret[_\-]?key`,
		`strip[e]?[_\-]?publishable[_\-]?key`,
	}

	// plain keywords from YAML — "_" auto-converts to [_-]?
	blob := "" +
		/* heroku */ "heroku_api_key heroku_token heroku_oauth_secret heroku_oauth_token heroku_secret_token heroku_key heroku_email " +
		/* mail core */ "mail_host mail_username mail_port mail_encryption mail_password mail_driver mail_from_address mail_from_name mailer_password email_host_password " +
		/* spring mail */ "spring_mail_password spring_mail_username spring_mail_host " +
		/* mailchimp */ "mailchimp_api_key mailchimp_key mailchimp_secret " +
		/* mailgun */ "mailgun_api_key mailgun_secret_api_key mailgun_pub_key mailgun_pub_apikey mailgun_priv_key mailgun_password mailgun_key mailgun_secret mailgun_apikey mailgun_domain mailgun_smtp_password " +
		/* mandrill */ "mandrill_api_key mandrill_key mandrill_secret mandrill_username " +
		/* sendgrid */ "sendgrid_username sendgrid_user sendgrid_password sendgrid_key sendgrid_api_key sendgrid_token sendgrid_smtp_password sendgrid " +
		/* google */ "google_oauth_secret google_secret google_server_key google_private_key google_maps_api_key google_client_secret google_client_id google_client_email google_account_type google_api_key google_api_secret google_app_id gsecr " +
		/* gpg */ "gpg_secret_keys gpg_private_key gpg_passphrase gpg_ownertrust gpg_keyname gpg_key_name gpg_pass gpg_recipient " +
		/* htaccess */ "htaccess_pass htaccess_user " +
		/* incident */ "incident_bot_name incident_channel_name " +
		/* jwt */ "jwt_passphrase jwt_password jwt_public_key jwt_secret jwt_secret_key jwt_secret_token jwt_token jwt_user jwt_pass jwt_key jwt_signing_key " +
		/* keystore */ "key_password keypassword keystore_pass keystore_password store_password storepassword storepass key_store_password " +
		/* signing */ "signing_key_sid signing_key_secret signing_key_password signing_key signing_password signing_keystore_password android_signing_password private_signing_password " +
		/* maps/pusher */ "maps_api_key mix_pusher_app_cluster mix_pusher_app_key pusher_app_cluster pusher_app_id pusher_app_key pusher_app_secret pushover_token pushover_user_key " +
		/* mysql */ "mysql_password mysql_root_password mysql_username mysql_user mysql_hostname mysql_database mysqlsecret mysqlmasteruser mysql_host mysql_port mysql_db " +
		/* oauth */ "oauth_discord_id oauth_discord_secret oauth_key oauth_token oauth2_secret oauth_secret oauth_client_secret oauth_client_id oauth_consumer_key oauth_consumer_secret " +
		/* paypal */ "paypal_identity_token paypal_sandbox paypal_secret paypal_token paypal_client_secret paypal_api_username paypal_api_password paypal_api_signature " +
		/* misc a */ "playbooks_url private_key private_signing_password queue_driver root_password sa_password send_keys preferred_username prebuild_auth plugin_password pring_mail_username " +
		/* prod */ "prod_secret_key prod_password prod_access_key_id production_secret production_password production_key project_config publish_secret publish_key publish_access " +
		/* parse */ "parse_js_key parse_rest_api_key passwordtravis pagerduty_apikey pagerduty_token pagerduty_service_key packagecloud_token plotly_apikey plotly_api_key " +
		/* places */ "places_apikey places_api_key pg_host pg_database pg_password pg_user pg_port " +
		/* percy */ "percy_token percy_project personal_secret personal_key pypi_passowrd pypi_password pypi_token postman_token " +
		/* postgres */ "postgres_password postgresql_pass postgresql_db postgresql_password postgres_env_postgres_password postgres_env_postgres_db postgres_user postgres_host " +
		/* redis */ "redis_host redis_password redis_port rediscloud_url redis_stunnel_urls response_auth_jwt_secret response_data_secret " +
		/* sentry */ "sentry_dsn sentry_key sentry_secret sentry_endpoint sentry_default_org sentry_auth_token sentry_project " +
		/* session */ "session_driver session_lifetime session_secret session_token session_key session_cookie_secret " +
		/* sf/sendwithus */ "sf_username sendwithus_key ses_secret_key ses_access_key ses_smtp_password " +
		/* service */ "service_account_secret service_account_key setsecretkey setdstsecretkey setdstaccesskey " +
		/* scrutinizer */ "scrutinizer_token sdr_token sauce_access_key sauce_username " +
		/* slack */ "slack_channel slack_incoming_webhook slack_key slack_outgoing_token slack_secret slack_signing_secret slack_token slack_url slack_webhook slack_webhook_url slack_bot_token slack_app_token " +
		/* square */ "square_access_token square_apikey square_app square_app_id square_appid square_secret square_token square_reader_sdk_repository_password square_location_id squaresecret squaretoken " +
		/* ssh */ "ssh2_auth_password sshkey sshpass ssmtp_config svn_pass svn_password " +
		/* surge */ "surge_token surge_login " +
		/* stormpath */ "stormpath_api_key_secret stormpath_api_key_id " +
		/* strip/stripe */ "strip_key strip_secret strip_secret_token strip_token strip_secret_key strip_publishable_key stripe_key stripe_secret stripe_secret_token stripe_token stripe_public stripe_private stripe_publishable_key stripe_secret_key stripe_publishable stripe_pk_key stripe_sk_key stripsecret striptoken " +
		/* token misc */ "token_twilio token_core_java token_secret token_key trusted_hosts twi_auth twi_sid " +
		/* twilio */ "twilio_account_id twilio_account_secret twilio_account_sid twilio_accountsid twilio_api twilio_api_auth twilio_api_key twilio_api_secret twilio_api_token twilio_auth twilio_auth_token twilio_secret twilio_secret_token twilio_sid twilio_token twilioapiauth twilioapisecret twilioapisid twilioapitoken twilioauthtoken twiliosecret twiliotoken twilio_configuration_sid twilio_chat_account_api_service twilio_from_number twilio_account_phone_number twilioauthkey twilioauthsid twiliokey twiliosid " +
		/* twitter */ "twitter_api_secret twitter_consumer_key twitter_consumer_secret twitter_key twitter_secret twitter_token twitteroauthaccesstoken twitteroauthaccesssecret twitter_access_token twitter_access_secret twitter_api_key twitterkey twittersecret " +
		/* wordpress */ "wordpress_password wordpress_db_user wordpress_db_password wordpress_db_host wordpress_db_name wporg_password wpjm_phpunit_google_geocode_api_key wordpress_auth_key wordpress_logged_in_salt " +
		/* z */ "zen_key zen_tkn zen_token zendesk_api_token zendesk_key zendesk_token zendesk_url zendesk_username zendesk_password zendesk_travis_github zensonatypepassword zhuliang_gh_token zopim_account_key " +
		/* access */ "access_key access_token accesskey access_key_id access_secret access_token_secret account_sid accountsid account_id admin_pass admin_user admin_password admin_email admin_username accesskeyid accesstoken " +
		/* api */ "api_key api_secret apikey api_token api_key_id api_secret_key app_key app_secret app_url app_id app_token application_id application_secret authsecret auth_token auth_secret auth_key auth_password authorization_token api_key_sid api_key_secret " +
		/* aws */ "aws_secret_token aws_access aws_access_key_id aws_bucket aws_config aws_default_region aws_key aws_secret aws_secret_access_key aws_secret_key aws_token aws_session_token aws_region aws_s3_bucket aws_lambda_function awssecretkey awsaccesskeyid aws_secrets aws_config_secretaccesskey aws_config_accesskeyid aws_ses_secret_access_key aws_ses_access_key_id amazon_secret_access_key amazon_bucket_name " +
		/* b-c */ "bucket_password client_secret cloudinary_api_key cloudinary_api_secret cloudinary_name cloudinary_url connectionstring connection_string consumer_secret consumer_key consumerkey " +
		/* database */ "database_dialect database_host database_logging database_password database_schema database_schema_test database_url database_username database_port database_name db_database db_dialect db_host db_password db_port db_server db_username db_name db_pass db_user dbpasswd dbpassword dbuser db_pw db_connection " +
		/* django */ "django_password django_secret_key django_debug " +
		/* digitalocean */ "digitalocean_token digitalocean_access_token digitalocean_secret_key digitalocean_ssh_key_ids digitalocean_ssh_key_body " +
		/* docker */ "docker_password docker_token docker_username docker_hub_token docker_pass docker_passwd dockerhubpassword dockerhub_password docker_postgres_url docker_key " +
		/* elastic */ "elastic_host elastic_port elastic_prefix elasticsearch_password elasticsearch_secret elasticsearch_url elasticsearch_username elastic_cloud_auth " +
		/* encrypt */ "encrypt_key encryption_key encryption_secret encryption_password decrypt_key decryption_key " +
		/* facebook */ "facebook_app_secret facebook_secret facebook_client_secret facebook_access_token facebook_app_id fb_app_secret fb_id fb_secret fb_token fb_app_id " +
		/* firebase */ "firebase_token firebase_api_key firebase_secret firebase_project_id firebase_database_url firebase_messaging_sender_id firebase_app_id firebase_key firebase_api_token firebase_api_json firebase_project_develop " +
		/* fcm */ "fcm_server_key fcm_api_key " +
		/* gatsby */ "gatsby_wordpress_base_url gatsby_wordpress_client_id gatsby_wordpress_client_secret gatsby_wordpress_password gatsby_wordpress_protocol gatsby_wordpress_user " +
		/* github */ "github_id github_secret github_token github_tokens github_repo github_release_token github_pwd github_password github_oauth_token github_oauth github_key github_hunter_username github_hunter_token github_deployment_token github_deploy_hb_doc_pass github_client_secret github_auth_token github_auth github_api_token github_api_key github_access_token github_client_id github_email github_username github_user github_webhook_secret github_deploy_key github_npm_token ghb_token ghost_api_key " +
		/* gitlab */ "gitlab_user_email gitlab_token gitlab_secret gitlab_client_id gitlab_client_secret " +
		/* git */ "git_token git_name git_email git_committer_name git_committer_email git_password git_user git_username git_author_name git_author_email " +
		/* gh next */ "gh_token gh_oauth_token gh_oauth_client_secret gh_repo_token gh_email gh_api_key gh_next_oauth_client_secret gh_next_unstable_oauth_client_secret gh_next_unstable_oauth_client_id gh_unstable_oauth_client_secret " +
		/* gogs */ "gogs_password gogs_token " +
		/* gradle */ "gradle_signing_password gradle_signing_key_id gradle_publish_secret gradle_publish_key gradle_release_key gradle_release_password " +
		/* gren */ "gren_github_token grgit_user " +
		/* hab */ "hab_key hab_auth_token " +
		/* hb */ "hb_codesign_key_pass hb_codesign_gpg_pass " +
		/* homebrew */ "homebrew_github_api_token " +
		/* hockey */ "hockeyapp_token " +
		/* hub */ "hub_dxia2_password hub_upload_password " +
		/* internal */ "ij_repo_username ij_repo_password index_name internal_secrets internal_api_key integration_test_appid integration_test_api_key ios_docs_deploy_token itest_gh_token " +
		/* jdbc */ "jdbc_mysql jdbc_host jdbc_databaseurl jdbc_password jdbc_user jdbc_url jdbc_connection_string " +
		/* kafka */ "kafka_rest_url kafka_instance_name kafka_admin_url kafka_password kafka_username kafka_broker " +
		/* k8s */ "kovan_private_key kubeconfig kubecfg_s3_path kubernetes_token k8s_secret " +
		/* misc k */ "kxoltsn3vogdop92m " +
		/* leanplum */ "leanplum_key " +
		/* lektor */ "lektor_deploy_username lektor_deploy_password " +
		/* lighthouse */ "lighthouse_api_key " +
		/* linkedin */ "linkedin_client_secret linkedin_client_id " +
		/* linux */ "linux_signing_key " +
		/* ll */ "ll_shared_key ll_publish_url " +
		/* looker */ "looker_test_runner_client_secret " +
		/* lottie */ "lottie_upload_cert_key_store_password lottie_upload_cert_key_password lottie_s3_secret_key lottie_s3_api_key lottie_happo_secret_key lottie_happo_api_key " +
		/* magento */ "magento_password magento_auth_username magento_auth_password " +
		/* manage */ "manage_secret manage_key management_token managementapiaccesstoken " +
		/* manifest */ "manifest_app_url manifest_app_token " +
		/* mapbox */ "mapboxaccesstoken mapbox_aws_secret_access_key mapbox_aws_access_key_id mapbox_api_token mapbox_access_token " +
		/* mg */ "mg_public_api_key mg_api_key " +
		/* mh */ "mh_password mh_apikey " +
		/* mile */ "mile_zero_key " +
		/* minio */ "minio_secret_key minio_access_key " +
		/* mistral */ "mistral_api_key " +
		/* multi */ "multi_workspace_sid multi_workflow_sid multi_disconnect_sid multi_connect_sid multi_bob_sid " +
		/* my */ "my_secret_env " +
		/* native */ "nativeevents " +
		/* netlify */ "netlify_api_key netlify_token " +
		/* nexus */ "nexuspassword nexus_password " +
		/* newrelic */ "new_relic_beta_token new_relic_license_key new_relic_api_key " +
		/* ngrok */ "ngrok_token ngrok_auth_token " +
		/* node */ "node_pre_gyp_secretaccesskey node_pre_gyp_github_token node_pre_gyp_accesskeyid node_env " +
		/* npm */ "npm_token npm_secret_key npm_password npm_email npm_auth_token npm_api_token npm_api_key " +
		/* numbers */ "numbers_service_pass " +
		/* nuget */ "nuget_key nuget_apikey nuget_api_key " +
		/* now */ "now_token non_token " +
		/* object */ "object_store_creds object_store_bucket object_storage_region_name object_storage_password " +
		/* oc */ "oc_pass " +
		/* octest */ "octest_password octest_app_username octest_app_password " +
		/* ofta */ "ofta_secret ofta_region ofta_key " +
		/* okta */ "okta_oauth2_clientsecret okta_oauth2_client_secret okta_client_token okta_api_token " +
		/* omise */ "omise_skey omise_pubkey omise_pkey omise_key omise_secret " +
		/* onesignal */ "onesignal_user_auth_key onesignal_api_key " +
		/* openwhisk */ "openwhisk_key open_whisk_key " +
		/* ossrh */ "org_project_gradle_sonatype_nexus_password org_gradle_project_sonatype_nexus_password os_password os_auth_url ossrh_username ossrh_secret ossrh_password ossrh_pass ossrh_jira_password " +
		/* misc q-r */ "quip_token qiita_token rabbitmq_password rabbitmq_user randrmusicapiaccesstoken razorpay_secret razorpay_key_id razorpay_key refresh_token registry_secure registry_pass registry_password release_token release_gh_token repotoken repo_token reporting_webdav_url reporting_webdav_pwd rest_api_key route53_access_key_id route53_secret_access_key rtd_store_pass rtd_key_pass rubygems_auth_token ropsten_private_key rinkeby_private_key " +
		/* s3 */ "s3_user_secret s3_secret_key s3_secret_assets s3_secret_app_logs s3_key_assets s3_key_app_logs s3_key s3_external_3_amazonaws_com s3_bucket_name_assets s3_bucket_name_app_logs s3_access_key_id s3_access_key s3_bucket s3_secret s3_bucket_name " +
		/* sacloud */ "sacloud_api sacloud_access_token_secret sacloud_access_token " +
		/* salesforce */ "salesforce_bulk_test_security_token salesforce_bulk_test_password salesforce_password salesforce_token salesforce_client_id salesforce_client_secret " +
		/* salt */ "salt_value " +
		/* sandbox */ "sandbox_aws_secret_access_key sandbox_aws_access_key_id sandbox_access_token sandbox_secret sandbox_password sandbox_token " +
		/* segment */ "secretkey secretaccesskey secret_key_base secret_question secret_token segment_api_key segment_token " +
		/* selion */ "selion_selenium_host selion_log_level_dev " +
		/* se misc */ "slash_developer_space_key slash_developer_space slate_user_email snyk_token snyk_api_token snoowrap_refresh_token snoowrap_password snoowrap_client_secret " +
		/* sonar */ "sonar_token sonar_project_key sonar_organization_key sonar_login dsonar_projectkey dsonar_login " +
		/* sonatype */ "sonatypepassword sonatype_token_user sonatype_token_password sonatype_password sonatype_pass sonatype_nexus_password sonatype_gpg_passphrase sonatype_gpg_key_name " +
		/* socrata */ "socrata_password socrata_app_token " +
		/* soundcloud */ "soundcloud_password soundcloud_client_secret " +
		/* spaces */ "spaces_secret_access_key spaces_access_key_id spaces_key spaces_secret " +
		/* spotify */ "spotify_api_client_secret spotify_api_access_token spotify_client_secret " +
		/* sqs */ "sqssecretkey sqsaccesskey " +
		/* srcclr */ "srcclr_api_token " +
		/* starship */ "starship_auth_token starship_account_sid " +
		/* star test */ "star_test_secret_access_key star_test_location star_test_bucket star_test_aws_access_key_id " +
		/* staging */ "staging_base_url_runscope " +
		/* telegram */ "telegram_bot_token telegram_token " +
		/* thera */ "thera_oss_access_key " +
		/* tester */ "tester_keys_password test_test test_github_token tesco_api_key " +
		/* trex */ "trex_okta_client_token trex_client_token " +
		/* travis */ "travis_token travis_secure_env_vars travis_pull_request travis_gh_token travis_e2e_token travis_com_token travis_branch travis_api_token travis_access_token " +
		/* unity */ "unity_serial unity_password " +
		/* urban */ "urban_secret urban_master_secret urban_key " +
		/* user */ "use_ssh usertravis user_assets_secret_access_key user_assets_access_key_id us_east_1_elb_amazonaws_com " +
		/* v misc */ "v_sfdc_password v_sfdc_client_secret vercel_token virustotal_apikey virustotal_api_key visual_recognition_api_key " +
		/* vip */ "vip_github_deploy_key_pass vip_github_deploy_key vip_github_build_repo_deploy_key " +
		/* vsc */ "vscetoken " +
		/* w misc */ "wakatime_api_key watson_password watson_device_password watson_conversation_password webhook_secret webhook_token widget_test_server wincert_password www_googleapis_com " +
		/* yangshun */ "yangshun_gh_token yangshun_gh_password " +
		/* yt */ "yt_server_api_key yt_partner_refresh_token yt_partner_client_secret yt_client_secret yt_api_key yt_account_refresh_token yt_account_client_secret " +
		/* ftp */ "ftp_username ftp_user ftp_pw ftp_password ftp_login ftp_host " +
		/* fossa/flickr/flask */ "fossa_api_key flickr_api_secret flickr_api_key flask_secret_key firefox_secret " +
		/* file/exp/eureka/env */ "file_password exp_password eureka_awssecretkey env_sonatype_password env_secret_access_key env_secret env_key env_heroku_api_key env_github_oauth_token " +
		/* end user */ "end_user_password " +
		/* gcs/gcr/gcloud */ "gcs_bucket gcr_password gcloud_service_key gcloud_project gcloud_bucket " +
		/* danger/cypress/coverity/coveralls */ "danger_github_api_token cypress_record_key coverity_scan_token coveralls_token coveralls_repo_token coveralls_api_token " +
		/* cos/conversation/contentful */ "cos_secrets conversation_username conversation_password contentful_v2_access_token contentful_test_org_cma_token contentful_php_management_test_token contentful_management_api_access_token_new contentful_management_api_access_token contentful_integration_management_token contentful_cma_test_token contentful_access_token " +
		/* conekta/coding/codecov/codeclimate/codacy */ "conekta_apikey coding_token codecov_token codeclimate_repo_token codacy_project_token " +
		/* cocoapods */ "cocoapods_trunk_token cocoapods_trunk_email " +
		/* cn/clu */ "cn_secret_access_key cn_access_key_id clu_ssh_private_key_base64 clu_repo_url " +
		/* cloudinary staging */ "cloudinary_url_staging " +
		/* cloudflare extra */ "cloudflare_email cloudflare_auth_email " +
		/* cloudant */ "cloudant_service_database cloudant_processed_database cloudant_password cloudant_parsed_database cloudant_order_database cloudant_instance cloudant_database cloudant_audited_database cloudant_archived_database " +
		/* cloud/clojars */ "cloud_api_key clojars_password " +
		/* cli/claimr */ "cli_e2e_cma_token claimr_token claimr_superuser claimr_db claimr_database " +
		/* ci */ "ci_user_token ci_server_name ci_registry_user ci_project_url ci_deploy_password " +
		/* chrome/cheverny/cf/certificate/censys */ "chrome_refresh_token chrome_client_secret cheverny_token cf_password certificate_password censys_secret " +
		/* cattle/cargo/cache */ "cattle_secret_key cattle_agent_instance_auth cattle_access_key cargo_token cache_s3_secret_key " +
		/* bx/bundlesize/built/bucketeer */ "bx_username bx_password bundlesize_github_token built_branch_deploy_key bucketeer_aws_secret_access_key bucketeer_aws_access_key_id " +
		/* brackets/bluemix/bintray/b2 */ "brackets_repo_oauth_token bluemix_username bluemix_pwd bluemix_password bluemix_pass_prod bluemix_pass bluemix_auth bluemix_api_key bintraykey bintray_token bintray_key bintray_gpg_password bintray_apikey b2_bucket b2_app_key " +
		/* awscn */ "awscn_secret_access_key awscn_access_key_id " +
		/* author/apple/appclientsecret/app extra */ "author_npm_api_key author_email_addr apple_id_password appclientsecret app_secrete app_report_token_key app_bucket_perm " +
		/* apigw/apiary */ "apigw_access_token apiary_api_key " +
		/* aos/ansible/android/anaconda */ "aos_sec aos_key ansible_vault_password android_docs_deploy_token anaconda_token " +
		/* alicloud/alias/algolia extra/adzerk */ "alicloud_secret_key alicloud_access_key alias_pass algolia_search_key_1 algolia_search_key algolia_search_api_key algolia_api_key_search algolia_api_key_mcm algolia_admin_key_mcm algolia_admin_key_2 algolia_admin_key_1 adzerk_api_key " +
		/* droplet/dropbox/doordash */ "droplet_travis_password dropbox_oauth_bearer doordash_auth_token " +
		/* generic */ "password passwd pwd passphrase credentials credential userpass secret token key " +
		/* env */ "env_secret env_key env_token api_secret_key auth_secret_key"

	// Build list: plain keywords → regex form, dedupe
	list := make([]string, 0, 700)
	uniq := make(map[string]bool)

	for _, k := range strings.Fields(blob) {
		// convert "_" to character class [_-]? to match both yaml "_" and "-" variants
		r := strings.ReplaceAll(k, "_", "[_-]?")
		// handle camelCase too (e.g., accessToken → optional case-insensitive)
		if !uniq[r] {
			uniq[r] = true
			list = append(list, r)
		}
	}
	for _, s := range specials {
		if !uniq[s] {
			uniq[s] = true
			list = append(list, s)
		}
	}

	// group by first letter → 1 mega regex per letter (fast + clean)
	buckets := make(map[string][]string)
	for _, k := range list {
		c := strings.ToLower(k[:1])
		buckets[c] = append(buckets[c], k)
	}

	letters := make([]string, 0, len(buckets))
	for c := range buckets {
		letters = append(letters, c)
	}
	sort.Strings(letters)

	for _, c := range letters {
		kws := buckets[c]
		// longest-first: "secret_key_base" must win over "secret"
		sort.Slice(kws, func(i, j int) bool {
			return len(kws[i]) > len(kws[j])
		})
		re := `(?i)["']?(?:` + strings.Join(kws, "|") + `)["']*\s*(?:=>|[:=])\s*["']?([^\s"'\r\n<>,;\\]{1,60})`
		comp, err := regexp.Compile(re)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] keyword bucket '%s': %v\n", c, err)
			continue
		}
		patterns = append(patterns, Pattern{
			Name:    "Credential Assignment [" + strings.ToUpper(c) + "]",
			Re:      comp,
			Keyword: true,
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EXTRA REGEX LOADER
// ═══════════════════════════════════════════════════════════════════════════════

func loadExtraPatterns(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot open extra regex file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		compiled, err := regexp.Compile(line)
		if err != nil {
			l := len(line)
			if l > 60 {
				l = 60
			}
			fmt.Fprintf(os.Stderr, "[!] skipping invalid regex: %s...\n", line[:l])
			continue
		}
		patterns = append(patterns, Pattern{
			Name:   "Custom",
			Re:     compiled,
			Custom: true,
		})
		count++
	}
	if !*silentFlag {
		nc := !*noColorFlag
		fmt.Printf("%s loaded %d custom patterns from %s\n",
			colorize(nc, C_BGRN, "[+]"), count, path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  REPORTING —  [+] URL [match]
// ═══════════════════════════════════════════════════════════════════════════════

func report(rawURL, typ, match string) {
	key := cleanMatch(match)
	if key == "" {
		return
	}

	// global dedup — same secret only printed once
	cacheKey := typ + "|" + key
	if _, dup := seen.LoadOrStore(cacheKey, struct{}{}); dup {
		atomic.AddInt64(&st.Dupes, 1)
		return
	}
	atomic.AddInt64(&st.Found, 1)

	nc := !*noColorFlag
	fmt.Printf("%s %s %s\n",
		colorize(nc, C_BGRN, "[+]"),
		rawURL,
		colorize(nc, C_BCYN, "["+key+"]"))

	if outFile != nil {
		fmt.Fprintf(outFile, "[+] %s [%s]\n", rawURL, key)
	}
	if jsonOut != nil {
		f := Finding{URL: rawURL, Type: typ, Match: key}
		b, _ := json.Marshal(f)
		fmt.Fprintln(jsonOut, string(b))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SCANNING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

func scanBody(body string, rawURL string) {
	bodyLen := int64(len(body))
	atomic.AddInt64(&st.Bytes, bodyLen)

	for i := range patterns {
		p := &patterns[i]
		matches := p.Re.FindAllStringSubmatch(body, *maxMatchFlag)

		for _, m := range matches {
			full := m[0]
			val := full

			// use capture group if available (for keyword=value patterns)
			if len(m) > 1 && m[1] != "" {
				val = m[1]
			}

			// false positive check
			if p.Keyword || p.Custom {
				if isFPKeyword(val, *entropyFlag) {
					continue
				}
			} else {
				if isFPValue(val, *entropyFlag) {
					continue
				}
			}

			report(rawURL, p.Name, full)
		}
	}
}

func fetchURL(rawURL string, client *http.Client, headers map[string]string) {
	// normalize URL
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}

	atomic.AddInt64(&st.Requests, 1)

	for attempt := 0; attempt <= *retryFlag; attempt++ {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return
		}

		// set headers
		req.Header.Set("User-Agent", *uaFlag)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Connection", "keep-alive")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt == *retryFlag {
				atomic.AddInt64(&st.Errors, 1)
			}
			continue
		}

		// read body with size limit
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(*maxBodyFlag)*1024*1024))
		resp.Body.Close()

		atomic.AddInt64(&st.URLs, 1)
		scanBody(string(body), rawURL)
		return
	}
}

func worker(jobs <-chan string, client *http.Client, headers map[string]string, wg *sync.WaitGroup) {
	defer wg.Done()
	for u := range jobs {
		fetchURL(u, client, headers)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

func printSummary() {
	if *silentFlag {
		return
	}
	nc := !*noColorFlag
	elapsed := time.Since(start).Round(time.Millisecond)

	g := colorize(nc, C_BGRN, "[+]")

	fmt.Println()
	fmt.Printf("%s Scan Complete in %s\n", g, elapsed)

	// basic stats line
	line := fmt.Sprintf("%s URLs: %d | Findings: %d | Skipped: %d",
		g,
		atomic.LoadInt64(&st.URLs),
		atomic.LoadInt64(&st.Found),
		atomic.LoadInt64(&st.Dupes))

	if e := atomic.LoadInt64(&st.Errors); e > 0 {
		line += fmt.Sprintf(" | Errors: %d", e)
	}
	fmt.Println(line)

	// detailed stats (with -stats flag)
	if *showStatsFlag {
		b := atomic.LoadInt64(&st.Bytes)
		r := atomic.LoadInt64(&st.Requests)
		fmt.Printf("%s Requests: %d | Data: %s | Patterns: %d\n",
			g, r, humanBytes(b), len(patterns))
	}
}

// humanBytes formats bytes to human readable
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════════════════

func main() {
	flag.Usage = printUsage
	flag.Parse()

	// ─── initialize patterns ───
	patterns = make([]Pattern, 0, 700)
	initStructuredPatterns()
	buildKeywordPatterns()

	if *extraFlag != "" {
		loadExtraPatterns(*extraFlag)
	}

	// ─── print banner ───
	printBanner()

	// ─── parse custom headers ───
	headers := make(map[string]string)
	if *headerFlag != "" {
		parts := strings.SplitN(*headerFlag, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// ─── HTTP client setup ───
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !*verifyTLSFlag},
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   30,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: time.Duration(*timeoutFlag) * time.Second,
	}

	// proxy support
	if *proxyFlag != "" {
		proxyURL, err := url.Parse(*proxyFlag)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			fmt.Fprintf(os.Stderr, "[!] invalid proxy URL: %v\n", err)
		}
	}

	client := &http.Client{
		Timeout:   time.Duration(*timeoutFlag) * time.Second,
		Transport: transport,
	}

	// ─── output files ───
	if *outputFlag != "" {
		f, err := os.OpenFile(*outputFlag, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			outFile = f
			defer outFile.Close()
		} else {
			fmt.Fprintf(os.Stderr, "[!] cannot open output file: %v\n", err)
		}
	}

	if *jsonFlag != "" {
		f, err := os.OpenFile(*jsonFlag, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			jsonOut = f
			defer jsonOut.Close()
		} else {
			fmt.Fprintf(os.Stderr, "[!] cannot open JSON output file: %v\n", err)
		}
	}

	// ─── signal handling (Ctrl+C → graceful summary) ───
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	start = time.Now()

	go func() {
		<-sig
		printSummary()
		os.Exit(0)
	}()

	// ─── worker pool ───
	jobs := make(chan string, 500)
	var wg sync.WaitGroup

	for i := 0; i < *threadsFlag; i++ {
		wg.Add(1)
		go worker(jobs, client, headers, &wg)
	}

	// ─── input reader ───
	sc := bufio.NewScanner(os.Stdin)
	if *listFlag != "" {
		f, err := os.Open(*listFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot open input file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	}
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	go func() {
		for sc.Scan() {
			u := strings.TrimSpace(sc.Text())
			if u != "" && !strings.HasPrefix(u, "#") {
				jobs <- u
			}
		}
		close(jobs)
	}()

	// ─── wait & summarize ───
	wg.Wait()
	printSummary()
}
