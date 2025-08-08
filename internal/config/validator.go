package config

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

var validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9*]([a-zA-Z0-9\-.*]*[a-zA-Z0-9])?$`)

// IsValidDomainName validates domain names for config files
func IsValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Allow "default" as special case
	if domain == "default" {
		return true
	}

	// Allow wildcard domains like *.example.com
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}

	// Basic domain validation
	if !validDomainRegex.MatchString(domain) {
		return false
	}

	// Additional validation using net package
	if net.ParseIP(domain) == nil && !strings.Contains(domain, ".") &&
		domain != "localhost" && domain != "default" {
		return false // Reject single-word domains except localhost/default
	}

	return true
}

// IsPathSafe checks if a path is within the expected directory
func IsPathSafe(path, baseDir string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}

	return strings.HasPrefix(absPath, absBaseDir)
}

// ValidateCorazaConfig validates Coraza configuration directives
func ValidateCorazaConfig(directives string, baseDir string) error {
	// Create a test WAF instance to validate configuration
	_, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(os.DirFS(baseDir)).
		WithDirectives(directives))
	return err
}

// IsHiddenFile checks if a file or directory is hidden (starts with .)
func IsHiddenFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

// IsConfigFile checks if a file is a .conf file
func IsConfigFile(name string) bool {
	return strings.HasSuffix(name, ".conf")
}
