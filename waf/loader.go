package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"gopkg.in/yaml.v3"
)

var (
	profiles   = make(map[string]coraza.WAF)
	profilesMu sync.RWMutex

	mappings   = make(map[string]string)
	mappingsMu sync.RWMutex
)

type ConfigMapping struct {
	Mappings map[string]string `yaml:"mappings"`
}

// LoadProfiles loads all .conf files from a directory as WAF profiles
func LoadProfiles(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		return fmt.Errorf("glob profiles: %w", err)
	}

	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".conf")
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read profile %s: %w", name, err)
		}

		wafInstance, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(string(data)))
		if err != nil {
			return fmt.Errorf("new waf instance %s: %w", name, err)
		}

		profilesMu.Lock()
		profiles[name] = wafInstance
		profilesMu.Unlock()

		fmt.Printf("Loaded WAF profile: %s\n", name)
	}
	return nil
}

// LoadMappings loads authority->profile mappings from a YAML file
func LoadMappings(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read mappings: %w", err)
	}

	var cfg ConfigMapping
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("unmarshal mappings: %w", err)
	}

	mappingsMu.Lock()
	mappings = cfg.Mappings
	mappingsMu.Unlock()

	fmt.Printf("Loaded authority->profile mappings\n")
	return nil
}

// GetProfile returns a WAF profile instance by name
func GetProfile(name string) coraza.WAF {
	profilesMu.RLock()
	defer profilesMu.RUnlock()

	if waf, ok := profiles[name]; ok {
		return waf
	}
	return profiles["default"]
}

// GetProfileNameForAuthority returns the profile name mapped to an authority
func GetProfileNameForAuthority(authority string) string {
	mappingsMu.RLock()
	defer mappingsMu.RUnlock()

	if profile, ok := mappings[authority]; ok {
		return profile
	}
	return mappings["default"]
}
