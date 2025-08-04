package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
)

var (
	profiles   = make(map[string]coraza.WAF)
	profileMux sync.RWMutex
)

func LoadProfiles(dir string) {
	files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".conf")
		p, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}

		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(string(p)))
		if err != nil {
			panic(err)
		}

		profileMux.Lock()
		profiles[name] = waf
		profileMux.Unlock()

		fmt.Printf("Loaded WAF profile: %s\n", name)
	}
}

func GetProfile(name string) coraza.WAF {
	profileMux.RLock()
	defer profileMux.RUnlock()
	if waf, ok := profiles[name]; ok {
		return waf
	}
	return profiles["default"]
}
