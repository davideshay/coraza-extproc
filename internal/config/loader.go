package config

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"coraza-extproc/internal/types"

	"github.com/corazawaf/coraza/v3"
	"github.com/fsnotify/fsnotify"
)

// Loader handles configuration loading and watching
type Loader struct {
	baseDir     string
	confDir     string
	watcher     *fsnotify.Watcher
	hashTracker map[string][32]byte
	onChange    func(map[string]coraza.WAF)
}

// New creates a new config loader
func NewLoader(baseDir, confDir string, onChange func(map[string]coraza.WAF)) (*Loader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	loader := &Loader{
		baseDir:     baseDir,
		confDir:     confDir,
		watcher:     watcher,
		hashTracker: make(map[string][32]byte),
		onChange:    onChange,
	}

	return loader, nil
}

// LoadInitial loads the initial configuration
func (l *Loader) LoadInitial() error {
	engines, err := l.loadFromDirectory()
	if err != nil {
		return err
	}

	l.onChange(engines)
	return nil
}

// StartWatching starts the file watching routine
func (l *Loader) StartWatching() {
	go l.watchLoop()
}

// Close shuts down the loader
func (l *Loader) Close() error {
	if l.watcher != nil {
		return l.watcher.Close()
	}
	return nil
}

func (l *Loader) loadFromDirectory() (map[string]coraza.WAF, error) {
	absConfDir, err := filepath.Abs(l.confDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config directory: %w", err)
	}

	engines := make(map[string]coraza.WAF)

	err = filepath.WalkDir(absConfDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			slog.Error("Error accessing path", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		// Security checks
		if !IsPathSafe(path, absConfDir) {
			slog.Warn("Path outside config directory, skipping", slog.String("path", path))
			return nil
		}

		// Skip hidden directories
		if d.IsDir() && IsHiddenFile(d.Name()) && path != absConfDir {
			return filepath.SkipDir
		}

		// Only process .conf files
		if d.IsDir() || IsHiddenFile(d.Name()) || !IsConfigFile(d.Name()) {
			return nil
		}

		// Validate domain name
		domain := strings.TrimSuffix(d.Name(), ".conf")
		if !IsValidDomainName(domain) {
			slog.Warn("Invalid domain name, skipping",
				slog.String("domain", domain),
				slog.String("file", path))
			return nil
		}

		// Check file size
		fileInfo, err := d.Info()
		if err != nil {
			slog.Error("Failed to get file info", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		if fileInfo.Size() > types.MaxConfigFileSize {
			slog.Error("Config file too large, skipping",
				slog.String("path", path),
				slog.Int64("size", fileInfo.Size()))
			return nil
		}

		// Read and validate config
		confContent, err := os.ReadFile(path)
		if err != nil {
			slog.Error("Failed to read config file", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		// Validate config before creating WAF
		if err := ValidateCorazaConfig(string(confContent), l.baseDir); err != nil {
			slog.Error("Invalid Coraza configuration, skipping",
				slog.String("domain", domain),
				slog.String("path", path),
				slog.Any("err", err))
			return nil
		}

		// Create WAF engine
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(os.DirFS(l.baseDir)).
			WithDirectives(string(confContent)))
		if err != nil {
			slog.Error("Failed to create WAF for domain",
				slog.String("domain", domain),
				slog.Any("err", err))
			return nil
		}

		engines[domain] = waf
		slog.Info("Loaded WAF rules", slog.String("domain", domain))
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk config directory: %w", err)
	}

	slog.Info("Configuration loaded", slog.Int("engines", len(engines)))
	return engines, nil
}

func (l *Loader) watchLoop() {
	ticker := time.NewTicker(types.ConfigWatchInterval)
	defer ticker.Stop()

	for range ticker.C {
		l.checkForChanges()
	}
}

func (l *Loader) checkForChanges() {
	changed := false

	filepath.WalkDir(l.confDir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() && IsHiddenFile(d.Name()) && path != l.confDir {
			return filepath.SkipDir
		}

		if err != nil || d.IsDir() || !IsConfigFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		hash := sha256.Sum256(content)
		if oldHash, exists := l.hashTracker[path]; !exists || oldHash != hash {
			slog.Info("Config file changed", slog.String("path", path))
			l.hashTracker[path] = hash
			changed = true
		}
		return nil
	})

	if changed {
		engines, err := l.loadFromDirectory()
		if err != nil {
			slog.Error("Failed to reload config", slog.Any("error", err))
			return
		}
		l.onChange(engines)
	}
}
