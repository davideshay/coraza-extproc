package processor

import (
	"log/slog"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// getWAFEngine retrieves the appropriate WAF engine for a given authority
func (p *Processor) getWAFEngine(authority string) coraza.WAF {
	p.wafMutex.RLock()
	defer p.wafMutex.RUnlock()

	// Try exact match first
	if waf, exists := p.wafEngines[authority]; exists {
		slog.Debug("Found exact WAF match", slog.String("authority", authority))
		return waf
	}

	// Try wildcard matches
	for domain, waf := range p.wafEngines {
		if strings.HasPrefix(domain, "*.") {
			wildcard := strings.TrimPrefix(domain, "*.")
			if strings.HasSuffix(authority, wildcard) {
				slog.Debug("Found wildcard WAF match",
					slog.String("authority", authority),
					slog.String("domain", domain))
				return waf
			}
		}
	}

	// Return default WAF if exists
	if waf, exists := p.wafEngines["default"]; exists {
		slog.Debug("Using default WAF engine", slog.String("authority", authority))
		return waf
	}

	slog.Error("No WAF engine found", slog.String("authority", authority))
	return nil
}

// logAvailableEngines logs debug information about loaded WAF engines
func (p *Processor) logAvailableEngines() {
	p.wafMutex.RLock()
	defer p.wafMutex.RUnlock()

	slog.Debug("Available WAF engines:")
	for domain := range p.wafEngines {
		slog.Debug("  Domain:", slog.String("domain", domain))
	}

	if len(p.wafEngines) == 0 {
		slog.Error("No WAF engines loaded!")
	}
}
