package evasion

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// SNIRotator manages rotation through whitelisted SNI values
type SNIRotator struct {
	pool       []string
	weights    []int      // Higher weight = higher priority
	index      uint64     // Current index for round-robin
	mu         sync.RWMutex
	strategy   RotationStrategy
	lastUsed   map[string]time.Time // Track usage for cooldown
	cooldown   time.Duration        // Cooldown between same SNI uses
}

// RotationStrategy defines how SNIs are selected
type RotationStrategy int

const (
	// StrategyRoundRobin cycles through SNIs in order
	StrategyRoundRobin RotationStrategy = iota
	// StrategyRandom picks random SNI each time
	StrategyRandom
	// StrategyWeighted uses weights to prefer certain SNIs
	StrategyWeighted
	// StrategyCooldown avoids recently used SNIs
	StrategyCooldown
)

// SNIEntry represents an SNI with metadata
type SNIEntry struct {
	SNI         string
	Weight      int    // 1-100, higher = more likely
	Category    string // e.g., "google", "yandex", "cdn"
	Description string
}

// WhitelistedSNIs contains known-good SNIs for Russian DPI bypass
// Ordered by effectiveness based on research.md analysis
var WhitelistedSNIs = []SNIEntry{
	// Tier 1: Russian services (highest priority - always whitelisted)
	{SNI: "yandex.ru", Weight: 100, Category: "russian", Description: "Yandex main"},
	{SNI: "ya.ru", Weight: 100, Category: "russian", Description: "Yandex short"},
	{SNI: "yandex.net", Weight: 95, Category: "russian", Description: "Yandex CDN"},
	{SNI: "vk.com", Weight: 100, Category: "russian", Description: "VKontakte"},
	{SNI: "vk.me", Weight: 95, Category: "russian", Description: "VK messenger"},
	{SNI: "mail.ru", Weight: 100, Category: "russian", Description: "Mail.ru"},
	{SNI: "ok.ru", Weight: 90, Category: "russian", Description: "Odnoklassniki"},
	{SNI: "sberbank.ru", Weight: 100, Category: "russian", Description: "Sberbank"},
	{SNI: "gosuslugi.ru", Weight: 100, Category: "russian", Description: "Government services"},
	{SNI: "mos.ru", Weight: 95, Category: "russian", Description: "Moscow portal"},

	// Tier 2: Google services (heavily used, usually not blocked)
	{SNI: "google.com", Weight: 85, Category: "google", Description: "Google main"},
	{SNI: "www.google.com", Weight: 85, Category: "google", Description: "Google www"},
	{SNI: "google.ru", Weight: 90, Category: "google", Description: "Google Russia"},
	{SNI: "googleapis.com", Weight: 80, Category: "google", Description: "Google APIs"},
	{SNI: "gstatic.com", Weight: 80, Category: "google", Description: "Google static"},
	{SNI: "googleusercontent.com", Weight: 75, Category: "google", Description: "Google content"},
	{SNI: "firebase.google.com", Weight: 70, Category: "google", Description: "Firebase"},
	{SNI: "firebaseio.com", Weight: 70, Category: "google", Description: "Firebase IO"},

	// Tier 3: Microsoft/Azure (enterprise, usually allowed)
	{SNI: "microsoft.com", Weight: 80, Category: "microsoft", Description: "Microsoft main"},
	{SNI: "office.com", Weight: 80, Category: "microsoft", Description: "Office 365"},
	{SNI: "azure.com", Weight: 75, Category: "microsoft", Description: "Azure"},
	{SNI: "windows.net", Weight: 75, Category: "microsoft", Description: "Windows services"},
	{SNI: "live.com", Weight: 70, Category: "microsoft", Description: "Microsoft Live"},
	{SNI: "outlook.com", Weight: 75, Category: "microsoft", Description: "Outlook"},

	// Tier 4: CDNs (common, hard to block entirely)
	{SNI: "cloudflare.com", Weight: 60, Category: "cdn", Description: "Cloudflare"},
	{SNI: "akamai.net", Weight: 65, Category: "cdn", Description: "Akamai"},
	{SNI: "fastly.net", Weight: 60, Category: "cdn", Description: "Fastly"},

	// Tier 5: Banking (critical infrastructure, never blocked)
	{SNI: "tinkoff.ru", Weight: 100, Category: "banking", Description: "Tinkoff Bank"},
	{SNI: "alfabank.ru", Weight: 100, Category: "banking", Description: "Alfa Bank"},
	{SNI: "vtb.ru", Weight: 100, Category: "banking", Description: "VTB Bank"},
}

// NewSNIRotator creates a new SNI rotator
func NewSNIRotator(strategy RotationStrategy) *SNIRotator {
	pool := make([]string, 0, len(WhitelistedSNIs))
	weights := make([]int, 0, len(WhitelistedSNIs))

	for _, entry := range WhitelistedSNIs {
		pool = append(pool, entry.SNI)
		weights = append(weights, entry.Weight)
	}

	return &SNIRotator{
		pool:     pool,
		weights:  weights,
		strategy: strategy,
		lastUsed: make(map[string]time.Time),
		cooldown: 30 * time.Second,
	}
}

// NewSNIRotatorWithPool creates rotator with custom SNI pool
func NewSNIRotatorWithPool(snis []string, strategy RotationStrategy) *SNIRotator {
	weights := make([]int, len(snis))
	for i := range weights {
		weights[i] = 50 // Default weight
	}

	return &SNIRotator{
		pool:     snis,
		weights:  weights,
		strategy: strategy,
		lastUsed: make(map[string]time.Time),
		cooldown: 30 * time.Second,
	}
}

// Next returns the next SNI according to rotation strategy
func (r *SNIRotator) Next() string {
	if len(r.pool) == 0 {
		return "google.com" // Fallback
	}

	switch r.strategy {
	case StrategyRoundRobin:
		return r.nextRoundRobin()
	case StrategyRandom:
		return r.nextRandom()
	case StrategyWeighted:
		return r.nextWeighted()
	case StrategyCooldown:
		return r.nextWithCooldown()
	default:
		return r.nextRoundRobin()
	}
}

func (r *SNIRotator) nextRoundRobin() string {
	idx := atomic.AddUint64(&r.index, 1) - 1
	return r.pool[int(idx)%len(r.pool)]
}

func (r *SNIRotator) nextRandom() string {
	return r.pool[rand.Intn(len(r.pool))]
}

func (r *SNIRotator) nextWeighted() string {
	// Calculate total weight
	totalWeight := 0
	for _, w := range r.weights {
		totalWeight += w
	}

	// Pick random point
	point := rand.Intn(totalWeight)

	// Find corresponding SNI
	cumulative := 0
	for i, w := range r.weights {
		cumulative += w
		if point < cumulative {
			return r.pool[i]
		}
	}

	return r.pool[len(r.pool)-1]
}

func (r *SNIRotator) nextWithCooldown() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Find SNI not in cooldown, preferring higher weights
	for _, entry := range WhitelistedSNIs {
		lastUsed, exists := r.lastUsed[entry.SNI]
		if !exists || now.Sub(lastUsed) > r.cooldown {
			r.lastUsed[entry.SNI] = now
			return entry.SNI
		}
	}

	// All in cooldown, use random
	return r.nextRandom()
}

// GetBySNI returns SNI entry by name
func GetBySNI(sni string) *SNIEntry {
	for i := range WhitelistedSNIs {
		if WhitelistedSNIs[i].SNI == sni {
			return &WhitelistedSNIs[i]
		}
	}
	return nil
}

// GetByCategory returns all SNIs in category
func GetByCategory(category string) []SNIEntry {
	var result []SNIEntry
	for _, entry := range WhitelistedSNIs {
		if entry.Category == category {
			result = append(result, entry)
		}
	}
	return result
}

// GetRussianSNIs returns SNIs of Russian services (highest priority)
func GetRussianSNIs() []string {
	result := make([]string, 0)
	for _, entry := range WhitelistedSNIs {
		if entry.Category == "russian" || entry.Category == "banking" {
			result = append(result, entry.SNI)
		}
	}
	return result
}
