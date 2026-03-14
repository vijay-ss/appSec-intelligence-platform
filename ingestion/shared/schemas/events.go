// Package schemas defines canonical event types shared across all ingestion services.
// All events are serialised to JSON before being published to Kafka.
package schemas

import "time"

// VulnerabilityEvent is the normalised CVE record emitted by the NVD and OSV pollers.
// NVD is the authoritative source for CVSS scores and CWE IDs.
// OSV is the authoritative source for package-level version ranges.
type VulnerabilityEvent struct {
	EventID              string    `json:"event_id"`
	CVEID                string    `json:"cve_id"`
	Source               string    `json:"source"`
	PublishedAt          time.Time `json:"published_at"`
	IngestedAt           time.Time `json:"ingested_at"`
	CVSSScore            float64   `json:"cvss_score"`
	SeverityTier         string    `json:"severity_tier"`
	CWEID                string    `json:"cwe_id,omitempty"`
	Description          string    `json:"description"`
	AffectedPackage      string    `json:"affected_package"`
	Ecosystem            string    `json:"ecosystem"`
	AffectedVersionRange string    `json:"affected_version_range"`
	SafeVersion          string    `json:"safe_version,omitempty"`
	AffectedVersions     []string  `json:"affected_versions"`
}

// DependencyPin is a single package pinned to a specific version.
type DependencyPin struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// DependencyUpdate records a package version change (from → to).
type DependencyUpdate struct {
	Package string `json:"package"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
}

// DependencyChangeEvent is emitted whenever a dependency manifest changes in a repo.
// ServiceID is always set to the repo name for archive/events-api sources,
// and to the synthetic service name for events from the synthetic generator.
type DependencyChangeEvent struct {
	EventID      string             `json:"event_id"`
	Source       string             `json:"source"`
	Repo         string             `json:"repo"`
	ServiceID    string             `json:"service_id"`
	PRNumber     int                `json:"pr_number"`
	Author       string             `json:"author"`
	Ecosystem    string             `json:"ecosystem"`
	ManifestFile string             `json:"manifest_file"`
	Added        []DependencyPin    `json:"added"`
	Removed      []DependencyPin    `json:"removed"`
	Updated      []DependencyUpdate `json:"updated"`
	OccurredAt   time.Time          `json:"occurred_at"`
	IngestedAt   time.Time          `json:"ingested_at"`
}

// SeverityFromCVSS maps a CVSS base score to a severity tier string.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// EcosystemFromBranch maps a Dependabot branch prefix to a normalised ecosystem name.
func EcosystemFromBranch(branchRef string) string {
	prefixes := map[string]string{
		"dependabot/pip/":          "pypi",
		"dependabot/npm_and_yarn/": "npm",
		"dependabot/go_modules/":   "go",
		"dependabot/maven/":        "maven",
		"dependabot/cargo/":        "cargo",
		"dependabot/bundler/":      "rubygems",	
	}
	for prefix, eco := range prefixes {
		if len(branchRef) >= len(prefix) && branchRef[:len(prefix)] == prefix {
			return eco
		}
	}
	return ""
}

// ManifestForEcosystem returns the canonical manifest filename for an ecosystem.
func ManifestForEcosystem(eco string) string {
	m := map[string]string{
		"pypi":     "requirements.txt",
		"npm":      "package.json",
		"go":       "go.mod",
		"maven":    "pom.xml",
		"cargo":    "Cargo.toml",
		"rubygems": "Gemfile",
	}
	if v, ok := m[eco]; ok {
		return v
	}
	return "unknown"
}