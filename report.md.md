# Vulnerability Exploitability Analysis Report

**Generated:** 2025-11-02T19:13:46Z

**Target:** /workspace (repository)

---

## Executive Summary

This analysis identified **0** vulnerabilities across **37** components.

### Exploitability Breakdown

| Score | Count |
|-------|-------|

- **Exploitable:** 0 vulnerabilities
- **Not Exploitable:** 0 vulnerabilities

---

## Component Inventory

| Component | Version | Type | Source | Location |
|-----------|---------|------|--------|----------|
| github.com/spf13/viper | v1.21.0 | gomod | trivy |  |
| github.com/sagikazarmark/locafero | v0.11.0 | gomod | trivy |  |
| go.yaml.in/yaml/v3 | v3.0.4 | gomod | trivy |  |
| github.com/matanlivne/exploint |  | gomod | trivy |  |
| github.com/sashabaranov/go-openai | v1.41.2 | gomod | trivy |  |
| github.com/spf13/cobra | v1.10.1 | gomod | trivy |  |
| github.com/spf13/pflag | v1.0.10 | gomod | trivy |  |
| github.com/subosito/gotenv | v1.6.0 | gomod | trivy |  |
| github.com/CycloneDX/cyclonedx-go | v0.9.3 | gomod | trivy |  |
| gopkg.in/yaml.v3 | v3.0.1 | gomod | trivy |  |
| github.com/go-viper/mapstructure/v2 | v2.4.0 | gomod | trivy |  |
| github.com/pelletier/go-toml/v2 | v2.2.4 | gomod | trivy |  |
| golang.org/x/sys | v0.29.0 | gomod | trivy |  |
| golang.org/x/text | v0.28.0 | gomod | trivy |  |
| github.com/fsnotify/fsnotify | v1.9.0 | gomod | trivy |  |
| github.com/inconshreveable/mousetrap | v1.1.0 | gomod | trivy |  |
| github.com/sourcegraph/conc | v0.3.1-0.20240121214520-5f936abd7ae8 | gomod | trivy |  |
| github.com/spf13/afero | v1.15.0 | gomod | trivy |  |
| github.com/spf13/cast | v1.10.0 | gomod | trivy |  |
| cyclonedx-go | 0.9.3 | go | go.mod | github.com/CycloneDX/cyclonedx-go |
| go-openai | 1.41.2 | go | go.mod | github.com/sashabaranov/go-openai |
| cobra | 1.10.1 | go | go.mod | github.com/spf13/cobra |
| viper | 1.21.0 | go | go.mod | github.com/spf13/viper |
| yaml.v3 | 3.0.1 | go | go.mod | gopkg.in/yaml.v3 |
| fsnotify | 1.9.0 | go | go.mod | github.com/fsnotify/fsnotify |
| v2 | 2.4.0 | go | go.mod | github.com/go-viper/mapstructure/v2 |
| mousetrap | 1.1.0 | go | go.mod | github.com/inconshreveable/mousetrap |
| v2 | 2.2.4 | go | go.mod | github.com/pelletier/go-toml/v2 |
| locafero | 0.11.0 | go | go.mod | github.com/sagikazarmark/locafero |
| conc | 0.3.1-0.20240121214520-5f936abd7ae8 | go | go.mod | github.com/sourcegraph/conc |
| afero | 1.15.0 | go | go.mod | github.com/spf13/afero |
| cast | 1.10.0 | go | go.mod | github.com/spf13/cast |
| pflag | 1.0.10 | go | go.mod | github.com/spf13/pflag |
| gotenv | 1.6.0 | go | go.mod | github.com/subosito/gotenv |
| v3 | 3.0.4 | go | go.mod | go.yaml.in/yaml/v3 |
| sys | 0.29.0 | go | go.mod | golang.org/x/sys |
| text | 0.28.0 | go | go.mod | golang.org/x/text |

---

## Detailed Findings

## Recommendations

1. Address all exploitable vulnerabilities (scores: CRITICAL, HIGH, MEDIUM, LOW)
2. Review components marked as NOT_EXPLOITABLE to confirm assessment
3. Keep dependencies up to date
4. Implement security scanning in CI/CD pipeline

