package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse strictly unmarshals the raw YAML (unknown keys are errors, reported
// with line numbers against the user's own file), then expands ${ENV_VAR} references in the decoded string fields,
// applies defaults, and validates.
//
// Expansion runs after unmarshalling — not on the raw bytes — so that: (a)
// parse errors never echo secret values, only the literal ${VAR} text the
// user wrote; (b) ${VAR} inside YAML comments is inert, since comments don't
// survive unmarshalling; (c) secrets containing quotes or newlines survive
// verbatim, since they're substituted after YAML's own escaping is resolved.
//
// Secrets are expanded into memory only — callers must never write the
// expanded form back to disk.
//
// Parse never panics on any input: a bad file is an error, because the
// reload goroutine (Watch) runs it on whatever an operator saved.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := unmarshalStrict(data, &c); err != nil {
		return nil, err
	}
	if err := expandEnv(&c); err != nil {
		return nil, err
	}
	withDefaults(&c)
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config:\n%w", err)
	}
	return &c, nil
}

// unmarshalStrict is the strict YAML step. goccy/go-yaml v1.19.2 panics on
// some malformed tags (a nil dereference in ast.(*ArrayNodeIter).Len, audit
// P3-CORE-001), so a panic from the decoder is turned into a parse error
// instead of taking the process down. The recovered value is not echoed: it
// is an internal decoder message, not something the operator wrote.
func unmarshalStrict(data []byte, c *Config) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parse config: malformed YAML (the decoder failed on this input; check tags such as !foo and indentation)")
		}
	}()
	if uerr := yaml.UnmarshalWithOptions(data, c, yaml.Strict()); uerr != nil {
		return fmt.Errorf("parse config:\n%s", yaml.FormatError(uerr, false, true))
	}
	return nil
}
