package config

import (
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agardenat/clotr/internal/i18n"
)

var Version = "dev"

var releaseRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func parseRelease(v string) ([3]int, bool) {
	m := releaseRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

func RequireVersion(what, min, hint string) error {
	if strings.TrimSpace(min) == "" {
		return nil
	}
	want, ok := parseRelease(min)
	if !ok {
		return i18n.E("config.min_version_bad", what, min)
	}
	have, ok := parseRelease(Version)
	if !ok {
		return nil
	}
	for i := range have {
		if have[i] != want[i] {
			if have[i] > want[i] {
				return nil
			}
			if hint = strings.TrimSpace(hint); hint != "" {
				hint = " ; " + hint
			}
			return i18n.E("config.min_version", what, strings.TrimPrefix(min, "v"), strings.TrimPrefix(Version, "v"), hint)
		}
	}
	return nil
}

type versionHeader struct {
	MinVersion string `yaml:"min_version"`
	UpdateHint string `yaml:"update_hint"`
}

func PeekVersion(data []byte) (min, hint string) {
	var h versionHeader
	_ = yaml.Unmarshal(data, &h)
	return h.MinVersion, h.UpdateHint
}
