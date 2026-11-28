package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
)

type clientEntry struct {
	Name     string         `json:"name"`
	Label    string         `json:"label,omitempty"`
	Projects []projectEntry `json:"projects"`
}

type projectEntry struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
}

func clientsCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clients",
		Short: i18n.T("cli.clients.short"),
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfig(o)
			if err != nil {
				return err
			}
			return writeClients(c.OutOrStdout(), cfg, o.json)
		},
	}
	cmd.Flags().BoolVar(&o.json, "json", false, i18n.T("cli.flag.json"))
	return cmd
}

func clientEntries(cfg *config.Config) []clientEntry {
	out := make([]clientEntry, 0, len(cfg.Clients))
	for _, cl := range cfg.Clients {
		e := clientEntry{Name: cl.Name, Label: cl.Label, Projects: []projectEntry{}}
		for _, p := range cl.Projects {
			e.Projects = append(e.Projects, projectEntry{Name: p.Name, Label: p.Label})
		}
		out = append(out, e)
	}
	return out
}

func writeClients(w io.Writer, cfg *config.Config, asJSON bool) error {
	entries := clientEntries(cfg)
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"clients": entries})
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, i18n.T("clients.head"))
	for _, e := range entries {
		var projects []string
		for _, p := range e.Projects {
			if p.Label != "" {
				projects = append(projects, p.Name+" ("+p.Label+")")
			} else {
				projects = append(projects, p.Name)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.Label, strings.Join(projects, ", "))
	}
	return tw.Flush()
}
