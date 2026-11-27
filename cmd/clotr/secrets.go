package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/vault"
)

func registerSecretSources(cfg *config.Config, warn func(string)) {
	var active []config.SecretSource
	for _, s := range cfg.Secrets {
		if s.IsEnabled() {
			active = append(active, s)
		}
	}
	if len(active) == 0 {
		return
	}
	set, err := template.Load(cfg.Templates.Dir)
	for _, s := range active {
		in, ierr := secretInstance(cfg, set, err, s)
		if ierr != nil {
			creds.DisableSecretSource(s.Name, ierr)
			warn(i18n.T("cli.warn.secrets_off", s.Name, ierr))
			continue
		}
		creds.RegisterSecretSource(s.Name, in.SecretRead)
	}
}

func secretInstance(cfg *config.Config, set *template.Set, loadErr error, s config.SecretSource) (*template.Instance, error) {
	if loadErr != nil {
		return nil, loadErr
	}
	t, ok := set.Get(s.Template)
	if !ok {
		return nil, i18n.E("cli.warn.template_missing", s.Name, s.Template)
	}
	if !t.Secrets() {
		return nil, i18n.E("tpl.secrets.not", t.Name)
	}
	params := map[string]any{}
	for k, v := range cfg.Params {
		if _, declared := t.Params[k]; declared {
			params[k] = v
		}
	}
	maps.Copy(params, s.Params)
	rendered, err := renderVars(params, map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("secrets.%s.params.%w", s.Name, err)
	}
	return template.NewInstance(s.Name, t, rendered.(map[string]any))
}

func secretsCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{Use: "secrets", Short: i18n.T("cli.secrets.short")}
	test := &cobra.Command{
		Use:   "test <ref>",
		Short: i18n.T("cli.secrets.test.short"),
		Long:  i18n.T("cli.secrets.test.long"),
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return cmdSecretsTest(c.Context(), o, args[0], c.OutOrStdout())
		},
	}
	cmd.AddCommand(test)
	return cmd
}

func cmdSecretsTest(ctx context.Context, o *options, ref string, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	if l := cfg.Vault.Login; l != nil {
		if err := vault.EnsureLogin(ctx, vault.LoginOptions{Path: l.Path, Role: l.Role, Port: l.Port, MinTTL: l.MinTTL.Duration, Wait: 5 * time.Minute}); err != nil {
			fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("cli.warn.vault_login", err))
		}
	}
	v, err := creds.ReadVault(ctx, ref)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, i18n.T("cli.secrets.ok", ref, len([]rune(v))))
	if u, err := creds.ReadVaultUser(ctx, ref); err == nil && u != v {
		fmt.Fprintln(w, i18n.T("cli.secrets.account", u))
	}
	return nil
}
