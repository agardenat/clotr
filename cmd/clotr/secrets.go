package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tunnel"
	"github.com/agardenat/clotr/internal/vault"
)

func registerSecretSources(cfg *config.Config, warn func(string)) {
	var active []config.SecretSource
	for _, s := range cfg.Secrets {
		if s.IsEnabled() {
			active = append(active, s)
		} else {
			creds.DisableSecretSource(s.Name, i18n.E("cli.secrets.disabled"))
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
	check := &cobra.Command{
		Use:   i18n.T("cli.secrets.check.use"),
		Short: i18n.T("cli.secrets.check.short"),
		Long:  i18n.T("cli.secrets.check.long"),
		RunE: func(c *cobra.Command, args []string) error {
			return cmdSecretsCheck(c.Context(), o, args, c.OutOrStdout())
		},
	}
	cmd.AddCommand(test, check)
	return cmd
}

func plannedTunnelURL(cfg *config.Config, ic config.Instance) string {
	cl, ok := cfg.Client(ic.Client)
	if !ok {
		return ""
	}
	if tc, _ := cl.TunnelFor(ic.Project); tc != nil {
		return fmt.Sprintf("socks5h://127.0.0.1:%d", tc.Port)
	}
	return ""
}

func vaultLogin(l *config.VaultLogin, unattended error) vault.LoginOptions {
	return vault.LoginOptions{Path: l.Path, Role: l.Role, Port: l.Port, MinTTL: l.MinTTL.Duration, Wait: 5 * time.Minute, Unattended: unattended}
}

func cmdSecretsCheck(ctx context.Context, o *options, targets []string, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := loadConfig(o)
	if err != nil {
		return err
	}
	unattended := i18n.E("cli.secrets.check.mode")
	saved := creds.OpenTTY
	creds.OpenTTY = func() (*creds.Console, error) { return nil, unattended }
	defer func() { creds.OpenTTY = saved }()
	failed := 0
	report := func(what string, err error) {
		if err != nil {
			failed++
			fmt.Fprintln(w, i18n.T("cli.secrets.check.ko", what, err))
			return
		}
		fmt.Fprintln(w, i18n.T("cli.secrets.check.ok", what))
	}
	if l := cfg.Vault.Login; l != nil {
		report("Vault", vault.EnsureLogin(ctx, vaultLogin(l, unattended)))
	}
	for _, s := range cfg.Secrets {
		if s.IsEnabled() {
			report(i18n.T("cli.secrets.check.source", s.Name), creds.SourceErr(s.Name))
		}
	}
	filter := toolFilter{only: expandClients(cfg, targets)}
	var selected []config.Instance
	for _, ic := range cfg.Instances {
		if filter.active(ic.Name, ic.IsEnabled()) {
			selected = append(selected, ic)
		}
	}
	if len(targets) > 0 && len(selected) == 0 {
		return i18n.E("cli.secrets.check.none", strings.Join(targets, ", "))
	}
	tunnels := map[string]bool{}
	for _, ic := range selected {
		cl, ok := cfg.Client(ic.Client)
		if !ok {
			continue
		}
		tc, key := cl.TunnelFor(ic.Project)
		if tc == nil || tunnels[key] {
			continue
		}
		tunnels[key] = true
		project := ""
		if pr, ok := cl.Project(ic.Project); ok && pr.Tunnel == tc {
			project = pr.Name
		}
		rendered, err := renderTunnel(*tc, clientVars(cl, project))
		if err == nil {
			err = tunnel.CheckCredentials(ctx, key, rendered)
		}
		report(tunnel.Label(key), err)
	}
	var set *template.Set
	if len(selected) > 0 {
		if set, err = template.Load(cfg.Templates.Dir); err != nil {
			return err
		}
	}
	for _, ic := range selected {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		t, ok := set.Get(ic.Template)
		if !ok {
			report(ic.Name, i18n.E("cli.warn.template_missing", ic.Name, ic.Template))
			continue
		}
		in, err := newInstance(cfg, ic, t, o.levelFor(cfg, ic), plannedTunnelURL(cfg, ic))
		if err == nil {
			err = in.CheckCredentials(ctx)
			in.Close()
		}
		report(ic.Name, err)
	}
	if failed > 0 {
		return i18n.E("cli.secrets.check.failed", failed)
	}
	return nil
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
		if err := vault.EnsureLogin(ctx, vaultLogin(l, creds.CanPrompt())); err != nil {
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
