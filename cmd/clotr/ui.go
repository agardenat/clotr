package main

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
)

func initUILanguage(args []string) {
	var cfgFlag string
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		if !hasVal && i+1 < len(args) {
			val = args[i+1]
		}
		switch name {
		case "--":
			i = len(args)
		case "--ui-lang":
			if config.ValidUILanguage(val) {
				i18n.SetUI(val)
			}
		case "--config", "-c":
			cfgFlag = val
		}
	}
	if path, err := config.Resolve(cfgFlag); err == nil {
		i18n.DefaultUI(config.PeekUILanguage(path))
	}
}

func localizeCobra(root *cobra.Command) {
	root.SetUsageTemplate(i18n.T("cli.usage"))
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	name := root.Name()
	for _, c := range root.Commands() {
		switch c.Name() {
		case "help":
			c.Short, c.Long = i18n.T("cli.help.short"), i18n.T("cli.help.long", name)
		case "completion":
			c.Short, c.Long = i18n.T("cli.completion.short"), i18n.T("cli.completion.long", name)
			for _, sh := range c.Commands() {
				sh.Short, sh.Long = i18n.T("cli.completion.shell", sh.Name()), i18n.T("cli.completion."+sh.Name(), name)
				if f := sh.Flags().Lookup("no-descriptions"); f != nil {
					f.Usage = i18n.T("cli.flag.no_descriptions")
				}
			}
		}
	}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("help") == nil {
			c.Flags().BoolP("help", "h", false, i18n.T("cli.flag.help", c.Name()))
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}
