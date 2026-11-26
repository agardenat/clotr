package main

import (
	"context"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/report"
	"github.com/agardenat/clotr/internal/session"
)

const topicTimeout = 30 * time.Second

var topicWord = regexp.MustCompile(`[\p{L}\p{N}]+`)

func (rt *app) startSession(ctx context.Context, o *options, sess *session.Session, request string) error {
	if sess.Started() {
		return nil
	}
	var parts []string
	for _, cl := range rt.cfg.Clients {
		if clientCited(rt.cfg, cl, o.tools, request) {
			parts = append(parts, cl.Name)
		}
	}
	parts = append(parts, rt.sessionTopic(ctx, o, request))
	if err := sess.Start(session.NamePrefix(parts...)); err != nil {
		return err
	}
	sess.Language = o.lang
	return sess.Save()
}

func (o *options) modeWord() string {
	switch {
	case o.cveFlag != "":
		return report.ModeCVE
	case o.datVariant != "" && o.diagramOnly:
		return i18n.T("session.word.diagram")
	case o.datVariant != "":
		return report.ModeDAT
	case o.watch:
		return i18n.T("session.word.watch")
	case o.incident:
		return report.ModeIncident
	case o.change:
		return report.ModeChange
	case o.upgrade:
		return report.ModeUpgrade
	case o.minutes:
		return i18n.T("session.word.minutes")
	case o.ticketFlag != "":
		return "ticket"
	}
	return ""
}

func (rt *app) sessionTopic(ctx context.Context, o *options, request string) string {
	word := o.modeWord()
	if o.cveFlag != "" || o.datVariant != "" || strings.TrimSpace(request) == "" {
		return word
	}
	var role string
	var cands []catalog.ModelInfo
	for _, r := range rolesBySpeed(rt.cfg) {
		if c, err := rt.router.Candidates(r); err == nil && len(c) > 0 {
			role, cands = r, c
			break
		}
	}
	if role == "" {
		return word
	}
	ctx, cancel := context.WithTimeout(ctx, topicTimeout)
	defer cancel()
	runner := rt.newRunner(progress.Nop{}, rt.registry)
	runner.Attempts, runner.Persistent = 1, nil
	out, err := runner.Run(ctx, agent.Spec{TaskID: "session-name", Role: role, System: topicPrompt, User: request, Candidates: cands})
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("cli.warning"), i18n.T("session.topic_failed", err))
		return word
	}
	if w := topicWord.FindString(thinkFree(out.Content)); w != "" && len([]rune(w)) <= 24 {
		return w
	}
	return word
}

func thinkFree(s string) string {
	if i := strings.LastIndex(s, "</think>"); i >= 0 {
		s = s[i+len("</think>"):]
	}
	return strings.TrimSpace(s)
}

func rolesBySpeed(cfg *config.Config) []string {
	names := slices.Sorted(maps.Keys(cfg.Roles))
	if !slices.Contains(names, config.RolePlanner) {
		names = append(names, config.RolePlanner)
	}
	rank := func(n string) int {
		if r := config.TierRank(cfg.Roles[n].Tier); r > 0 {
			return r
		}
		return 99
	}
	slices.SortStableFunc(names, func(a, b string) int { return rank(a) - rank(b) })
	return names
}

const topicPrompt = "Donner un seul mot, en minuscules, sans espace, qui résume le sujet technique de la demande : composant, produit ou symptôme (exemples : kerberos, nginx, hdfs, certificat, disque, ingress, upgrade). Ne pas donner le nom du client, d'un hôte ou d'une instance. Répondre uniquement par ce mot."
