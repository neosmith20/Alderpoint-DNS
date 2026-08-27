// Package dnsruntime is the web-side half of the Go-native DNS runtime
// compiler: it gathers already-loaded Go control-plane state (via the
// same service objects httpapi already holds -- no raw SQL duplicated
// here) into internal/dnscompile's pure Input shape, compiles the
// dnsdist config itself (no secrets, no root needed), and hands it to
// apdns-hostagent's dns_runtime.promote operation, which compiles
// BIND's own config (it owns the rndc secret) and does the real
// stage -> validate -> promote -> reload -> health-check -> rollback
// pipeline (see internal/hostagentd/ops_dnsruntime.go).
//
// Scope, matching internal/dnscompile's own disclosed narrowing: global
// policy only, one default upstream profile, a flat global list of
// domain-routing rules (not per-network), no SafeSearch/ECS. Strong
// ClientID identities/overrides ARE compiled (added 2026-08-27) --
// every active (non-revoked) identity of every enabled managed client,
// via internal/clients.AllActiveClientIdentities, matching that
// package's own doc comment for the disclosed scope of per-client
// enforcement (explicit domain overrides only, not the full per-field
// policy layer). Every mutation this orchestrator is wired to run
// after (see its own callers in internal/httpapi) reports its runtime
// result back to the caller the same way internal/localdns's existing
// stageAndPromote convention already does -- "saved, but runtime
// generation failed" is a distinct, visible failure mode, never silent.
package dnsruntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dnscompile"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/domainrouting"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

type Orchestrator struct {
	LocalDNS      *localdns.Service
	CustomRules   *customrules.Service
	Blocklists    *blocklists.Service
	Upstreams     *upstreams.Service
	DNSTransports *dnstransports.Service
	Policy        *policy.Service
	DomainRouting *domainrouting.Service
	Clients       *clients.Service
	HostAgent     *hostagent.Client

	// DnsdistListenAddress, BindBackendAddress, and TLSCertPath/
	// TLSKeyPath are fixed deployment configuration (not stored in any
	// table) -- the same address/paths the host-agent was started with
	// for this exact runtime, so the two sides always agree.
	DnsdistListenAddress string
	BindBackendAddress   string
	TLSCertPath          string
	TLSKeyPath           string
}

// Result mirrors hostagentd.DNSPromoteResult, plus whether the
// orchestrator itself could even attempt a promotion (e.g. no
// HostAgent configured at all -- this deployment has no DNS runtime
// wired, an honest, distinct case from "promotion failed").
type Result struct {
	Attempted  bool   `json:"attempted"`
	Promoted   bool   `json:"promoted"`
	RolledBack bool   `json:"rolled_back"`
	Stage      string `json:"stage,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Apply gathers current state, compiles it, and promotes it through
// the host-agent. Never returns a Go error itself -- every failure
// mode (no host-agent configured, compile error, denied/rejected
// promotion) is reported in the returned Result so a caller can always
// surface it without a type switch.
func (o *Orchestrator) Apply(ctx context.Context) Result {
	if o.HostAgent == nil {
		return Result{Attempted: false, Error: "no host-agent configured for this deployment -- DNS runtime compilation is unavailable"}
	}

	in, bindForwarders, bindTLSHostname, err := o.build(ctx)
	if err != nil {
		return Result{Attempted: true, Error: fmt.Sprintf("gathering runtime state: %v", err)}
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		return Result{Attempted: true, Error: fmt.Sprintf("compiling dnsdist config: %v", err)}
	}

	params := map[string]any{
		"dnsdist_conf":      dnsdistConf,
		"bind_forwarders":   bindForwarders,
		"bind_tls_hostname": bindTLSHostname,
	}
	var promResult struct {
		Promoted   bool   `json:"promoted"`
		RolledBack bool   `json:"rolled_back"`
		Stage      string `json:"stage"`
		Detail     string `json:"detail"`
	}
	if err := o.HostAgent.Call(ctx, hostagent.OpDNSRuntimePromote, params, &promResult); err != nil {
		return Result{Attempted: true, Error: err.Error()}
	}
	return Result{
		Attempted: true, Promoted: promResult.Promoted, RolledBack: promResult.RolledBack,
		Stage: promResult.Stage, Detail: promResult.Detail,
	}
}

func (o *Orchestrator) build(ctx context.Context) (dnscompile.Input, []string, string, error) {
	in := dnscompile.Input{
		ListenAddress:      o.DnsdistListenAddress,
		BindBackendAddress: o.BindBackendAddress,
		TLSCertPath:        o.TLSCertPath,
		TLSKeyPath:         o.TLSKeyPath,
		CacheMaxEntries:    10000,
	}

	if o.LocalDNS != nil {
		recs, err := o.LocalDNS.List(ctx)
		if err != nil {
			return in, nil, "", fmt.Errorf("loading local DNS records: %w", err)
		}
		for _, r := range recs {
			if !r.Enabled {
				continue
			}
			in.LocalDNSRecords = append(in.LocalDNSRecords, dnscompile.LocalDNSRecord{Name: r.Name, RecordType: r.RecordType, Value: r.Value, TTL: r.TTL})
		}
	}

	blockedSet := map[string]bool{}
	allowedSet := map[string]bool{}
	if o.CustomRules != nil {
		rules, err := o.CustomRules.List(ctx)
		if err != nil {
			return in, nil, "", fmt.Errorf("loading custom rules: %w", err)
		}
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			switch r.RuleType {
			case "block":
				blockedSet[strings.ToLower(r.Pattern)] = true
			case "allow":
				allowedSet[strings.ToLower(r.Pattern)] = true
			case "regex_block":
				in.RegexBlock = append(in.RegexBlock, r.Pattern)
			case "regex_allow":
				in.RegexAllow = append(in.RegexAllow, r.Pattern)
			case "rewrite":
				target := ""
				if r.RewriteTarget != nil {
					target = *r.RewriteTarget
				}
				in.RewriteRules = append(in.RewriteRules, dnscompile.CustomRule{RuleType: r.RuleType, Pattern: r.Pattern, RewriteTarget: target})
			}
		}
	}

	if o.Blocklists != nil {
		subs, err := o.Blocklists.List(ctx)
		if err != nil {
			return in, nil, "", fmt.Errorf("loading blocklist subscriptions: %w", err)
		}
		for _, sub := range subs {
			if !sub.Enabled {
				continue
			}
			path := filepath.Join(o.Blocklists.RuntimeDir, sub.SubscriptionID+".rpz")
			domains, err := readRPZDomains(path)
			if err != nil {
				continue // not yet pulled, or a stale/removed file -- not a hard error
			}
			for _, d := range domains {
				blockedSet[d] = true
			}
		}
	}
	for d := range blockedSet {
		if !allowedSet[d] {
			in.BlockedDomains = append(in.BlockedDomains, d)
		}
	}

	if o.Policy != nil {
		layer, err := o.Policy.Load(ctx, "global", "global")
		if err == nil {
			if layer.BlockingResponseMode != nil {
				in.BlockingResponseMode = *layer.BlockingResponseMode
			}
			if layer.CustomIPv4 != nil {
				in.CustomIPv4 = *layer.CustomIPv4
			}
			if layer.CustomIPv6 != nil {
				in.CustomIPv6 = *layer.CustomIPv6
			}
		}
	}

	if o.DNSTransports != nil {
		settings, err := o.DNSTransports.Get(ctx)
		if err == nil {
			in.Transports = dnscompile.TransportSettings{
				DotEnabled: settings.DotEnabled, DotPort: settings.DotPort,
				DohEnabled: settings.DohEnabled, DohPort: settings.DohPort, DohPath: settings.DohPath,
				DoqEnabled: settings.DoqEnabled, DoqPort: settings.DoqPort,
			}
		}
	}

	var bindForwarders []string
	var bindTLSHostname string
	var allProfiles []upstreams.Profile
	if o.Upstreams != nil {
		profiles, _, err := o.Upstreams.List(ctx)
		if err != nil {
			return in, nil, "", fmt.Errorf("loading upstream profiles: %w", err)
		}
		allProfiles = profiles
		for _, p := range profiles {
			if !p.Enabled || len(p.Endpoints) == 0 {
				continue
			}
			endpoints := make([]dnscompile.UpstreamEndpoint, len(p.Endpoints))
			for i, ep := range p.Endpoints {
				var tlsHost, dohPath string
				if ep.TLSHostname != nil {
					tlsHost = *ep.TLSHostname
				}
				if ep.DohPath != nil {
					dohPath = *ep.DohPath
				}
				endpoints[i] = dnscompile.UpstreamEndpoint{Address: ep.Address, TLSHostname: tlsHost, DohPath: dohPath}
			}
			in.DefaultProfile = &dnscompile.UpstreamProfile{Transport: p.Transport, Strategy: p.Strategy, Endpoints: endpoints}
			if p.Transport == "plain" {
				for _, ep := range endpoints {
					bindForwarders = append(bindForwarders, ep.Address)
				}
			} else if p.Transport == "dot" && len(endpoints) > 0 {
				bindTLSHostname = endpoints[0].TLSHostname
				for _, ep := range endpoints {
					bindForwarders = append(bindForwarders, ep.Address)
				}
			}
			break // first enabled profile only -- see package doc comment
		}
	}

	if o.DomainRouting != nil {
		rules, err := o.DomainRouting.List(ctx)
		if err != nil {
			return in, nil, "", fmt.Errorf("loading domain routing rules: %w", err)
		}
		if len(rules) > 0 {
			byID := make(map[string]upstreams.Profile, len(allProfiles))
			for _, p := range allProfiles {
				byID[p.UpstreamProfileID] = p
			}
			for _, r := range rules {
				p, ok := byID[r.UpstreamProfileID]
				if !ok || len(p.Endpoints) == 0 {
					// The rule's own referenced profile was deleted or
					// has no endpoints since the rule was created --
					// same "not a hard error" honesty as an unreadable
					// blocklist runtime file above: skip this one rule
					// rather than fail the whole compile over stale
					// state a later profile edit can still fix.
					continue
				}
				endpoints := make([]dnscompile.UpstreamEndpoint, len(p.Endpoints))
				for i, ep := range p.Endpoints {
					var tlsHost, dohPath string
					if ep.TLSHostname != nil {
						tlsHost = *ep.TLSHostname
					}
					if ep.DohPath != nil {
						dohPath = *ep.DohPath
					}
					endpoints[i] = dnscompile.UpstreamEndpoint{Address: ep.Address, TLSHostname: tlsHost, DohPath: dohPath}
				}
				in.DomainRoutes = append(in.DomainRoutes, dnscompile.DomainRoute{
					MatchKind: r.MatchKind, Domain: r.Domain, ProfileID: r.UpstreamProfileID,
					Profile: dnscompile.UpstreamProfile{Transport: p.Transport, Strategy: p.Strategy, Endpoints: endpoints},
				})
			}
		}
	}

	if o.Clients != nil {
		active, err := o.Clients.AllActiveClientIdentities(ctx)
		if err != nil {
			return in, nil, "", fmt.Errorf("loading active Strong ClientID identities: %w", err)
		}
		overridesAdded := map[string]bool{}
		for _, a := range active {
			if !a.ClientEnabled {
				continue // a disabled client's identities are never compiled into the live runtime
			}
			key := fmt.Sprintf("client-%d", a.ClientID)
			in.ClientIdentities = append(in.ClientIdentities, dnscompile.ClientIdentity{ClientKey: key, Hex: a.Value})
			// A client with multiple active identities appears as
			// multiple rows here, each carrying the same overrides
			// (internal/clients.AllActiveClientIdentities' own doc
			// comment) -- add them once per client, not once per row.
			if !overridesAdded[key] {
				overridesAdded[key] = true
				for _, ov := range a.Overrides {
					in.ClientOverrides = append(in.ClientOverrides, dnscompile.ClientOverride{ClientKey: key, Kind: ov.OverrideType, Domain: ov.Pattern})
				}
			}
		}
	}

	return in, bindForwarders, bindTLSHostname, nil
}

func readRPZDomains(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		domain := strings.Fields(line)[0]
		domains = append(domains, strings.ToLower(domain))
	}
	return domains, nil
}
