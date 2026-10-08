package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/HemmeligOrg/hemmelig-cli/internal/service"
)

func (a *app) orgsCommand(args []string) error {
	return a.group("orgs", "Your organizations. An <org> is the slug or the ID of an organization.", args, []subcommand{
		{"list", "List your organizations", a.orgsList},
		{"members", "List the members of an organization", a.orgsMembers},
		{"audit", "Show or export the audit log of an organization", a.orgsAudit},
		{"domains", "Email domains whose users join the organization", a.orgsDomains},
	})
}

func (a *app) orgsList(args []string) error {
	fs := newFlagSet("hemmelig orgs list [flags]", "List your organizations. Opening the list also adds you to the organizations of your verified email domain.",
		`hemmelig orgs list`, `hemmelig orgs list --json`)
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	svc, _, err := a.service()
	if err != nil {
		return err
	}
	orgs, err := svc.ListOrganizations(a.ctx)
	if err != nil {
		return err
	}
	return a.output(orgs, func() {
		rows := [][]string{}
		for _, org := range orgs {
			rows = append(rows, []string{org.Slug, org.Name, org.Role, org.ID})
		}
		a.table([]string{"SLUG", "NAME", "ROLE", "ID"}, rows)
	})
}

func (a *app) orgsMembers(args []string) error {
	fs := newFlagSet("hemmelig orgs members <org> [flags]", "List the members of an organization.",
		`hemmelig orgs members acme`)
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usagef("give one organization")
	}
	svc, _, err := a.service()
	if err != nil {
		return err
	}
	members, err := svc.ListMembers(a.ctx, fs.Args()[0])
	if err != nil {
		return err
	}
	return a.output(members, func() {
		rows := [][]string{}
		for _, member := range members {
			second := "-"
			switch {
			case member.TwoFactorEnabled && member.HasPasskey:
				second = "2fa,passkey"
			case member.TwoFactorEnabled:
				second = "2fa"
			case member.HasPasskey:
				second = "passkey"
			}
			rows = append(rows, []string{member.Username, member.Email, member.Role, second, shortTime(member.JoinedAt)})
		}
		a.table([]string{"USERNAME", "EMAIL", "ROLE", "2FA", "JOINED"}, rows)
	})
}

// auditCommand shows or exports the audit log of the instance (org "") or of an organization.
func (a *app) auditCommand(fs *flagSet, args []string, needsOrg bool) error {
	category := fs.String("category", "c", "", "name", "Show one category: "+strings.Join(service.AuditCategories, ", "))
	csv := fs.String("csv", "", "", "file", "Write the log as CSV to this file, or - for stdout. The export has at most 10,000 entries")
	page := fs.Int("page", "", 1, "number", "Page number")
	limit := fs.Int("limit", "", 20, "number", "Entries per page, up to 100")
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	org := ""
	switch {
	case needsOrg && len(fs.Args()) != 1:
		return usagef("give one organization")
	case needsOrg:
		org = fs.Args()[0]
	case len(fs.Args()) > 0:
		return usagef("unexpected argument %q", fs.Args()[0])
	}
	svc, _, err := a.service()
	if err != nil {
		return err
	}
	if *csv != "" {
		data, err := svc.ExportAudit(a.ctx, org, *category)
		if err != nil {
			return err
		}
		if *csv == "-" {
			_, err = a.stdout.Write(data)
			return err
		}
		if err := os.WriteFile(*csv, data, 0o600); err != nil {
			return err
		}
		return a.done("Wrote the audit log to "+*csv+".", map[string]string{"path": *csv})
	}
	list, err := svc.ListAudit(a.ctx, org, *category, *page, *limit)
	if err != nil {
		return err
	}
	return a.output(list, func() {
		rows := [][]string{}
		for _, entry := range list.Data {
			actor := "-"
			if entry.Actor != nil {
				actor = entry.Actor.Username
			}
			target := "-"
			if entry.TargetType != "" {
				target = entry.TargetType
				if entry.TargetID != "" {
					target += ":" + entry.TargetID
				}
			}
			rows = append(rows, []string{shortTime(entry.CreatedAt), entry.Action, actor, target})
		}
		a.table([]string{"TIME", "ACTION", "ACTOR", "TARGET"}, rows)
		a.info("Page %d of %d, %d entries in total.", list.Meta.Page, max(list.Meta.TotalPages, 1), list.Meta.Total)
	})
}

func (a *app) orgsAudit(args []string) error {
	fs := newFlagSet("hemmelig orgs audit <org> [flags]",
		"Show the audit log of an organization. Owners and admins can read it. Entries hold metadata only, never secret content.",
		`hemmelig orgs audit acme --category people`,
		`hemmelig orgs audit acme --csv audit.csv`)
	return a.auditCommand(fs, args, true)
}

func (a *app) orgsDomains(args []string) error {
	return a.group("orgs domains",
		"People with a verified email address at a verified domain join the organization. These commands need a session from hemmelig login.",
		args, []subcommand{
			{"list", "List the domains and their DNS records", a.orgsDomainsList},
			{"add", "Add a domain and print its DNS TXT record", a.orgsDomainsAdd},
			{"verify", "Check the DNS TXT record of a domain", a.orgsDomainsVerify},
			{"remove", "Remove a domain. The current members stay", a.orgsDomainsRemove},
		})
}

func (a *app) printDomain(domain *service.OrgDomain) {
	if domain.Verified {
		fmt.Fprintf(a.stdout, "%s is verified.\n", domain.Domain)
		return
	}
	fmt.Fprintf(a.stdout, "Add this DNS record, then run hemmelig orgs domains verify:\n  Type:  TXT\n  Name:  %s\n  Value: %s\n", domain.Record.Name, domain.Record.Value)
}

func (a *app) orgsDomainsList(args []string) error {
	fs := newFlagSet("hemmelig orgs domains list <org> [flags]", "List the email domains of an organization.",
		`hemmelig orgs domains list acme`)
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usagef("give one organization")
	}
	svc, _, err := a.sessionService()
	if err != nil {
		return err
	}
	domains, err := svc.ListDomains(a.ctx, fs.Args()[0])
	if err != nil {
		return err
	}
	return a.output(domains, func() {
		rows := [][]string{}
		for _, domain := range domains {
			status := "verified"
			record := "-"
			if !domain.Verified {
				status = "not verified"
				record = domain.Record.Name + " TXT " + domain.Record.Value
			}
			rows = append(rows, []string{domain.Domain, status, record})
		}
		a.table([]string{"DOMAIN", "STATUS", "DNS RECORD"}, rows)
	})
}

func (a *app) orgsDomainsAdd(args []string) error {
	fs := newFlagSet("hemmelig orgs domains add <org> <domain> [flags]", "Add an email domain and print the DNS TXT record that proves control of it.",
		`hemmelig orgs domains add acme example.com`)
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	if len(fs.Args()) != 2 {
		return usagef("give an organization and a domain")
	}
	svc, _, err := a.sessionService()
	if err != nil {
		return err
	}
	domain, err := svc.AddDomain(a.ctx, fs.Args()[0], fs.Args()[1])
	if err != nil {
		return err
	}
	return a.output(domain, func() { a.printDomain(domain) })
}

func (a *app) orgsDomainsVerify(args []string) error {
	fs := newFlagSet("hemmelig orgs domains verify <org> <domain> [flags]", "Check the DNS TXT record of a domain. DNS changes can take some time.",
		`hemmelig orgs domains verify acme example.com`)
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	if len(fs.Args()) != 2 {
		return usagef("give an organization and a domain")
	}
	svc, _, err := a.sessionService()
	if err != nil {
		return err
	}
	domain, err := svc.VerifyDomain(a.ctx, fs.Args()[0], fs.Args()[1])
	if err != nil {
		return err
	}
	return a.output(domain, func() { a.printDomain(domain) })
}

func (a *app) orgsDomainsRemove(args []string) error {
	fs := newFlagSet("hemmelig orgs domains remove <org> <domain> [flags]", "Remove an email domain. New users stop joining. The current members stay.",
		`hemmelig orgs domains remove acme example.com`)
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	if len(fs.Args()) != 2 {
		return usagef("give an organization and a domain")
	}
	svc, _, err := a.sessionService()
	if err != nil {
		return err
	}
	if err := svc.RemoveDomain(a.ctx, fs.Args()[0], fs.Args()[1]); err != nil {
		return err
	}
	return a.done("Removed the domain.", map[string]bool{"removed": true})
}
