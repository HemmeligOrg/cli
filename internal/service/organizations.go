package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/HemmeligOrg/hemmelig-cli/internal/api"
)

// Organization is an organization of the signed-in user.
type Organization struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Plan     string `json:"plan"`
	Role     string `json:"role"`
	JoinedAt string `json:"joinedAt"`
}

// ListOrganizations lists the organizations of the signed-in user. The
// server also adds the user to organizations of a verified email domain.
func (s *Service) ListOrganizations(ctx context.Context) ([]Organization, error) {
	var orgs []Organization
	if err := s.API.Get(ctx, "/api/organizations", nil, &orgs); err != nil {
		return nil, err
	}
	if orgs == nil {
		orgs = []Organization{}
	}
	return orgs, nil
}

// FindOrganization returns the organization with this ID or slug. A slug can
// start with @, as in the organization links.
func (s *Service) FindOrganization(ctx context.Context, ref string) (*Organization, error) {
	orgs, err := s.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	slug := strings.TrimPrefix(strings.ToLower(ref), "@")
	for i := range orgs {
		if orgs[i].ID == ref || orgs[i].Slug == slug {
			return &orgs[i], nil
		}
	}
	return nil, fmt.Errorf("you are not a member of the organization %q", ref)
}

// Member is a member of an organization.
type Member struct {
	MembershipID     string `json:"membershipId"`
	UserID           string `json:"userId"`
	Username         string `json:"username"`
	Email            string `json:"email"`
	Role             string `json:"role"`
	JoinedAt         string `json:"joinedAt"`
	TwoFactorEnabled bool   `json:"twoFactorEnabled"`
	HasPasskey       bool   `json:"hasPasskey"`
}

// ListMembers lists the members of an organization.
func (s *Service) ListMembers(ctx context.Context, orgRef string) ([]Member, error) {
	org, err := s.FindOrganization(ctx, orgRef)
	if err != nil {
		return nil, err
	}
	var members []Member
	if err := s.API.Get(ctx, "/api/organizations/"+url.PathEscape(org.ID)+"/members", nil, &members); err != nil {
		return nil, err
	}
	if members == nil {
		members = []Member{}
	}
	return members, nil
}

// AuditCategories are the filters of an audit log.
var AuditCategories = []string{"secrets", "people", "settings", "keys"}

// AuditEntry is one entry of an audit log. It holds metadata only.
type AuditEntry struct {
	ID         string         `json:"id"`
	Action     string         `json:"action"`
	TargetType string         `json:"targetType"`
	TargetID   string         `json:"targetId"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  string         `json:"createdAt"`
	Actor      *struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"actor"`
	Organization *struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"organization"`
}

// AuditList is one page of an audit log.
type AuditList struct {
	Data []AuditEntry `json:"data"`
	Meta Page         `json:"meta"`
}

// auditPath returns the audit log of the instance for "", or of the organization.
func (s *Service) auditPath(ctx context.Context, orgRef string) (string, error) {
	if orgRef == "" {
		return "/api/audit", nil
	}
	org, err := s.FindOrganization(ctx, orgRef)
	if err != nil {
		return "", err
	}
	return "/api/organizations/" + url.PathEscape(org.ID) + "/audit", nil
}

func auditQuery(category string) (url.Values, error) {
	query := url.Values{}
	if category == "" {
		return query, nil
	}
	if !slices.Contains(AuditCategories, category) {
		return nil, fmt.Errorf("invalid category %q: use one of %s", category, strings.Join(AuditCategories, ", "))
	}
	query.Set("category", category)
	return query, nil
}

// ListAudit lists the audit log of the instance (orgRef "", admins only) or of
// an organization (owners and admins).
func (s *Service) ListAudit(ctx context.Context, orgRef, category string, page, limit int) (*AuditList, error) {
	path, err := s.auditPath(ctx, orgRef)
	if err != nil {
		return nil, err
	}
	query, err := auditQuery(category)
	if err != nil {
		return nil, err
	}
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var list AuditList
	if err := s.API.Get(ctx, path, query, &list); err != nil {
		return nil, adminError(err)
	}
	if list.Data == nil {
		list.Data = []AuditEntry{}
	}
	return &list, nil
}

// ExportAudit returns the audit log as CSV, with at most 10,000 entries.
func (s *Service) ExportAudit(ctx context.Context, orgRef, category string) ([]byte, error) {
	path, err := s.auditPath(ctx, orgRef)
	if err != nil {
		return nil, err
	}
	query, err := auditQuery(category)
	if err != nil {
		return nil, err
	}
	query.Set("format", "csv")
	resp, err := s.API.Raw(ctx, api.Request{Method: http.MethodGet, Path: path, Query: query})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, adminError(&api.Error{Status: resp.Status, Message: "the audit export failed"})
	}
	return data, nil
}

// OrgDomain is an email domain whose users join the organization.
type OrgDomain struct {
	ID         string  `json:"id"`
	Domain     string  `json:"domain"`
	Verified   bool    `json:"verified"`
	VerifiedAt *string `json:"verifiedAt"`
	Record     struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"record"`
}

func (s *Service) domainsPath(ctx context.Context, orgRef string) (string, error) {
	org, err := s.FindOrganization(ctx, orgRef)
	if err != nil {
		return "", err
	}
	return "/api/organizations/" + url.PathEscape(org.ID) + "/domains", nil
}

// sessionOnly explains a 403 from a route that accepts only a session.
func sessionOnly(err error) error {
	if api.StatusOf(err) == http.StatusForbidden && api.CodeOf(err) == "" {
		return errors.Join(ErrSessionRequired, err)
	}
	return err
}

// ListDomains lists the email domains of an organization. It needs a session.
func (s *Service) ListDomains(ctx context.Context, orgRef string) ([]OrgDomain, error) {
	path, err := s.domainsPath(ctx, orgRef)
	if err != nil {
		return nil, err
	}
	var body struct {
		Domains []OrgDomain `json:"domains"`
	}
	if err := s.API.Get(ctx, path, nil, &body); err != nil {
		return nil, sessionOnly(err)
	}
	if body.Domains == nil {
		body.Domains = []OrgDomain{}
	}
	return body.Domains, nil
}

// AddDomain adds an email domain. Verify it with the TXT record in the result.
func (s *Service) AddDomain(ctx context.Context, orgRef, domain string) (*OrgDomain, error) {
	path, err := s.domainsPath(ctx, orgRef)
	if err != nil {
		return nil, err
	}
	var created OrgDomain
	if err := s.API.Send(ctx, http.MethodPost, path, map[string]string{"domain": domain}, &created); err != nil {
		return nil, sessionOnly(err)
	}
	return &created, nil
}

func (s *Service) findDomain(ctx context.Context, orgRef, domain string) (string, *OrgDomain, error) {
	path, err := s.domainsPath(ctx, orgRef)
	if err != nil {
		return "", nil, err
	}
	var body struct {
		Domains []OrgDomain `json:"domains"`
	}
	if err := s.API.Get(ctx, path, nil, &body); err != nil {
		return "", nil, sessionOnly(err)
	}
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	for i := range body.Domains {
		if body.Domains[i].Domain == want || body.Domains[i].ID == domain {
			return path, &body.Domains[i], nil
		}
	}
	return "", nil, &api.Error{Status: http.StatusNotFound, Message: fmt.Sprintf("the organization has no domain %q", domain)}
}

// VerifyDomain checks the DNS TXT record of a domain.
func (s *Service) VerifyDomain(ctx context.Context, orgRef, domain string) (*OrgDomain, error) {
	path, row, err := s.findDomain(ctx, orgRef, domain)
	if err != nil {
		return nil, err
	}
	var verified OrgDomain
	if err := s.API.Send(ctx, http.MethodPost, path+"/"+url.PathEscape(row.ID)+"/verify", nil, &verified); err != nil {
		return nil, sessionOnly(err)
	}
	return &verified, nil
}

// RemoveDomain removes a domain. The current members stay.
func (s *Service) RemoveDomain(ctx context.Context, orgRef, domain string) error {
	path, row, err := s.findDomain(ctx, orgRef, domain)
	if err != nil {
		return err
	}
	err = s.API.Do(ctx, api.Request{Method: http.MethodDelete, Path: path + "/" + url.PathEscape(row.ID)}, nil)
	return sessionOnly(err)
}
