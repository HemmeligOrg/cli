package service

import (
	"context"
	"fmt"
	"strings"
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
