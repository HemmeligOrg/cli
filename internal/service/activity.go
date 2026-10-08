package service

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// MaxBurnIDs is the most secrets in one burn request.
const MaxBurnIDs = 500

// BurnSecrets deletes secrets of the signed-in user at once. Without IDs, it
// deletes all active secrets of the user. It returns the number of deleted
// secrets.
func (s *Service) BurnSecrets(ctx context.Context, ids []string, all bool) (int, error) {
	if all == (len(ids) > 0) {
		return 0, errors.New("give secret IDs or all, not both and not neither")
	}
	if len(ids) > MaxBurnIDs {
		return 0, errors.New("burn at most 500 secrets at once")
	}
	body := map[string]any{"all": true}
	if !all {
		refs := make([]string, 0, len(ids))
		for _, value := range ids {
			ref, err := parseSecretRef(value)
			if err != nil {
				return 0, err
			}
			refs = append(refs, ref.ID)
		}
		body = map[string]any{"ids": refs}
	}
	var result struct {
		Deleted int `json:"deleted"`
	}
	if err := s.API.Send(ctx, http.MethodPost, "/api/secrets/bulk-delete", body, &result); err != nil {
		return 0, err
	}
	return result.Deleted, nil
}

// Activity is one entry of the view receipts of the signed-in user.
type Activity struct {
	ID             string `json:"id"`
	Action         string `json:"action"`
	SecretID       string `json:"secretId"`
	CreatedAt      string `json:"createdAt"`
	ViewsRemaining *int   `json:"viewsRemaining"`
	// Count is the number of secrets in a bulk burn.
	Count *int `json:"count"`
	// Viewer is set for organization secrets and for secrets with recipients.
	Viewer       string `json:"viewer"`
	Organization string `json:"organization"`
	IsOwnAction  bool   `json:"isOwnAction"`
}

// ActivityList is one page of view receipts.
type ActivityList struct {
	Data []Activity `json:"data"`
	Meta Page       `json:"meta"`
}

// ListActivity lists when the secrets of the signed-in user were opened,
// burned or deleted. The receipts stay after the secrets are gone.
func (s *Service) ListActivity(ctx context.Context, page, limit int) (*ActivityList, error) {
	query := url.Values{}
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var list ActivityList
	if err := s.API.Get(ctx, "/api/secrets/activity", query, &list); err != nil {
		return nil, err
	}
	if list.Data == nil {
		list.Data = []Activity{}
	}
	return &list, nil
}
