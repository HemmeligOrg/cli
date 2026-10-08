package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/HemmeligOrg/cli/v2/internal/api"
	"github.com/HemmeligOrg/cli/v2/internal/hcrypto"
	"github.com/HemmeligOrg/cli/v2/internal/links"
)

// The server limits for inbox messages.
const (
	maxInboxCiphertext = 200_000
	MaxInboxFiles      = 10
)

var slugPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// InboxSendInput is a message for the encrypted inbox of an organization.
type InboxSendInput struct {
	// Inbox is the slug of the organization, @slug, or the inbox link
	// https://host/@slug/inbox.
	Inbox   string
	Subject string
	Message string
	// From is an optional name or contact. Only the organization sees it.
	From  string
	Files []FileInput
}

// InboxSendResult is a delivered message.
type InboxSendResult struct {
	ID           string   `json:"id"`
	Organization string   `json:"organization"`
	Files        []string `json:"files"`
}

type inboxInfo struct {
	Organization struct {
		Slug        string `json:"slug"`
		DisplayName string `json:"displayName"`
	} `json:"organization"`
	PublicKey        string `json:"publicKey"`
	AllowFileUploads bool   `json:"allowFileUploads"`
}

type inboxAttachment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int    `json:"size"`
}

// inboxPayload is the plaintext of a message. The web app reads the same
// fields after it decrypts the message.
type inboxPayload struct {
	Subject  string            `json:"subject"`
	Message  string            `json:"message"`
	From     string            `json:"from"`
	FileKey  string            `json:"fileKey,omitempty"`
	FileSalt string            `json:"fileSalt,omitempty"`
	Files    []inboxAttachment `json:"files,omitempty"`
}

// parseInboxRef returns the base URL of a link, or "", and the slug.
func parseInboxRef(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			return "", "", fmt.Errorf("invalid inbox link %q", value)
		}
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for i, segment := range segments {
			if strings.HasPrefix(segment, "@") {
				base, err := links.NormalizeBaseURL(parsed.Scheme + "://" + parsed.Host + "/" + strings.Join(segments[:i], "/"))
				if err != nil {
					return "", "", err
				}
				return parseSlug(base, segment)
			}
		}
		return "", "", fmt.Errorf("invalid inbox link %q: use https://host/@<org>/inbox", value)
	}
	return parseSlug("", value)
}

func parseSlug(base, value string) (string, string, error) {
	slug := strings.ToLower(strings.TrimPrefix(value, "@"))
	if !slugPattern.MatchString(slug) {
		return "", "", fmt.Errorf("invalid organization %q", value)
	}
	return base, slug, nil
}

// SendInboxMessage encrypts a message with the public key of the inbox and
// delivers it. Attachments need an API key or a session, as in the web app.
func (s *Service) SendInboxMessage(ctx context.Context, in InboxSendInput) (*InboxSendResult, error) {
	if strings.TrimSpace(in.Message) == "" {
		return nil, errors.New("the message is empty")
	}
	if len(in.Files) > MaxInboxFiles {
		return nil, fmt.Errorf("a message can have at most %d files", MaxInboxFiles)
	}
	base, slug, err := parseInboxRef(in.Inbox)
	if err != nil {
		return nil, err
	}
	client := s.clientFor(base)
	path := "/api/inbox/" + url.PathEscape(slug)

	var info inboxInfo
	if err := client.Get(ctx, path, nil, &info); err != nil {
		if api.StatusOf(err) == http.StatusNotFound {
			return nil, fmt.Errorf("the organization %q has no inbox, or the inbox is off (%w)", slug, err)
		}
		return nil, err
	}
	recipient, err := hcrypto.ParseInboxPublicKey(info.PublicKey)
	if err != nil {
		return nil, err
	}

	payload := inboxPayload{Subject: in.Subject, Message: in.Message, From: in.From}
	attached := []attachedFile{}
	names := []string{}
	if len(in.Files) > 0 {
		if client != s.API {
			return nil, errors.New("attachments work only for the configured instance: set --url to the instance of the inbox")
		}
		if !info.AllowFileUploads {
			return nil, errors.New("this inbox does not accept files")
		}
		// The browser encrypts each file with a random key. The key travels
		// only inside the encrypted message.
		if payload.FileKey, err = hcrypto.GenerateKey(); err != nil {
			return nil, err
		}
		if payload.FileSalt, err = hcrypto.GenerateSalt(); err != nil {
			return nil, err
		}
		cipher, err := hcrypto.NewCipher(payload.FileKey, payload.FileSalt)
		if err != nil {
			return nil, err
		}
		for _, file := range in.Files {
			uploaded, err := s.uploadFile(ctx, cipher, file)
			if err != nil {
				return nil, fmt.Errorf("upload %s: %w", file.Name, err)
			}
			attached = append(attached, uploaded)
			names = append(names, file.Name)
			payload.Files = append(payload.Files, inboxAttachment{ID: uploaded.ID, Name: file.Name, Size: len(file.Data)})
		}
	}

	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	envelope, err := hcrypto.EncryptForInbox(recipient, plain)
	if err != nil {
		return nil, err
	}
	if len(envelope.Ciphertext) > maxInboxCiphertext {
		return nil, errors.New("the message is too long: send long text as a file")
	}

	body := map[string]any{
		"ephemeralPublicKey": envelope.EphemeralPublicKey,
		"hkdfSalt":           envelope.HKDFSalt,
		"iv":                 envelope.IV,
		"ciphertext":         envelope.Ciphertext,
	}
	if len(attached) > 0 {
		body["files"] = attached
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := client.Send(ctx, http.MethodPost, path+"/messages", body, &created); err != nil {
		return nil, err
	}
	return &InboxSendResult{ID: created.ID, Organization: info.Organization.DisplayName, Files: names}, nil
}
