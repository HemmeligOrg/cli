package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/HemmeligOrg/hemmelig-cli/internal/service"
)

func (a *app) inboxCommand(args []string) error {
	return a.group("inbox", "Send encrypted messages to the inbox of an organization.", args, []subcommand{
		{"send", "Encrypt a message for an organization inbox and send it", a.inboxSend},
	})
}

func (a *app) inboxSend(args []string) error {
	fs := newFlagSet("hemmelig inbox send <org|link> [text|-] [flags]",
		"Encrypt a message with the public key of an organization inbox and send it. Only the organization can decrypt it. Without text, the CLI reads stdin. Sending needs no account. Files need an API key or a session.",
		`hemmelig inbox send acme "The new API key is ..." --subject "API key"`,
		`cat credentials.env | hemmelig inbox send https://hemmelig.app/@acme/inbox --from "Kari, Vendor AS"`,
		`hemmelig inbox send acme "See the file" --file ./backup-codes.txt`)
	subject := fs.String("subject", "s", "", "text", "Subject of the message")
	from := fs.String("from", "", "", "text", "Your name or contact. Only the organization sees it")
	files := fs.List("file", "f", "path", "Attach a file, at most 10. Files need an API key or a session")
	if done, err := a.parse(fs, args); done || err != nil {
		return err
	}
	if len(fs.Args()) == 0 {
		return usagef("give the organization: its slug or its inbox link")
	}
	if len(fs.Args()) > 2 {
		return usagef("give the message as one argument, in quotes")
	}
	text, _, err := a.readInput(fs.Args()[1:])
	if err != nil {
		return err
	}
	inputs := make([]service.FileInput, 0, len(*files))
	for _, path := range *files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		inputs = append(inputs, service.FileInput{Name: filepath.Base(path), Data: data})
	}
	if text == "" {
		if len(inputs) == 0 {
			return usagef("no message given: pass the text as an argument or pipe it to stdin")
		}
		text = fmt.Sprintf("%d attached files", len(inputs))
	}

	svc, _, err := a.service()
	if err != nil {
		return err
	}
	result, err := svc.SendInboxMessage(a.ctx, service.InboxSendInput{
		Inbox:   fs.Args()[0],
		Subject: *subject,
		Message: text,
		From:    *from,
		Files:   inputs,
	})
	if err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Delivered the message to %s. Only %s can read it.", result.Organization, result.Organization), result)
}
