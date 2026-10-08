# Hemmelig CLI

The `hemmelig` CLI gives you the full Hemmelig app in the terminal. You can create, read and burn secrets, send messages to an organization inbox, manage organizations, your account and an instance. The CLI also runs a local MCP server for AI assistants. See [MCP server](mcp.md).

Version 2 of the CLI works with Hemmelig 7.

The CLI encrypts and decrypts on your machine. The server gets only ciphertext. The decryption key stays in the URL fragment, and browsers and the CLI never send the fragment to the server.

```
 _   _                               _ _
| | | | ___ _ __ ___  _ __ ___   ___| (_) __ _
| |_| |/ _ \ '_ ` _ \| '_ ` _ \ / _ \ | |/ _` |
|  _  |  __/ | | | | | | | | | |  __/ | | (_| |
|_| |_|\___|_| |_| |_|_| |_| |_|\___|_|_|\__, |
                                         |___/
```

## Install

Download the binary for your platform from the [releases](https://github.com/HemmeligOrg/hemmelig-cli/releases). The files are `hemmelig-linux-amd64`, `hemmelig-linux-arm64`, `hemmelig-darwin-amd64`, `hemmelig-darwin-arm64` and `hemmelig-windows-amd64.exe`.

```bash
VERSION=2.0.0
PLATFORM=linux-amd64
curl -fL "https://github.com/HemmeligOrg/hemmelig-cli/releases/download/v${VERSION}/hemmelig-${PLATFORM}" -o hemmelig
chmod +x hemmelig
sudo mv hemmelig /usr/local/bin/
```

To verify the download, compare it with the checksum file of the release:

```bash
curl -fL "https://github.com/HemmeligOrg/hemmelig-cli/releases/download/v${VERSION}/checksums.txt" -o checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

On Windows, download `hemmelig-windows-amd64.exe` and put it in a folder in your `PATH`.

To install with Go 1.25 or later, run:

```bash
go install github.com/HemmeligOrg/hemmelig-cli@latest
```

The installed binary is `hemmelig-cli`. Rename it to `hemmelig`, or build from a clone with `go build -o hemmelig .`.

## Quick start

```bash
# Create a secret on hemmelig.app. The CLI prints the link.
hemmelig "db password: hunter2" --expires 1h

# Open a secret link and print the content.
hemmelig secrets get "https://hemmelig.app/s/<id>#<key>"

# Work with your own instance.
hemmelig config set url https://secrets.example.com
hemmelig login
hemmelig secrets list
```

## Authentication

Anonymous users can create and read secrets, and send inbox messages without files. All other commands need an API key or a session.

| Credential | How to get it                                                                | What it can do                                                     |
| ---------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| API key    | The web app under Account > Developer, or `hemmelig account api-keys create` | All commands with the role of its owner, except credential changes |
| Session    | `hemmelig login`                                                             | All commands                                                       |

Credential changes need a session. These commands are `account password`, `account delete`, `account 2fa enable`, `account 2fa verify`, `account 2fa disable` and `account api-keys create`. The server rejects them for an API key, so a leaked key cannot take over the account. `account 2fa status` works with an API key or a session.

### Choose the instance

The CLI uses the first URL that it finds in this order:

1. The `--url` flag. The short form is `-u`.
2. The `HEMMELIG_URL` environment variable.
3. The `url` value in the config file.
4. `https://hemmelig.app`.

```bash
hemmelig config set url https://secrets.example.com
HEMMELIG_URL=https://secrets.example.com hemmelig health
```

### Use an API key

The CLI uses the first API key that it finds in this order:

1. The `--api-key` flag.
2. The `HEMMELIG_API_KEY` environment variable.
3. The `api-key` value in the config file.

A key from the flag or the environment always wins. Without one, a session from `hemmelig login` wins over the key in the config file.

```bash
# Store a key. Without a value, the CLI asks for it without echo.
hemmelig config set api-key

# Or give the key in the environment, for example in CI.
export HEMMELIG_API_KEY=hemmelig_xxxxxxxxxxxxxxxx
hemmelig secrets list
```

The config file binds the stored key to the stored URL. The CLI does not send it to another instance.

### Sign in

```bash
hemmelig login --username jane_doe
```

The CLI asks for the password without echo. When the account has 2FA, the CLI also asks for a code from the authenticator app. To use a backup code, add `--backup-code`. To give the app code in the command, use `--code 123456`.

To sign in from a script, pipe the answers to stdin. When stdin is not a terminal, the CLI reads each answer as one line.

```bash
printf '%s\n' "$HEMMELIG_PASSWORD" | hemmelig login --username jane_doe
```

The server allows 3 sign-in attempts from one address until it sees a pause of 10 seconds. After that, `login` fails with `Too many requests`.

To see the credential that the CLI uses, run `whoami`:

```bash
hemmelig whoami
```

To end the session, run `logout`. A stored API key stays.

```bash
hemmelig logout
```

### Config file

The CLI stores its settings in `$XDG_CONFIG_HOME/hemmelig` on Linux, which is usually `~/.config/hemmelig`. On macOS, the folder is `~/Library/Application Support/hemmelig`. On Windows, the folder is `%AppData%\hemmelig`. The folder has mode `0700` and the files have mode `0600`. To use another folder, set `HEMMELIG_CONFIG_DIR`.

| File          | Content                                                        |
| ------------- | -------------------------------------------------------------- |
| `config.json` | The URL, the API key and the session                           |
| `tokens.json` | Delete tokens of secrets that you created or opened in the CLI |

```bash
hemmelig config path
hemmelig config get
hemmelig config unset api-key
```

`config get` shows only the prefix of the API key.

## Global flags

Every command accepts these flags:

| Flag           | Description                                   |
| -------------- | --------------------------------------------- |
| `-u`, `--url`  | The instance URL                              |
| `--api-key`    | The API key                                   |
| `--json`       | Print the result as JSON                      |
| `-h`, `--help` | Show the help of the command and its examples |

Put the global flags before or after the command:

```bash
hemmelig --json secrets list
hemmelig secrets list --json
```

## Secrets

### Create a secret

```bash
hemmelig secrets create "db password: hunter2" --title "Staging DB" --expires 1h --views 2
```

The CLI prints the link to stdout. Other messages go to stderr, so `LINK=$(hemmelig ...)` gets only the link. Without text, or with `-`, the CLI reads the secret from stdin:

```bash
cat .env | hemmelig secrets create --title "Staging env"
```

| Flag                | Description                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `-t`, `--title`     | A title. The CLI encrypts it with the secret                                                                        |
| `-e`, `--expires`   | `5m`, `30m`, `1h`, `4h`, `12h`, `1d`, `3d`, `7d`, `14d` or `28d`. The default is `1d`                               |
| `-v`, `--views`     | Views before the secret burns, from 1 to 9999. The default is 1                                                     |
| `--no-view-limit`   | Keep the secret until it expires, however many views. The web app calls this burn after time                        |
| `--burn-after-time` | The same as `--no-view-limit`. The web app uses this name                                                           |
| `--no-burnable`     | Send the `secret.viewed` webhook event after the last view instead of `secret.burned`. The view limit still applies |
| `-p`, `--password`  | Protect the secret with a password                                                                                  |
| `--password-prompt` | Ask for the password without echo                                                                                   |
| `--ip`              | Allow only this IP address or CIDR range, for example `203.0.113.0/24`                                              |
| `-f`, `--file`      | Attach a file. Use the flag again for more files                                                                    |
| `--to`              | Only this person can open the secret, after sign-in with a verified address. Use the flag again for more people, at most 20 |
| `--org`             | Create the secret in this organization. Give the slug or the ID. You must be a member                               |
| `--org-only`        | Only members of the organization can open the secret. Needs `--org`                                                 |
| `--release-in`      | Keep the secret closed for this time, from `1m` to `30d`, for example `2h`                                          |
| `--release-at`      | Keep the secret closed until this time, in RFC 3339, for example `2026-10-09T14:00:00Z`                             |
| `--notify`          | Email you each time someone opens the secret. Needs an API key or a session, and email delivery on the instance     |

A link without a password has the form `https://host/s/<id>#<key>`. A password-protected link has no key. Send the password on another channel. The password never goes to the server. The CLI sends only a verifier that it derives from the password.

Files need an API key or a session. The CLI encrypts the file content and the file name. It uses the chunked file format of the web app, so the web app opens the files, and the CLI opens files from the web app.

```bash
hemmelig secrets create "The deploy key is attached" --file ./id_ed25519 --password-prompt --expires 4h
```

A recipient lock keeps the secret closed for everybody else, also for a person with the full link. A denied person uses no view.

```bash
# Only Kari can open it, after she signs in.
hemmelig secrets create "prod DB password" --to kari@example.com --notify

# Only the members of the organization acme can open it, from 09:00 UTC.
hemmelig secrets create "launch code" --org acme --org-only --release-at 2026-10-09T09:00:00Z
```

The first version of the CLI had only one command. That form still works and is the same as `secrets create`:

```bash
hemmelig "my secret" -t "API key" -e 7d -v 3
echo "my secret" | hemmelig -e 1h
```

### Read a secret

```bash
hemmelig secrets get "https://hemmelig.app/s/<id>#<key>"
```

`secrets read` is the same command. The CLI prints the content to stdout, and the title and the views left to stderr. It saves attached files in the current folder.

| Flag                 | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `-k`, `--key`        | The decryption key, when the link or the ID has no key         |
| `-p`, `--password`   | The password of a protected secret                             |
| `--password-prompt`  | Ask for the password without echo                              |
| `-o`, `--output-dir` | The folder for attached files. The default is `.`              |
| `--no-files`         | Do not download the attached files                             |
| `--force`            | Overwrite files that exist                                     |
| `--raw`              | Print the content as stored. Secrets from the web app are HTML |

If you open a password-protected secret on a terminal without `--password`, the CLI asks for the password.

Opening a secret uses one view, also when the key or the password is wrong. When a secret has no views left, `get` exits with code 4.

A scheduled secret stays closed until its release time. `get` then prints the release time, exits with code 1 and uses no view.

A locked secret needs the account of a recipient. Set the API key of that account, or run `hemmelig login`. Without the right account, `get` exits with code 3 and uses no view.

The CLI saves each file with its base name only, and with mode `0600`. A file name from the sender cannot write outside the folder.

The CLI converts web app secrets from HTML to plain text. To get the HTML, add `--raw`.

### List your secrets

```bash
hemmelig secrets list --page 1 --limit 20
```

The server stores only metadata, so the list shows no content and no titles. The `OPTIONS` column shows `password`, `ip:<range>`, `files:<n>`, `locked:org` or `locked:emails`, `opens:<time>`, `notify` and `opened:<n>`.

### View receipts

```bash
hemmelig secrets activity --limit 50
```

The receipts show when your secrets were opened, burned or deleted. They stay after the secrets are gone. The viewer name shows only for organization secrets and for secrets with recipients.

### Burn many secrets

```bash
# Burn some secrets.
hemmelig secrets burn 3uSXycrFyYfP X9fTq2LmPo0a

# Burn all your active secrets. The CLI asks for confirmation. Add --yes to skip it.
hemmelig secrets burn --all
```

A burned secret is gone for everyone. The view receipts stay.

### Delete a secret

```bash
hemmelig secrets delete 3f0c2a4e-6f1b-4c1d-9a55-0a4c8f1e2b7d
```

You can delete a secret when one of these is true:

- You own the secret, and the CLI uses your API key or your session.
- You created the secret with the CLI. The server returns a delete token, and the CLI stores it in `tokens.json`.
- You opened the secret with the CLI. The server returns a delete token after each reveal.

The CLI removes delete tokens after 30 days, because no secret lives longer than 28 days.

## Organizations

An `<org>` is the slug of an organization, for example `acme` or `@acme`, or its ID.

```bash
# List your organizations and your role.
hemmelig orgs list

# List the members, with their 2FA and passkey status.
hemmelig orgs members acme

# Show the audit log. Owners and admins can read it.
hemmelig orgs audit acme --category people
hemmelig orgs audit acme --csv audit.csv
```

| Flag of `audit`    | Description                                                                         |
| ------------------ | ----------------------------------------------------------------------------------- |
| `-c`, `--category` | `secrets`, `people`, `settings` or `keys`                                           |
| `--csv`            | Write the log as CSV to a file, or `-` for stdout. The export has at most 10,000 entries |
| `--page`, `--limit` | The page, and the entries per page up to 100                                       |

### Email domains

People with a verified email address at a verified domain join the organization as members. A DNS TXT record proves that the organization controls the domain. The domain commands need a session from `hemmelig login`, because the server does not accept API keys for them.

```bash
# Add a domain. The CLI prints the TXT record to add at your DNS provider.
hemmelig orgs domains add acme example.com

# Check the record. DNS changes can take some time.
hemmelig orgs domains verify acme example.com

hemmelig orgs domains list acme
hemmelig orgs domains remove acme example.com
```

When you remove a domain, the current members stay. A member that an admin removes does not join again.

## Encrypted inbox

An organization inbox takes messages from anyone. The CLI encrypts the message with the public key of the inbox. Only the organization can decrypt it, with its passphrase.

```bash
hemmelig inbox send acme "The new API key is ..." --subject "API key" --from "Kari, Vendor AS"

# Read the message from stdin, and send to the inbox of another instance.
cat credentials.env | hemmelig inbox send https://secrets.example.com/@acme/inbox

# Attach files. Files need an API key or a session on the instance of the inbox.
hemmelig inbox send acme "See the file" --file ./backup-codes.txt
```

| Flag             | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `-s`, `--subject` | The subject. The CLI encrypts it with the message       |
| `--from`         | Your name or contact. Only the organization sees it      |
| `-f`, `--file`   | Attach a file, at most 10                                |

## Account

```bash
hemmelig account show
hemmelig account update --email jane@example.com
```

With an API key, `account show` returns the username and the email. With a session, it also returns the role and the 2FA state.

These commands need a session from `hemmelig login`:

```bash
# Change the password. The CLI asks for the current and the new password.
hemmelig account password

# Delete the account and all its secrets. Add --yes to skip the question.
hemmelig account delete
```

### Two-factor authentication

```bash
hemmelig account 2fa status
hemmelig account 2fa enable
hemmelig account 2fa disable
```

`enable` asks for the account password. Then it prints the setup URI and the backup codes. Add the URI to your authenticator app and keep the backup codes in a safe place. Then type a code from the app to finish the setup.

To finish the setup later, add `--no-verify`. Then run `verify` with a code from the app:

```bash
hemmelig account 2fa enable --no-verify --json
hemmelig account 2fa verify 123456
```

The server replaces the session when 2FA changes. The CLI stores the new session.

### API keys

```bash
hemmelig account api-keys list
hemmelig account api-keys create --name "CI deploy" --expires-in-days 90
hemmelig account api-keys revoke <id>
```

`create` needs a session. It prints the key once. To store the key in the config file, add `--save`. A user can have 5 keys.

## Administration

The `admin` commands need an admin account. With the key or the session of a normal user, they exit with code 3.

### Users

A `<user>` is a user ID, a username or an email.

```bash
hemmelig admin users list --search example.com
hemmelig admin users create --username jane_doe --email jane@example.com --role admin
hemmelig admin users update jane_doe --role user --email jane.doe@example.com
hemmelig admin users ban jane_doe --reason "Left the company" --duration 30d
hemmelig admin users unban jane_doe
hemmelig admin users set-password jane_doe
hemmelig admin users delete jane_doe --yes
```

A username can have letters, digits and underscores. Hyphens and dots are not accepted.

`create` and `set-password` ask for the password without echo. Without `--duration`, a ban has no end. A banned user cannot sign in, and the API keys of that user stop working.

### Invite codes

```bash
hemmelig admin invites list
hemmelig admin invites create --max-uses 10 --expires-in-days 14
hemmelig admin invites deactivate K3J9QX2M7ZPA
```

`create` prints the code. `deactivate` accepts the code or the ID.

### Instance settings

The settings have the same sections as the admin dashboard: `general`, `security`, `organization`, `webhook` and `metrics`.

```bash
hemmelig admin instance get
hemmelig admin instance get security
hemmelig admin instance set security allowFileUploads=false rateLimitRequests=50
hemmelig admin instance set general "importantMessage=Maintenance on Friday"
```

`set` checks each key and value type before it sends the change. Use `true` or `false` for a switch and a whole number for a number. An instance in managed mode rejects changes. See [Managed mode](https://github.com/HemmeligOrg/Hemmelig.app/blob/main/docs/managed.md).

### Analytics

```bash
hemmelig admin analytics show --range 7d
```

The range is `7d`, `14d` or `30d`. The default is `30d`.

### Audit log

```bash
hemmelig admin audit --category settings
hemmelig admin audit --csv - > audit.csv
```

The instance audit log has the entries of all organizations. It takes the same flags as `orgs audit`. The entries hold metadata only, never secret content.

## Other commands

```bash
# Check that the instance is ready. The command exits with 1 when it is not.
hemmelig health

# Print the CLI version.
hemmelig version

# Show help for a command.
hemmelig help secrets
hemmelig admin users ban --help

# Run the MCP server. See docs/mcp.md.
HEMMELIG_API_KEY=hemmelig_xxxxxxxxxxxxxxxx hemmelig mcp
```

## JSON output

Add `--json` to any command to get the result as JSON on stdout:

```bash
hemmelig secrets create "token" --json
```

```json
{
    "id": "3f0c2a4e-6f1b-4c1d-9a55-0a4c8f1e2b7d",
    "link": "https://hemmelig.app/s/3f0c2a4e-6f1b-4c1d-9a55-0a4c8f1e2b7d#Xo3...",
    "expiresIn": "1d",
    "views": 1,
    "passwordProtected": false,
    "files": [],
    "canDelete": true
}
```

With `--json`, errors go to stderr as JSON:

```json
{
    "error": "secret not found: it was viewed, expired or deleted (Secret not found (status 404))",
    "status": 404,
    "exitCode": 4
}
```

To read a field in a script, use `jq`:

```bash
LINK=$(hemmelig secrets create "token" --json | jq -r .link)
```

## Exit codes

| Code | Meaning                                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------ |
| 0    | Success                                                                                                            |
| 1    | Error, for example a network error, a validation error or a rate limit                                             |
| 2    | Usage error, for example a missing argument, an unknown flag or a missing password                                 |
| 3    | Authentication error: the credential is missing or wrong, the action needs a session, or the action needs an admin |
| 4    | Not found: the secret does not exist, expired or has no views left                                                 |

## CI/CD

The CLI prints only the link to stdout, so you can capture it in a pipeline. In GitHub Actions, the Hemmelig action installs the CLI, checks its checksum and masks the secret and the link. Without the action, this step shares a deploy key for 1 hour:

```yaml
- name: Share the deploy key
  env:
      HEMMELIG_URL: https://secrets.example.com
      HEMMELIG_API_KEY: ${{ secrets.HEMMELIG_API_KEY }}
  run: |
      curl -fsSL https://github.com/HemmeligOrg/hemmelig-cli/releases/download/v2.0.0/hemmelig-linux-amd64 -o hemmelig
      chmod +x hemmelig
      LINK=$(printf '%s' "${{ secrets.DEPLOY_KEY }}" | ./hemmelig secrets create --title "Deploy key" --expires 1h)
      echo "::add-mask::$LINK"
      echo "Send the link to the on-call engineer."
```

Treat the link as a secret. It contains the key.

## Security model

- The CLI encrypts with AES-256-GCM and derives keys with PBKDF2-SHA256 and 1,300,000 iterations. The web app uses the same format, so links work in both. See [Encryption](https://github.com/HemmeligOrg/Hemmelig.app/blob/main/docs/encryption.md).
- The server gets the ciphertext, the salt and, for a password, a verifier. It never gets the key, the password or the plaintext.
- The CLI sends the API key and the session only to the configured instance. For a link to another instance, the CLI sends no credentials.
- Anyone with a full link can read the secret. Use a password, an IP range or a low view count for sensitive data.
- A password on the command line can show in the shell history and the process list. Use `--password-prompt` instead.

## Troubleshooting

| Error text                              | Cause and next step                                                                                  |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `this action needs a signed-in session` | The command changes credentials. Run `hemmelig login` and try again                                  |
| `this action needs an admin account`    | The API key or the session belongs to a normal user. Use an admin account                            |
| `Too many requests`                     | The rate limit of the instance stopped the request. Wait and try again. For sign-in, wait 10 seconds |
| `Username is invalid`                   | Use only letters, digits and underscores in the username                                             |
| `could not decrypt`                     | The key or the password is wrong, or the link is not complete. The attempt used a view               |
