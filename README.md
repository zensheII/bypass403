A CLI tool for testing 403 Forbidden bypass techniques. Useful during pentests and bug bounty recon when you hit a wall and want to quickly check if the restriction is actually enforced properly.

> **For authorized security testing only. Do not use against targets you don't have permission to test.**

---
[![Screenshot-20260301-160854.png](https://i.postimg.cc/FsHtZpVn/Screenshot-20260301-160854.png)](https://postimg.cc/jCmkqz9z)

## What it does

Three test modes, can be mixed or run all at once:

**`--methods`** — sends the same URL with a bunch of HTTP methods (GET, POST, PUT, PATCH, OPTIONS, TRACE, PROPFIND, MKCOL, etc.) and checks if any return something other than 403.

**`--headers`** — replays the request with common bypass headers like `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-Custom-IP-Authorization`, etc. Tests both `127.0.0.1` and `::1` for IP headers.

**`--paths`** — generates path variants from the URL (e.g. `/admin`) and fires them all off. Things like `//admin//`, `/ADMIN`, `/admin%2f`, `/admin%00`, `/..;/admin`, `/%2e%2e/admin`, `/admin.json`, and more. Requests are sent raw — no normalization.

Anything that comes back as 200, 201, 204, 301, 302, or 401 gets flagged as interesting.

---

## Requirements

- Ruby 2.7+
- No gems. Standard library only (`net/http`, `uri`, `optparse`, `openssl`).

---

## Usage

```bash
# run everything
ruby bypass403.rb --url https://target.com/admin --all

# just headers and paths
ruby bypass403.rb --url https://target.com/admin --headers --paths

# slow it down a bit to avoid WAF rate limits
ruby bypass403.rb --url https://target.com/admin --all --delay 0.5

# custom timeout
ruby bypass403.rb --url https://target.com/admin --all --timeout 10
```

Run without arguments to see the banner and help.

---

## Flags

| Flag | Description |
|---|---|
| `--url URL` | Target URL (required) |
| `--methods` | Test HTTP method manipulation |
| `--headers` | Test header-based bypass |
| `--paths` | Test path fuzzing |
| `--all` | Run all three |
| `--timeout N` | Request timeout in seconds (default: 5) |
| `--delay N` | Delay between requests, e.g. `0.5` |
| `--verbose` | Verbose output |
| `-h`, `--help` | Show help |

---

## Output

Color-coded by status code:

- 🟢 **200, 201, 204** — highlighted green + `<-- interesting`
- 🟡 **301, 302** — yellow + `<-- interesting`
- 🟣 **401** — magenta + `<-- interesting`
- 🔴 **403** — red (expected, not flagged)
- ⬜ **404** — gray
- 🟡 **5xx** — yellow bold (worth checking)

---

## Techniques covered

**Methods:** GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE, CONNECT, PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK, SEARCH

**Headers:** X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Real-IP, X-Client-IP, X-Custom-IP-Authorization

**Path variants:** double slashes, trailing dot/semicolon, URL encoding (`%2f`, `%252f`, `%00`, `%09`), case variations, extension appending (`.json`, `.php`, `.html`), path traversal patterns (`/..;/`, `/%2e%2e/`, `/./`), tilde, and more.
