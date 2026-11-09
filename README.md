# resux.xyz

Personal site: a short bio and writeups of retired Hack The Box machines and CTF challenges.
Built with [Zola](https://www.getzola.org/) 0.23, deployed to GitHub Pages by `.github/workflows/deploy.yml`.

## Layout

```
zola.toml                 site config, sidebar content lives under [extra]
content/writeups/         one .md file (or folder with index.md + images) per writeup
templates/                index (sidebar + list), page (writeup), 404, partials, macros
static/css/site.css       all styles, colour tokens at the top
static/js/code.js         language label + copy button on code blocks
static/fonts/             Inter (bundled), JetBrains Mono (add it, see below)
static/CNAME              resux.xyz
```

## First run

1. Install Zola 0.23.4 (same version as the workflow). The release binary is the simplest:
   download `zola-v0.23.4-x86_64-unknown-linux-gnu.tar.gz` from
   https://github.com/getzola/zola/releases and put `zola` on your PATH.
2. Add JetBrains Mono: download the latest release zip from
   https://github.com/JetBrains/JetBrainsMono/releases and copy
   `fonts/webfonts/JetBrainsMono-Regular.woff2`, `-Medium.woff2` and `-Bold.woff2`
   into `static/fonts/`. Until then the site falls back to the system monospace font.
3. `zola serve --drafts` and open http://127.0.0.1:1111. The example Cronos post is a draft,
   so it only shows with `--drafts`. Delete it once you have a real writeup.

## Writing a writeup

Create `content/writeups/<box>.md`, or `content/writeups/<box>/index.md` if you want images
next to it (reference them as `![nmap](nmap.png)`).

```toml
+++
title = "Boxname"
date = 2026-11-08
description = "One or two sentences for search results and link previews."

[extra]
platform = "htb"          # or "ctf"
os = "linux"              # optional
difficulty = "medium"     # optional
chain = ["foothold step", "lateral step", "privesc step", "root"]   # optional
+++
```

`chain` drives the arrow line on the home page and the "Attack chain" box on the post.

Code blocks:

````md
```bash
nmap -sC -sV 10.10.10.10
```

```text,hl_lines=3
lines of output
where the third one
gets highlighted
```
````

Headings (`##`, `###`) get a clickable `##` link to the section automatically.

Zola 0.23 normally runs the template engine over Markdown too, which would break on
payloads like `{{7*7}}`. `skip_content_templating = ["writeups/**"]` in `zola.toml` turns
that off for writeups. Quick test: put `{{7*7}}` in a code block of a draft and run
`zola serve --drafts`; it should show literally, not as `49` or a build error. If it
doesn't, wrap such blocks in `{% raw %}` ... `{% endraw %}`.

Only publish writeups for retired machines; nothing from OffSec labs or exams.

## Deploying

1. Create the repo on GitHub, push to `main`.
2. Repo Settings → Pages → Source: **GitHub Actions**.
3. Settings → Pages → Custom domain: `resux.xyz`, then tick **Enforce HTTPS** once the certificate is issued.
4. Account Settings → Pages → **Verified domains**: add `resux.xyz` (stops anyone else claiming it on GitHub Pages).
5. DNS at your registrar:

   | Type  | Name | Value |
   |-------|------|-------|
   | A     | @    | 185.199.108.153 |
   | A     | @    | 185.199.109.153 |
   | A     | @    | 185.199.110.153 |
   | A     | @    | 185.199.111.153 |
   | AAAA  | @    | 2606:50c0:8000::153 |
   | AAAA  | @    | 2606:50c0:8001::153 |
   | AAAA  | @    | 2606:50c0:8002::153 |
   | AAAA  | @    | 2606:50c0:8003::153 |
   | CNAME | www  | resux1338.github.io |

Every push to `main` rebuilds and deploys the site.

## Things to check before going live

- Sidebar text, HTB stats and links in `zola.toml` → `[extra]` (the HTB profile URL especially).
- Impressum: if you need one, add `content/impressum.md` and set `impressum = "@/impressum.md"` in `zola.toml`.
- If `hl_lines` doesn't visibly highlight a line, inspect the generated markup and adjust the
  `.prose pre mark` selector in `site.css` to match what Zola emits.

## Credits

Inter by Rasmus Andersson (SIL OFL 1.1, see `static/fonts/Inter-LICENSE.txt`).
JetBrains Mono by JetBrains (SIL OFL 1.1). Code colours: Zola's built-in `tokyo-night` theme.
