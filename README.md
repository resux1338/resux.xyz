# resux.xyz

Zola 0.23.4. Preview with `zola serve` (add `--drafts` to see drafts). Pushing to `main` deploys.

## New writeup

Create `content/writeups/<box>/index.md`. Images go in the same folder: `![nmap scan](nmap.png)`.

A `badge.png` in that folder (square, 96x96) is shown as a round thumbnail in the writeup lists.

A `banner.png` in that folder is shown as a strip above the title and used as the link preview image. Crop it to about 9:2 (e.g. 1600x356) first; a taller image is cut to that shape, and `banner_y = 40` under `[extra]` moves the cut (0 = top of the image, 100 = bottom).

```toml
+++
title = "Boxname"
date = 2026-11-08
description = "One or two sentences for search results and link previews."
draft = true              # remove to publish

[taxonomies]
tags = ["Active Directory", "AS-REP roasting"]   # optional; general technique names, reuse the ones at /tags/

[extra]
platform = "htb"          # lower-case; shown via [extra.display_names] in zola.toml
os = "linux"              # optional
difficulty = "medium"     # optional
chain = ["foothold step", "lateral step", "privesc step", "root"]   # optional
+++
```

A new `platform`, `os` or `difficulty` value needs a line in `[extra.display_names]`, otherwise it is shown as written.

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

A writeup with three or more `##` sections gets a Contents list (its `##` and `###` headings) automatically.

Blocks with a language (`bash`, `powershell`, ...) get a Copy button. `text` blocks are output and get none.

## New goodie

Add a `##` section to `content/goodies.md`: one line on what it does, a usage block, a link to the source.

Only retired machines. Nothing from OffSec labs or exams.
