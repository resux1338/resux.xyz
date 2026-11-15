+++
title = "Goodies"
description = "Small scripts by resux."
template = "goodies.html"
+++

Small scripts I use. The source is on GitHub.

## resux-oscp-refsheets

Command reference for OSCP+ and CPTS, sorted by phase: recon, foothold, Linux and Windows privesc, Active Directory, pivoting, passwords, exam documentation.

```text
enumerate → lead → prove preconditions → access → re-enumerate
```

[Source](https://github.com/resux1338/resux-oscp-refsheets) · [Methodology and stuck checklist](https://github.com/resux1338/resux-oscp-refsheets/blob/main/00-methodology.md)

## tablog

Logs every terminal tab (zsh/bash, tmux-aware) and builds one Markdown report per engagement: a timeline over all tabs, then each command with its output. Reverse shells and evil-winrm sessions are split per remote command.

```bash
eng exam                 # set engagement, other tabs follow
tab 10.10.11.5-web       # name tab after the target
note creds admin:S3cret  # remark in the report timeline
tablog report            # -> ~/logs/exam/report.md
```

[Source](https://github.com/resux1338/tablog) · [Install and settings](https://github.com/resux1338/tablog#install)

## shot.sh

Screenshots the focused window into `~/exam/*/<OCTET>/screenshots/` and copies the Obsidian embed to the clipboard. X11 only.

```bash
echo <OCTET> > ~/exam/.current
~/bin/shot.sh      # save instantly
~/bin/shot.sh -l   # save, then ask for a label
```

[Source](https://github.com/resux1338/resux-oscp-refsheets/blob/main/scripts/shot.sh) · [Setup and hotkey binding](https://github.com/resux1338/resux-oscp-refsheets/blob/main/documentation/screenshots-and-logging.md)
