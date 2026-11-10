+++
title = "Goodies"
description = "Small scripts by resux."
template = "goodies.html"
+++

Small scripts I use. The source is on GitHub.

## shot.sh

Screenshots the focused window into `~/exam/*/<OCTET>/screenshots/` and copies the Obsidian embed to the clipboard. X11 only.

```bash
echo <OCTET> > ~/exam/.current
~/bin/shot.sh      # save instantly
~/bin/shot.sh -l   # save, then ask for a label
```

[Source](https://github.com/resux1338/resux-oscp-refsheets/blob/main/scripts/shot.sh) · [Setup and hotkey binding](https://github.com/resux1338/resux-oscp-refsheets/blob/main/documentation/screenshots-and-logging.md)
