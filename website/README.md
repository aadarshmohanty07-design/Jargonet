# Jargonet / meshchat showcase site

Static, dependency-light showcase for the meshchat LAN prototype. There is no
build step: GitHub Actions uploads the `website/` directory directly to GitHub
Pages.

## Preview locally

```bash
python3 -m http.server 8000 --directory website
# open http://localhost:8000
```

Opening `index.html` directly also renders the page, but browsers block the
local `fetch()` of `demo.cast` from `file://`; the site shows a fallback message
and the rest of the page works. Use the small HTTP server to test the player.

## Deployment

`.github/workflows/deploy-website.yml` deploys on pushes to `main` that touch
`website/**`. Pages must be enabled with **Source: GitHub Actions**:

Repository → Settings → Pages → Build and deployment → Source → GitHub Actions.

For a project repository the site is published under
`https://<username>.github.io/<repo>/`. All asset and stylesheet paths in
`index.html` are relative so the same files work under that subpath.

## Demo recording

The committed [`assets/demo.cast`](assets/demo.cast) is currently a placeholder
until the recording job is run. The player detects the placeholder and displays
a runbook fallback; it does not fail the page.

To record a real cast on Linux:

```bash
pip install asciinema
# from the repository root, with a built binary:
bash meshchat/run_demo.sh --bin "$PWD/build/meshchat" --no-attach
# in another terminal:
asciinema rec website/assets/demo.cast
tmux attach -t meshchat-demo
```

Record this sequence:

1. `/peers` on Alice — all four nodes appear.
2. `/send Bob hi` — Bob prints plaintext.
3. `/send Bob --relays 2 hello through the mesh` — R1 and R2 print yellow
   `[HOP ]` lines with hex; only Bob prints the message.
4. `/quit` on R1.
5. `/peers` on Alice — R1 is gone.
6. `/send Bob --relays 1 still works` — Bob receives.

Stop with `Ctrl+D` / detach, then commit `website/assets/demo.cast` and push.

A reproducible recording job is in
`.github/workflows/record-demo.yml` (workflow_dispatch). It builds meshchat,
installs asciinema and tmux, records the four-pane demo, and uploads the cast as
an artifact. Download that artifact, replace `website/assets/demo.cast`, and
commit it.

## Dependencies and privacy

- No analytics, cookies, `localStorage`, fonts, icon libraries or frameworks.
- The only external requests are the pinned asciinema-player CSS/JS from
  jsDelivr, and only after the demo section approaches the viewport. The pinned
  version is 3.10.0, with SRI hashes in `script.js`.
- The architecture diagram and favicon are local SVG files.
- `demo.cast` is local; the player does not require a third-party service.

## Files

```
website/
  index.html
  styles.css          under 300 lines
  script.js           lazy player, copy buttons, reveal observer
  assets/demo.cast
  assets/architecture.svg
  assets/favicon.svg
  README.md
```
