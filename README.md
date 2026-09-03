# FreakyBigFoot's 3DS Community Servers

**Self-hosted community game servers that bring Nintendo 3DS online multiplayer back — for more than one game — after the Nintendo Network shutdown.**

When Nintendo Network shut down in April 2024, every 3DS game's online features went with it. This project is a self-hosted replacement: one NEX/NASC server that hosts online multiplayer for **multiple games at once**, plus one small homebrew app that points a console at it. It runs **on top of Pretendo** and leaves everything it doesn't host untouched.

**Hosted right now:** Final Fantasy Explorers · Fantasy Life

**More games are on the way.** If there's a 3DS game you'd love to see playable online again, [open an issue](https://github.com/FreakyBigFoot/fbf-3ds-servers/issues) and tell us — we're taking requests.

**Live status:** https://status.freakybigfoot.com

---

> ### Disclaimer
> This is an **unofficial, non-commercial, fan-made** project. It is **not affiliated with, endorsed by, or associated with Nintendo, Square Enix, Level-5, or Pretendo Network.** All game names and marks belong to their respective owners.
>
> **No game files are distributed here** — only original server code and homebrew tooling. You must own each game and dump it yourself. Nothing in this project is or ever will be sold — it is free.

---

## How it works (the proxy)

This is the important part, because it's what lets one app safely serve many games:

1. **One app installs one universal redirect.** The homebrew app writes a small Luma IPS patch to the console's **friends module** — the single system service every game uses to log into online. The patch changes *one address*: where the console asks "which server do I log into?" It now points at **this server** instead of Pretendo. This is **game-agnostic** — *every* game's online login gets redirected, not just one.

2. **The server decides per game, and proxies the rest.** For each login, the server looks at the game's server ID:
   - **A game we host** (Final Fantasy Explorers, Fantasy Life, …) → the server answers it and runs the session (auth, matchmaking, and a NAT-traversal relay so consoles on different networks find each other).
   - **Anything else** — including the friends server itself — → the server **passes the request straight through to Pretendo**, and the console connects to Pretendo exactly as if this server weren't in the middle.

So the console is "dumb" — it sends us everything — and all the routing lives on the **server**. That's why every other Pretendo game, your friends list, and presence keep working normally: unhosted traffic is a transparent pass-through.

3. **Adding a game is a server-side change.** A new game needs its access key and an endpoint added to the server — **no new console patch and no app update.** The console is already sending us every game; we just start answering one more. That's how the same redirect that started with one game now serves several.

## The app: Connect & Undo

The homebrew app (a single CIA) has two buttons:

- **Connect** — reads your *anonymous* Pretendo NEX login from the friends module, registers it with the server over HTTP, installs the universal redirect, and reboots. After that, every hosted game works online.
- **Undo** — puts **Pretendo's own original friends-module patch back** and reboots, returning you to plain Pretendo.

Here's the key detail that makes it safe and **fully reversible**: Pretendo already patches that friends-module file (to point at pretendo.cc). Connect *overwrites that one file* with our version; Undo writes Pretendo's original back — the app ships a verbatim copy of it. Nothing else is ever touched: not your account, not your saves, not any game's files. It's a single file being swapped, either way.

## For players

**You need:**
- A 3DS with custom firmware (Luma3DS)
- **Pretendo (Nimbus) already set up**, and you've signed into Pretendo online at least once
- A game you own that this server hosts

**Steps:**
1. Install the **FreakyBigFoot's Community Servers** app (CIA — see [Releases](https://github.com/FreakyBigFoot/fbf-3ds-servers/releases))
2. Open it and tap **Connect** → let it reboot
3. Launch a hosted game and go online
4. To go back to plain Pretendo anytime: open the app → **Undo**

## Repository layout

| Path | What |
|------|------|
| `server/` | Go NEX/NASC server — per-game hosting, the Pretendo proxy pass-through, `/register`, dashboard, TLS w/ SNI |
| `server/vendor-nex/` | Modified fork of Pretendo's `nex-go` (AGPL — see its `MODIFICATIONS.md`) |
| `patcher/` | The homebrew Connect/Undo app (C, devkitARM) + build files + art |

## Building

**Server** (Go):
```sh
cd server
go build -o server .
cp run.sh.example run.sh   # then edit run.sh for your deployment
./run.sh
```
Needs Postgres (the Pretendo `matchmaking.*` schema plus an accounts table the server creates). Each hosted game is one entry in `games.go` (game server ID + access key + NEX version).

**App** (devkitARM + makerom):
```sh
cd patcher
make
bannertool makebanner -i banner.png -a banner.wav -o banner.bnr
makerom -f cia -o FreakyBigFootServers.cia -target t -exefslogo \
  -elf <target>.elf -rsf app.rsf -icon <target>.smdh -banner banner.bnr
```

## Self-hosting your own server

Point the app at your own host by editing `SERVER_HOST` / `SERVER_IP` in `patcher/source/main.c`, set `FFE_PUBLIC_HOST` / `FFE_SECURE_HOST` in your `run.sh`, and add the games you want to host to `server/games.go`.

## License & credits

Licensed under the **GNU AGPL-3.0** (see `LICENSE`). Builds on [Pretendo Network](https://pretendo.network/)'s open-source `nex-go` library (also AGPL); the vendored, modified copy and its change list live in `server/vendor-nex/`.

Not affiliated with Nintendo, Square Enix, Level-5, or Pretendo Network.
