# FFE Online

**Community online multiplayer for _Final Fantasy Explorers_ (Nintendo 3DS), revived after the Nintendo Network shutdown.**

Nintendo Network shut down in April 2024, taking Final Fantasy Explorers' online co-op
with it. This project is a self-hosted replacement: a NEX/NASC game server plus a tiny
homebrew app (**FFE Connect**) that points a console at it — restoring full online
multiplayer over the internet on real hardware. It runs **on top of Pretendo** and
redirects **only Final Fantasy Explorers**; every other Pretendo game keeps working.

**Live status:** https://status.freakybigfoot.com

---

> ### Disclaimer
> This is an **unofficial, non-commercial, fan-made** project. It is **not affiliated with,
> endorsed by, or associated with Nintendo, Square Enix, or Pretendo Network.**
> "Final Fantasy Explorers" and related marks belong to their respective owners.
>
> **No game files are distributed here.** This repository contains only original server
> code and homebrew tooling. You must own the game and dump it yourself. Nothing in this
> project is or ever will be sold — it is free.

---

## For players

**You need:**
- A 3DS with custom firmware (Luma3DS)
- **Pretendo (Nimbus) already set up**, and you've signed into Pretendo online at least once

**To join:**
1. Install **FFE Connect** (the homebrew CIA)
2. Open it and tap **Connect**
3. Reboot, then launch Final Fantasy Explorers
4. Go online — you're on the community server

It's **fully reversible**: tap **Undo** to restore stock Pretendo. The patch is an
in-memory Luma IPS on the friends module — it doesn't touch your account, saves, or
other games.

## How it works

- FFE Connect reads your *anonymous* Pretendo NEX login (principal ID + NEX password)
  from the friends module and registers it with the server over HTTPS.
- It writes a small Luma IPS patch that redirects the friends module's NASC lookup for
  **Final Fantasy Explorers only** to this server.
- The server speaks NASC (login → locator/token) and NEX/PRUDP (auth + matchmaking),
  so consoles find each other and play, just like the original service.

## Repository layout

| Path | What |
|------|------|
| `server/` | Go NEX/NASC server (matchmaking, `/register`, dashboard, TLS w/ SNI) |
| `server/vendor-nex/` | Modified fork of Pretendo's `nex-go` (AGPL — see its `MODIFICATIONS.md`) |
| `patcher/` | **FFE Connect** homebrew app (C, devkitARM) + build files + original art |

## Building

**Server** (Go):
```sh
cd server
go build -o ffe-server .
cp run.sh.example run.sh   # then edit run.sh for your deployment
./run.sh
```
Needs Postgres (schema: the Pretendo `matchmaking.*` tables plus an `ffe_accounts` table
the server creates). See `run.sh.example` for the full environment.

**Patcher** (devkitARM + makerom):
```sh
cd patcher
# compile in the devkitpro/devkitarm container, then pack with makerom
make
bannertool makebanner -i banner.png -a banner.wav -o banner.bnr
makerom -f cia -o FFEConnect.cia -target t -exefslogo \
  -elf FFEConnect.elf -rsf app.rsf -icon FFEConnect.smdh -banner banner.bnr
```

## Self-hosting your own server

Point the patcher at your own host by editing `SERVER_HOST` / `SERVER_IP` in
`patcher/source/main.c`, and set `FFE_PUBLIC_HOST` / `FFE_SECURE_HOST` in your `run.sh`.

## License & credits

Licensed under the **GNU AGPL-3.0** (see `LICENSE`). This project builds on
[Pretendo Network](https://pretendo.network/)'s open-source `nex-go` library (also AGPL);
the vendored, modified copy and its change list live in `server/vendor-nex/`.

Not affiliated with Nintendo, Square Enix, or Pretendo Network.
