# LG webOS 5.x, Permanent Root (Dev Mode)

> **⚠️ STATUS: BETA.** Functional and tested, but beta, use at your own risk, read the
> code before running it, and expect rough edges. No warranties, no pretence: this is a
> community kit that works on **one** certified TV (see below), not a polished product.

**Version 2**: tested on **LG CX** (OLED65CX6LA) and **LG NANO95** (55NANO956NA), both webOS 5.6.2:
root SSH (`:22`) comes up **by itself on every boot**, no computer needed.

> **Credits first, as they deserve:** the GPU privilege-escalation exploit at the heart of this
> kit (`payload/gfx_cred_escalate.py`) is the work of **James McVay**. This repo only adds the
> permanent-root chain, the installer and the NZ Store around it. Full credits at the bottom.

## Compatibility

| Model / firmware | Status |
|---|---|
| **LG CX** (OLED\*CX\*LA, webOS 5.6.2, fw 04.64.00) | ✅ certified (tested end-to-end, survives reboots) |
| **LG NANO95** (55NANO956NA, webOS 5.6.2, fw 04.64.00, machine e60) | ✅ tested (dynamic MMIO skip + nativehome boot persistence) |
| Other **webOS 5.x** panels (C6–C9 series and friends) | ⚠️ **likely**: the root chain is model-independent and the exploit self-calibrates. Reports and PRs welcome. |
| webOS 6+ | ❌ untested (Dev Mode internals differ) |

### Dynamic MMIO skip (multi-model support)

The original exploit scanned the full physical memory range between the GPU carveout and
the top of RAM. On the CX this works because that range is entirely System RAM. On other
SoCs (e.g. the NANO95's E60 platform) parts of that range are GPU MMIO or device registers
that **kernel-panic** when read through the GFX mapping.

The exploit detects unsafe regions at startup using two methods:

1. **`/proc/iomem` parsing** — when run as root (or on kernels that expose addresses to
   non-root), the exploit reads `/proc/iomem` to find which regions are System RAM and
   skips everything else.
2. **Probe-based fallback** — most kernels (including webOS) zero `/proc/iomem` addresses
   for non-root users. When this is detected, the exploit probes one page per 16 MB chunk
   boundary via the GFX device to discover unreadable regions before the full scan. This
   adds ~1 second of overhead but prevents kernel panics on MMIO regions.

This makes the scan safe on any SoC layout:

- **CX (M16P):** entire scan range is RAM → no skip needed, behavior unchanged.
- **NANO95 (E60):** `0xBA000000–0xFFFFFFFF` is MMIO → automatically skipped.
- **Other models:** skip ranges are derived at runtime; no hardcoded addresses.

## What it does

This kit provides two boot persistence paths, auto-detected at install time:

### Path A: Chokidar shim (CX and models with devmode chokidar)

The TV's own Dev Mode boot chain runs `devmode-helper.js` **as root on every boot**. This kit
piggybacks on that execution through an **unsigned dependency** (`node_modules/chokidar/index.js`)
and launches an init chain that starts a root SSH server on port 22.

**No signed file is ever modified.** The signature checks (which would disable Dev Mode) pass untouched.

```
devmode.sh (NAND, RO)
 └─ verifies start-devmode.sh (signature OK, untouched)
     └─ start-devmode.sh → verifies devmode-helper.js + devmode-helper-util.js (untouched)
         └─ node devmode-helper.js  ← RUNS AS ROOT ON EVERY BOOT
             └─ require('chokidar')  ← node_modules/chokidar/index.js, NOT VERIFIED ✅
                 └─ 🔥 NATXO SHIM → sh /media/developer/natxo/boot-root.sh
                     └─ run-parts /media/developer/natxo/init.d
                         ├─ 90-natxo-sshd → start.sh → sshd :22 (root)
                         ├─ 98-natxo-daemon → root daemon (API + telnet)
                         └─ 95-natxo-restore / 99-suidtest
```

### Path B: Nativehome hook (NANO95/E60, models with Clean Your TV but no chokidar)

On some models the devmode service lacks `node_modules/chokidar`, so the chokidar shim cannot
be used. If [Clean Your TV](https://github.com/Razdva122/clean-your-tv-lg-webos) is installed,
this kit hooks into its **nativehome service** instead: a JS snippet appended to `service.js`
checks whether root SSH is already running, and if not, spawns a boot-time GFX credential
escalation (`boot-escalate.py`) that re-escalates to root and starts sshd.

```
TV boots
 └─ CYTV nativehome service starts (Luna service, runs as developer)
     └─ service.js ← NATXO HOOK APPENDED ✅
         └─ setTimeout 5s → check port 22
             └─ port 22 down? → python boot-escalate.py
                 └─ GFX cred escalation (fork-spray + scan + blast)
                     └─ root child → sh boot-root.sh
                         └─ run-parts init.d → sshd :22 (root)
```

The installer tries Path A first; if chokidar is not found, it falls back to Path B.

## What you get after rooting

- **Root SSH** on port 22 (key-based), available ~75s after every boot.
- **Root daemon** on `http://127.0.0.1:7777` (token-protected, header `X-Natxo-Token`):
  - `GET /status`: root state, uptime
  - `POST /telnet/on|off`: toggle a root telnet shell on port 23 (password = token)
  - `POST /install {ipk}`: install an `.ipk` **as root** (the daemon parses the `ar` archive
    itself and extracts `data.tar.gz` straight into `/media/developer/apps/`: the field in
    `appInstallService` payloads is `ipkUrl`, not `ipk`)
  - `POST /app/install {url}`: download + registered install (`dev/install` with live
    subscription → launcher icon). `GET /app/log` for progress, `GET /app/installed` for state.
  - `POST /toggle {name,on}` / `GET /toggle`: system toggles used by the NZ Store
  - `POST /exec {cmd}`: run a root command
- **NZ Store** (`com.natxobsd.nzstore`), a lightweight homebrew store (plain HTML/JS, zero
  frameworks): webosbrew catalog + custom repos (add your own), remote-control navigation,
  6 languages, and a Control tab with quick system toggles (eco, LG tracking, SSH, Telnet,
  and **Dev Mode ∞**: keeps the developer session counter topped up so Dev Mode never expires)
  plus a **screen capture panel** (now / 10s / 20s at 4K, see `screen-capture/`).
- **Screen capture at 4K** (3840x2160): LG disables it per model, this kit re-enables it
  without touching anything signed. Scripts, boot persistence and docs in `screen-capture/`.
- Apps can also be installed anytime from SSH:
  `curl -H "X-Natxo-Token: $TOKEN" -d '{"ipk":"/tmp/app.ipk"}' http://127.0.0.1:7777/install`
- The token is created at install time and printed to `install.log`.

## Why our own store (NZ Store) instead of the Homebrew Channel?

The Homebrew Channel is a great webosbrew project, but on webOS 5 its app-elevation path
(autostart as a privileged service) caused repeated **boot loops and OOM crashes** on the
certified TV (two real incidents). Once this kit already gives you permanent root, that risk is
unnecessary: the NZ Store talks to the **local root daemon** instead of elevating itself.

What the NZ Store gives you:
- **Remote-first UI**: fully navigable with the LG remote (D-pad, OK, Back), no pointer needed.
- **6 languages** (ES/EN/IT/FR/DE/PT) with a flag selector.
- **Catalogs**: webosbrew + webosbrew non-free + Stremio, plus **your own repos** (add any
  `apps.json` feed, they persist across reboots).
- **Control tab**: system toggles, eco auto power-off, LG tracking (LivePlus), SSH root,
  Telnet, and **Dev Mode ∞** (the developer session never expires).
- **Registered installs with launcher icons** (`dev/install` with a live subscription) and
  friendly per-stage install status.
- **Tiny**: plain HTML/JS, zero frameworks, ~28 KB. No background service of its own.

If you prefer the Homebrew Channel, nothing here blocks it, this kit simply doesn't need it.

## Is this safe?

Short version: **nothing signed is ever touched** (signature checks pass, Dev Mode keeps
working), **no firmware modification**, **power-cut safe**, and it is **fully reversible**
(`rm -rf /media/developer/natxo` + restore the chokidar/nativehome backup from
`/media/developer/natxo/devmode-state/`, or just factory-reset Dev Mode).
Known beta risks: tested on CX and NANO95 only, do NOT update the TV firmware while
rooted. Full details and the removal steps: `LG-CX-ROOT-EN.md` / `LG-CX-ROOT-ES.md`.

## Contents

- **`one-click.sh`**: the whole thing for end users: detects the TV, fetches the Dev Mode key,
  runs the exploit, installs the permanent-root chain + daemon + apps, prints the token. ~15-30 min.
- `payload/`: exploit (James McVay), TV-side installer (`rootcmd_install.sh`), OpenSSH build,
  persistence shims (chokidar + nativehome), boot escalation, daemon. Drop `payload/apps/*.ipk`
  (and list them in `payload/apps/manifest.txt`) to auto-install apps (e.g. the NZ Store).
- `nzstore/`: NZ Store sources.
- `screen-capture/`: 4K screen capture scripts (shot, timer, boot persistence) + UI panel
  and the full recipe (`screen-capture/README.md`).
- `scripts/boot-root.sh`: launches the init chain
- `scripts/start.sh`: creates the PrivSep dir (`/var/run/sshd`), sets `LD_LIBRARY_PATH`,
  starts the OpenSSH server (process guard included), logs to `boot.log`
- `scripts/init.d/`: `90-natxo-sshd`, `95-natxo-restore`, `98-natxo-daemon`, `99-suidtest`

## Install (root shell required once)

```sh
mkdir -p /media/developer/natxo/init.d /media/developer/natxo/openssh /media/developer/natxo/devmode-state
cp scripts/boot-root.sh scripts/start.sh /media/developer/natxo/
cp scripts/init.d/* /media/developer/natxo/init.d/
cp payload/boot-escalate.py /media/developer/natxo/
cp payload/shim-chokidar.js payload/shim-nativehome.js /media/developer/natxo/devmode-state/
chmod 755 /media/developer/natxo/*.sh /media/developer/natxo/*.py /media/developer/natxo/init.d/*
# place your OpenSSH build + hostkey (RSA 2048 PEM, the TV's OpenSSH 6.1 reads no other)
# + authorized_keys in /media/developer/natxo/
#
# Then install persistence (one of):
# Path A (chokidar): prepend payload/shim-chokidar.js to:
#   /media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service/node_modules/chokidar/index.js
# Path B (nativehome, requires Clean Your TV): append payload/shim-nativehome.js to:
#   /media/developer/apps/usr/palm/services/com.local.nativehome.service/service.js
```

See `LG-CX-ROOT-EN.md` for the full method and `LG-CX-ROOT-ES.md` for the Spanish version.

## ⚠️ Critical lessons (learned the hard way)

1. **NEVER modify `devmode-helper.js`**: it is openssl-verified on every boot. On failure the
   helper simply does not start (`devmode-helper files verification is not valid`).
2. **NEVER modify `start-devmode.sh`**: it is the tripwire: a bad signature disables Dev Mode
   and triggers the wipe path.
3. The helper's verification key is read-only (`/usr/palm/services/com.palm.service.devmode/pub.pem`)
   and shared with the outer check, it cannot be removed or swapped.
4. The sshd must create `/var/run/sshd` (PrivSep) before starting or it dies **silently**.
5. Log everything to a file on the developer partition, early boot gives no other feedback.
6. `node --check` fails with `lstat` errors on `/proc/1/root/...` paths, test on `/tmp` copies.
7. Process guards must match the **exact path** (`/media/developer/natxo/openssh/sbin/sshd`): the Dev Mode sshd (`...devmode.service/openssh/sbin/sshd -p 9922`) shares the suffix and a
   loose pattern produces false positives (your sshd never starts and it *looks* like root is lost).

## Credits

- GPU credential-escalation exploit: **James McVay** (`gfx_cred_escalate.py`).
- RootMyTV / webosbrew community for the Dev Mode boot-chain research.
- Permanent-root chain (chokidar shim + nativehome hook), **v2**: Natxo, 2026-10.
- NANO95/E60 support (dynamic MMIO skip, nativehome boot persistence): Tom Hodgson, 2026-10.
