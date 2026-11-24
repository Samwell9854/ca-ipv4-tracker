#!/usr/bin/env python3
"""Build the Canadian IPv4 range lists in data/.

Sources:
  - The five RIR "delegated-extended" statistics files (country CA, IPv4,
    allocated or assigned), each verified against its published MD5.
  - X4BNet lists_vpn (https://github.com/X4BNet/lists_vpn): the "vpn" and
    "datacenter" IPv4 lists, used for the filtered variant.

Outputs (sorted, one CIDR per line, no comments):
  data/ca-ipv4.txt                  all IPv4 ranges registered to Canada
  data/ca-ipv4-no-vpn-hosting.txt   the same minus VPN and hosting ranges
  data/meta.json                    counts, SHA-256 of each list, build date

Every check below fails the build (non-zero exit) instead of publishing a
suspicious result. A large change against the previous build also fails,
unless FORCE=1 is set (manual run, after looking at why).

Standard library only.
"""

import datetime
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
import urllib.request

RIRS = {
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
EXCLUSIONS = {
    "vpn": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "datacenter": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
}

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUT_ALL = os.path.join(DATA, "ca-ipv4.txt")
OUT_FILTERED = os.path.join(DATA, "ca-ipv4-no-vpn-hosting.txt")
OUT_META = os.path.join(DATA, "meta.json")

# Sanity bounds. Canada held ~6,400 CIDRs / ~67 M addresses in 2026; these
# leave room for slow drift but catch truncated or garbage input.
CA_CIDRS = (4000, 10000)
CA_ADDRESSES = (50_000_000, 90_000_000)
MIN_EXCLUSION_LINES = {"vpn": 2000, "datacenter": 10000}
MIN_FILTERED_SHARE = 0.80   # filtered list keeps at least 80 % of CA addresses
MAX_CHANGE = 0.10           # vs previous build, in addresses, either list
SHORTEST_PREFIX = 8         # nothing wider than a /8 may be published

USER_AGENT = "ca-ipv4-tracker (+https://github.com/Samwell9854/ca-ipv4-tracker)"


class BuildError(Exception):
    pass


def fetch(url, attempts=3):
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except Exception as e:  # network errors: retry, then give up
            last = e
            time.sleep(5 * (i + 1))
    raise BuildError(f"download failed: {url}: {last}")


def rir_file(name, url):
    """Download a delegated file and check it against its .md5 (retry once:
    the file and its checksum are replaced separately upstream)."""
    for _ in range(2):
        body = fetch(url)
        md5_text = fetch(url + ".md5").decode("ascii", "replace")
        m = re.search(r"\b([0-9a-fA-F]{32})\b", md5_text)
        if not m:
            raise BuildError(f"{name}: no MD5 in {url}.md5")
        if hashlib.md5(body).hexdigest() == m.group(1).lower():
            return body.decode("ascii", "replace")
        time.sleep(30)
    raise BuildError(f"{name}: MD5 mismatch")


def parse_rir(name, text):
    lines = text.splitlines()
    header = next((l for l in lines if l and not l.startswith("#")), "")
    if not re.match(r"^2(\.\d+)?\|", header):
        raise BuildError(f"{name}: unexpected header: {header[:80]!r}")
    nets = []
    for line in lines:
        p = line.split("|")
        if len(p) < 7 or p[1] != "CA" or p[2] != "ipv4":
            continue
        if p[6] not in ("allocated", "assigned"):
            continue
        start = ipaddress.IPv4Address(p[3])
        count = int(p[4])
        if count <= 0:
            raise BuildError(f"{name}: bad count in {line!r}")
        nets.extend(ipaddress.summarize_address_range(start, start + count - 1))
    return nets


def parse_plain(name, text):
    nets = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            nets.append(ipaddress.IPv4Network(s, strict=False))
        except ValueError:
            raise BuildError(f"{name}: not an IPv4 CIDR: {s[:60]!r}")
    if len(nets) < MIN_EXCLUSION_LINES[name]:
        raise BuildError(f"{name}: only {len(nets)} entries, list looks truncated")
    return nets


def subtract(base, minus):
    """base minus minus, both collapsed lists, by interval arithmetic."""
    iv = sorted((int(n.network_address), int(n.broadcast_address)) for n in base)
    ex = sorted((int(n.network_address), int(n.broadcast_address)) for n in minus)
    out, j = [], 0
    for a, b in iv:
        cur = a
        while j < len(ex) and ex[j][1] < cur:
            j += 1
        k = j
        while k < len(ex) and ex[k][0] <= b:
            if ex[k][0] > cur:
                out.append((cur, ex[k][0] - 1))
            cur = max(cur, ex[k][1] + 1)
            k += 1
        if cur <= b:
            out.append((cur, b))
    nets = []
    for a, b in out:
        nets.extend(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)))
    return list(ipaddress.collapse_addresses(nets))


def addresses(nets):
    return sum(n.num_addresses for n in nets)


def within(label, value, bounds):
    lo, hi = bounds
    if not lo <= value <= hi:
        raise BuildError(f"{label} = {value}, outside {lo}-{hi}")


def previous_addresses(path):
    try:
        with open(path) as f:
            return addresses(ipaddress.IPv4Network(l.strip()) for l in f if l.strip())
    except FileNotFoundError:
        return None


def check_change(label, path, new, force):
    old = previous_addresses(path)
    if old is None or old == 0:
        return
    change = abs(new - old) / old
    if change > MAX_CHANGE and not force:
        raise BuildError(f"{label}: {change:.1%} change in addresses vs previous build "
                         f"({old} -> {new}); rerun with FORCE=1 once understood")


def write_list(path, nets):
    text = "".join(f"{n}\n" for n in nets)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    force = os.environ.get("FORCE") == "1"

    ca = []
    per_rir = {}
    for name, url in RIRS.items():
        nets = parse_rir(name, rir_file(name, url))
        per_rir[name] = len(nets)
        ca.extend(nets)
    ca = list(ipaddress.collapse_addresses(ca))
    within("CA CIDRs", len(ca), CA_CIDRS)
    within("CA addresses", addresses(ca), CA_ADDRESSES)

    excl = []
    per_excl = {}
    for name, url in EXCLUSIONS.items():
        nets = parse_plain(name, fetch(url).decode("ascii", "replace"))
        per_excl[name] = len(nets)
        excl.extend(nets)
    excl = list(ipaddress.collapse_addresses(excl))

    filtered = subtract(ca, excl)
    within("filtered CIDRs", len(filtered), CA_CIDRS)
    if addresses(filtered) < MIN_FILTERED_SHARE * addresses(ca):
        raise BuildError(f"filtered list keeps only {addresses(filtered) / addresses(ca):.1%} "
                         "of CA addresses")
    for nets in (ca, filtered):
        short = [n for n in nets if n.prefixlen < SHORTEST_PREFIX]
        if short:
            raise BuildError(f"prefix wider than /{SHORTEST_PREFIX}: {short[0]}")

    check_change("ca-ipv4", OUT_ALL, addresses(ca), force)
    check_change("ca-ipv4-no-vpn-hosting", OUT_FILTERED, addresses(filtered), force)

    os.makedirs(DATA, exist_ok=True)
    sha_all = write_list(OUT_ALL, ca)
    sha_filtered = write_list(OUT_FILTERED, filtered)

    # meta.json only changes when a list changes, so an unchanged build
    # makes no commit.
    try:
        with open(OUT_META) as f:
            old_meta = json.load(f)
    except (FileNotFoundError, ValueError):
        old_meta = {}
    old_shas = {k: v.get("sha256") for k, v in old_meta.get("lists", {}).items()}
    new_lists = {
        "ca-ipv4.txt": {"cidrs": len(ca), "addresses": addresses(ca), "sha256": sha_all},
        "ca-ipv4-no-vpn-hosting.txt": {"cidrs": len(filtered), "addresses": addresses(filtered),
                                       "sha256": sha_filtered},
    }
    if {k: v["sha256"] for k, v in new_lists.items()} != old_shas:
        meta = {
            "updated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lists": new_lists,
            "sources": {"rir_ca_entries": per_rir, "exclusion_entries": per_excl},
        }
        with open(OUT_META + ".tmp", "w") as f:
            json.dump(meta, f, indent=2)
            f.write("\n")
        os.replace(OUT_META + ".tmp", OUT_META)
        print("lists changed")
    else:
        print("no change")

    print(json.dumps(new_lists, indent=2))


if __name__ == "__main__":
    try:
        main()
    except BuildError as e:
        print(f"BUILD FAILED: {e}", file=sys.stderr)
        sys.exit(1)
