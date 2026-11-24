# ca-ipv4-tracker

IPv4 ranges registered to Canada, rebuilt weekly.

| File | Content |
|---|---|
| [`data/ca-ipv4.txt`](data/ca-ipv4.txt) | Every IPv4 range the five Regional Internet Registries list as allocated or assigned to Canada (`CA`), collapsed into CIDRs |
| [`data/ca-ipv4-no-vpn-hosting.txt`](data/ca-ipv4-no-vpn-hosting.txt) | The same, minus ranges listed as VPN or hosting/datacenter by [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) |
| [`data/meta.json`](data/meta.json) | Last change date, CIDR and address counts, SHA-256 of each list |

Lists are sorted, one CIDR per line, with no comments or blank lines.

## Sources

- RIR delegated statistics (extended format) from ARIN, RIPE NCC, APNIC, LACNIC and AFRINIC. Each file is checked against its published MD5 before use.
- X4BNet `lists_vpn`: `output/vpn/ipv4.txt` and `output/datacenter/ipv4.txt`.

## How it's built

[`build.py`](build.py) (Python 3, standard library only) downloads the sources, keeps Canadian IPv4 entries, collapses them, and subtracts the exclusion lists. A [scheduled workflow](.github/workflows/build.yml) runs it weekly and commits only when a list changes.

The build refuses to publish, and the run fails, when:

- a source can't be downloaded, fails its checksum, or looks truncated;
- the counts fall outside sane bounds;
- the filtered list keeps less than 80 % of the Canadian addresses;
- any range is wider than a /8;
- a list changes by more than 10 % of its addresses since the previous build (a manual run with `force` accepts it).

To build locally: `python3 build.py`.

## Caveats

Registration country isn't location: a range registered to Canada can be used elsewhere, and the reverse. VPN and hosting lists are never complete.

## License

Code: MIT, see [LICENSE](LICENSE). The filtered list is derived from X4BNet lists_vpn, MIT, Copyright (c) 2026 X4B (Mathew Heard); its notice is included in [LICENSE](LICENSE). RIR statistics are published by the registries for public use.
