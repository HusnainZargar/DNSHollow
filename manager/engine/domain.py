"""Split a DNS name into its parent (registered) domain and subdomain part.

Example: "a.b.example.co.uk" -> parent "example.co.uk", subdomain "a.b"
Uses the public suffix list bundled with tldextract (no network needed).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache

import tldextract

# suffix_list_urls=() -> use the bundled snapshot, never fetch from the internet.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True)
class ParsedName:
    qname: str      # normalized full name
    parent: str     # registered domain, e.g. "example.co.uk"
    subdomain: str  # everything left of the parent, e.g. "a.b" ("" if none)

    @property
    def labels(self) -> list[str]:
        return [l for l in self.subdomain.split(".") if l]

    @property
    def depth(self) -> int:
        """Number of labels below the parent domain."""
        return len(self.labels)


def normalize(qname: str) -> str:
    return qname.strip().lower().rstrip(".")


@lru_cache(maxsize=65536)
def split_domain(qname: str) -> ParsedName:
    name = normalize(qname)
    if not name:
        return ParsedName("", "", "")

    # Bare IP address: nothing to split.
    try:
        ipaddress.ip_address(name)
        return ParsedName(name, name, "")
    except ValueError:
        pass

    ext = _extract(name)
    if ext.domain and ext.suffix:
        parent = f"{ext.domain}.{ext.suffix}"
        return ParsedName(name, parent, ext.subdomain)

    # Unknown TLD (.local, .lan, custom tunnel TLDs) or single label:
    # fall back to the last two labels as the parent.
    labels = name.split(".")
    if len(labels) <= 2:
        return ParsedName(name, name, "")
    return ParsedName(name, ".".join(labels[-2:]), ".".join(labels[:-2]))


def is_trusted(parent: str, trusted_domains) -> bool:
    """True if parent equals a trusted domain or is a subdomain of one."""
    for t in trusted_domains:
        t = normalize(t)
        if t and (parent == t or parent.endswith("." + t)):
            return True
    return False
