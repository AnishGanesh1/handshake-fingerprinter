"""ML feature extraction.  [Day 9]

Turns a parsed ClientHello into a fixed-length numeric vector so a classifier
can score fingerprints that are NOT in the known-bad database.
"""

from __future__ import annotations

from typing import List

from .ja3 import GREASE, _clean

# Extensions whose presence/absence is informative (bitmap features).
KEY_EXTS = [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 65281]

# Number of features featurize() returns — handy for sanity checks / tests.
N_FEATURES = 8 + len(KEY_EXTS)


def featurize(ch: dict) -> List[int]:
    """Return the numeric feature vector for a parsed ClientHello."""
    ciphers = _clean(ch["ciphers"])
    exts = set(ch["extensions"])
    return [
        len(ciphers),
        len(_clean(ch["extensions"])),
        len(ch["groups"]),
        len(ch["sig_algs"]),
        int(bool(ch["sni"])),
        int(bool(ch["alpn"])),
        int(any(c in GREASE for c in ch["ciphers"])),   # GREASE => modern browser
        max(_clean(ch["sup_ver"]), default=ch["client_version"]),
        *[int(e in exts) for e in KEY_EXTS],
    ]
