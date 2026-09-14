"""ML feature extraction.  [Implemented on Day 9]

Turns a parsed ClientHello into a fixed-length numeric vector so a classifier
can score fingerprints that are NOT in the known-bad database.
"""

from __future__ import annotations

from typing import List

from .ja3 import GREASE, _clean  # noqa: F401  (used by the Day 9 implementation)

# Extensions whose presence/absence is informative (bitmap features).
KEY_EXTS = [0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 65281]


def featurize(ch: dict) -> List[int]:
    """Return the feature vector for a parsed ClientHello.  TODO(Day 9)."""
    raise NotImplementedError("featurize is implemented on Day 9")
