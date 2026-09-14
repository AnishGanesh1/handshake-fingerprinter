"""Handshake Fingerprinter — passive TLS (JA3/JA4) malware-C2 detection.

Package layout (implemented across the 14-day plan):

    parse.py     ClientHello byte parser          [Day 2]
    ja3.py       JA3 string + md5                  [Day 3]
    ja4.py       JA4 a_b_c fingerprint            [Day 4]
    db.py        sqlite fingerprint store         [Day 5]
    capture.py   pcap iteration + live sniff      [Day 1 / Day 8]  <-- done
    features.py  ML feature vectors               [Day 9]
    model.py     train / predict                  [Day 9]
    report.py    JSON + terminal report           [Day 11]
"""

__version__ = "0.1.0"
