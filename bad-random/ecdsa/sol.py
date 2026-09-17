import time
import os
from multiprocessing import Pool
from datetime import datetime

import hashlib
from ecdsa import SigningKey, NIST256p, VerifyingKey
from ecdsa.ecdsa import Public_key

def problem_1a(date_string, verfkey: VerifyingKey):
    if date_string is None or verfkey is None:
        raise ValueError("date_string and verfkey cannot be None")
    if not isinstance(date_string, str):
        raise TypeError("date_string must be a string")
    if not isinstance(verfkey, VerifyingKey):
        raise TypeError("verfkey must be a VerifyingKey instance")

    # multiple processes running at the same time
    dt = datetime.strptime(date_string, "%Y-%m-%d")
    timestamp = int(dt.timestamp())
    print(f"Timestamp for {date_string}: {timestamp}")
    hashes = [hashlib.sha256(b'%d' % (timestamp + i)).digest() for i in range(0, 86400)]
    secexps = [int.from_bytes(h, "big") for h in hashes]

    n_cores = os.cpu_count()
    print(f"本机核心数: {n_cores}")

    with Pool(processes=n_cores) as pool:


def problem_2b(sig1, sig2, Hm1, Hm2):
    pass
