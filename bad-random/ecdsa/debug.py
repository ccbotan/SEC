import snoop
import time
from ecdsa import NIST256p, SigningKey
import hashlib

def main():
    b = b'%d' % time.time()
    h = hashlib.sha256(b).digest()
    secexp = int.from_bytes(h, "big")

    with snoop(depth=3):          # 只包住你想追的这一段
        sk = SigningKey.from_secret_exponent(secexp, curve=NIST256p)
        vk = sk.verifying_key

    print(str(vk.to_pem(), "ascii"))

if __name__ == "__main__":
    main()
