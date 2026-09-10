from hashall import *
from hashbig import *
import os
import time

# return password, where toy_hash(password) = <HASH_OUTPUT_BY_GRADESCOPE>
def problem_2a():
    password = None
    script_dir = os.path.dirname(__file__)
    file_path = os.path.join(script_dir, "words_alpha.txt")
    target_hex = "a33a874eb313"
    target = bytes.fromhex(target_hex)
    with open(file_path) as f:
        for line in f:
            word = line.strip()
            digest = toy_hash(word.encode('ascii'))
            if digest == target:
                password = word
                break
    return password

# return password, where toy_hash(password) is in hashes.txt
def problem_2c():
    pw = None
    dir_path = os.path.dirname(__file__)
    hashes_path = os.path.join(dir_path, "hashes.txt")
    #passwd-keyboard-Top500.txt
    #passwd-EN-Top10000.txt
    with open(hashes_path) as h:
        targets = {bytes.fromhex(line.strip()) for line in h if line.strip()}

    wordlists = ["rockyou.txt"] 
    for wl in wordlists:
        path = os.path.join(dir_path, wl)
        if not os.path.exists(path):
            continue 
        with open(path, encoding= 'latin-1') as w:
            for line in w:
                pw = line.strip()
                if not pw:
                    continue
                try:
                    encoded = pw.encode('ascii')
                    digest = toy_hash(encoded)
                except UnicodeEncodeError:
                    continue
                if digest in targets:
                    return pw
    return pw

# return probability of being in bin k
def problem_3a(B, N):
    prob = None
    prob =  1 / N
    return prob

# return probability of both balls being in bin k
def problem_3b(B,N):
    prob = None
    prob = 1 / (N ** 2)
    return prob

# return number of ball pairs
def problem_3c(B):
    prob = None
    prob = B * (B - 1) / 2
    return prob

# return reasonable upper bound
def problem_3d(B,N):
    prob = None
    prob = N * B * (B - 1) / 2 * (1 / N ** 2)
    return prob
    
# return reasonable upper bound
def problem_3e(L,n):
    prob = None
    N = 2 ** n
    prob = N * L * (L - 1) / 2 * (1/ N ** 2)
    return prob

# return h1,h2 where H(h1) == H(h2)
def problem_4b():
    h1 = None
    h2 = None
    ring_length = 0
    tail_length = 0
    initial_val = "CSL".encode("ascii")

    # use Floyd's Cycle Detection Algorithm
    # search for a collision point in the ring

    c1 = H(initial_val)
    c2 = H(initial_val)
    c2 = H(c2)

    while c1 != c2:
        # print("No.", cnt, " h1: ", c1)
        c1 = H(c1)
        c2 = H(c2)
        c2 = H(c2)
    col_digest = c1
    print("Find the collision point!!")

    # Hash h1 and h2 until they collides
    h1 = initial_val    
    h2 = col_digest
    cnt = 1

    while True:
        # print("No.", cnt, " h1: ", h1, " h2: ", h2)
        tempval1 = H(h1)
        tempval2 = H(h2)
        if tempval1 == tempval2:
            break
        h1 = tempval1
        h2 = tempval2
        cnt = cnt + 1

    tail_length = cnt
    assert h1 != h2, "collision pair should not be identical!"        

    #calculate the length of the ring
    """target_hash = H(h1)
    temp_hash = H(target_hash)
    cnt = 1
    while target_hash != temp_hash:
        temp_hash = H(temp_hash)
        cnt = cnt + 1
    ring_length = cnt """

    # print("the length of the tail: ", tail_length)
    # print("the length of the ring: ", ring_length)

    # print("h1:", h1, "H(h1):", H(h1))
    # print("h2:", h2, "H(h2):", H(h2))
    # print("Find the hash collission!!!")

    return h1,h2

if __name__ == "__main__":
    start = time.perf_counter()
    problem_4b()
    end = time.perf_counter()
    print(f"耗时: {end - start:.4f} 秒") 
        