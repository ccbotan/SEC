from hashall import toy_hash
pw_hash = "<PASSWORD>"
with open("words_alpha.txt") as f:
    for i, line in enumerate(f):
        word = line.strip()
        if toy_hash(word.encode('ascii')) == pw_hash:
        