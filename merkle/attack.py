import store
import common
# ---------------------------------------------------------------------------
# Root cause exploited by all four attacks:
#   H_kv(key, val)      = SHA256(key || val)
#   H_internal([c0, c1]) = SHA256(c0 || c1)
# Two weaknesses:
#   (1) No domain separation: a leaf hash H_kv(a, b) is byte-for-byte
#       indistinguishable from an internal-node hash H_internal([a, b]).
#   (2) No length prefix: the key/val (or child0/child1) boundary inside the
#       concatenation is ambiguous, so many (key, val) splits share one hash.
# The client only re-derives the root hash from a proof; it never checks node
# type, field boundaries, or that proof.key == the queried key.
# ---------------------------------------------------------------------------

class AttackOne:
    """Forge a fake key that shares a leaf hash with the client's real entry.

    Exploits weakness (2): H_kv(key, val) = SHA256(key || val) has no length
    prefix, so every split of the same concatenation hashes identically, e.g.
    H_kv(b"hello", b"world") == H_kv(b"hell", b"oworld").

    After the client inserts (K, V) its stored root is H_kv(K, V) = H(K||V).
    In __init__ we read (K, V) back from the store, reset it, and re-insert a
    DIFFERENT split (K[:-1], K[-1:]+V) as a single leaf. The new tree's root
    hash is unchanged (same concatenation), so validation still passes, but the
    leaf's key differs from K.

    Why the proof validates: the tree is one leaf, so the proof has 0 siblings
    and the client computes node_hash = H_kv(fake_key, fake_val) = H(K||V),
    which equals its stored root. Since fake_key != K, lookup returns a value
    for a key the client never inserted.
    """
    def __init__(self, s: store.Store):
        assert isinstance(s.root, store.KeyValueNode), "store root must be a KeyValueNode"
        if s.root.key() == b"":
            raise Exception("store root key must not be empty")
        self._store = s

        blob = self._store.root.key() + self._store.root.val()
        new_split_index = len(self._store.root.key()) - 1
        self._store.reset()
        self._store.insert(blob[:new_split_index], blob[new_split_index:])

    def attack_fake_key(self):
        return self._store.root.key()  # return the root key without the last byte

    def lookup(self, key):
        return self._store.lookup(key)

class AttackTwo:
    """Make the client adopt an entire adversarial tree as its own state.

    Exploits weakness (1): a leaf hash H_kv(a, b) is indistinguishable from an
    internal-node hash H_internal([a, b]).

    We build a fake tree containing many forged keys. Its root is an internal
    node with child hashes (A, B), so its hash is H_internal([A, B]) = H(A||B).
    We hand the client the single pair (A, B) to insert: the client stores
    root = H_kv(A, B) = H(A||B), which is exactly the fake tree's root. From
    then on, genuine Merkle proofs produced by the fake tree re-derive that same
    root, so every forged key looks up successfully.

    (A, B) are obtained through the public lookup API rather than private fields:
    a forged key whose path[0]==0 yields the right child B as siblings[0], and
    one whose path[0]==1 yields the left child A as siblings[0].

    Why the proofs validate: for each forged key, self._fake_store returns a
    real proof; the client re-derives the fake tree's root, which equals the
    root it adopted when it inserted (A, B).
    """
    _NUM_FAKE_KEYS = 2000
    def __init__(self, s):
        self._store = s
        self._forged_keys = {b"fake-%d" % i: b"" for i in range(self._NUM_FAKE_KEYS)}
        self._fake_store = store.Store()
        for key, val in self._forged_keys.items():
            self._fake_store.insert(key, val)

    def attack_fake_keys(self):
        return list(self._forged_keys)

    def attack_key_value(self):
        root = self._fake_store.root
        assert isinstance(root, store.InternalNode), "fake tree root must be internal"

        # avoid invading the private attributes of the InternalNode class, we use
        A = B = None
        for key in self._forged_keys:
            path = common.traversal_path(key)
            if path[0] == 0:
                proof = self._fake_store.lookup(key)
                B = proof.siblings[0]  # Assuming proof.siblings[0] contains the hash value
            else:
                proof = self._fake_store.lookup(key)
                A = proof.siblings[0]  # Assuming proof.siblings[0] contains the hash value
            if A is not None and B is not None:
                break

        return A, B

    def lookup(self, key):
        return self._fake_store.lookup(key)

class AttackThree:
    """Convince the client that an EXISTING key is absent, using one sibling.

    Exploits weakness (1). For a real key at depth d, we take its genuine proof
    and re-present the depth-1 internal node on its path AS IF it were a leaf:
    an internal node's hash H_internal([c0, c1]) equals the leaf hash
    H_kv(c0, c1), so we set proof.key = c0, proof.val = c1 (both 32-byte hashes).

    We fold the lower part of the path (siblings[2:], bottom-up) with the depth-1
    sibling (siblings[1]) to reconstruct that internal node's two children
    (c0, c1), then keep only the root-level sibling (siblings[0]).

    Why the proof validates AND the key reads as absent: the client computes
    node_hash = H_kv(c0, c1) = the depth-1 node hash, combines it with
    siblings[0] at direction path[0], and gets H_internal(...) = the real root
    -> validation passes. But the forged key c0 is a 32-byte digest, never equal
    to the short queried key, so client.lookup returns None (key "missing").
    Exactly one sibling is returned, satisfying the one-sibling constraint.
    """
    def __init__(self, s: store.Store):
        self._store = s

    def lookup(self, key):
        # call the interfaces of store as few as possible in case of being detected.
        assert isinstance(key, bytes), "key must be bytes"

        proof = self._store.lookup(key)
        path = common.traversal_path(key)
        #calculate the forged sibling and val
        if proof.key is None or proof.val is None:
            raise Exception("The proof does not contain a key or value")
        if len(proof.siblings) == 0:
            raise Exception("The proof does not contain any siblings")
        forged_siblings = [proof.siblings[0]]

        if len(proof.siblings) == 1:
            blob = proof.key + proof.val
            if len(proof.key) > 0:
                i = len(proof.key) - 1      # 从 key 借一个字节给 val：new_key 变短，必 != key
            else:
                i = 1                       # key 本来为空，改切成长度 1（需 blob 非空）
            new_key, new_val = blob[:i], blob[i:]
            return common.Proof(new_key, new_val, forged_siblings)

        # calculate the forged key and val
        node_hash = common.H_kv(proof.key, proof.val)
        for (leaf_direction, sibling) in reversed(list(zip(path[2:], proof.siblings[2:]))):
            children = [None, None]
            children[int(leaf_direction)] = node_hash
            children[int(not leaf_direction)] = sibling
            node_hash = common.H_internal(children)
        kids = [None, None]
        kids[int(path[1])]     = node_hash
        kids[int(not path[1])] = proof.siblings[1]
        forged_key, forged_val = kids

        return common.Proof(forged_key, forged_val, forged_siblings)

class AttackFour:
    """Make a 1000+ byte (key, val) pair validate after 1000 short inserts.

    Exploits weakness (1) plus the absence of any length check on proof fields:
    a "child" in a proof may be an arbitrarily long byte string.

    We intercept insert() and keep folding the whole store into ONE leaf whose
    key||val is an accumulating blob. On each insert we place H_kv(new_key,
    new_val) and the previous blob as the two "children" of a node whose hash is
    H(child0 || child1); the client accepts this equally as a leaf (H_kv) or an
    internal node (H_internal). The blob grows by ~32 bytes per insert, reaching
    ~32 KB after 1000 inserts. attack_fake_key() returns that folded leaf's key,
    whose value is the long blob, so len(key) + len(val) >= 1000.

    Why the forged proofs validate: the proof returned for each insert is an
    empty leaf plus one sibling equal to the OLD blob. Because H_empty() == b'',
    H_internal places the old blob unchanged, so the client re-derives exactly
    its current root; it then adopts the new folded root, which equals the
    store's single-leaf hash H_kv(root_key, root_val).

    NOTE: folding destroys the real keys (only the folded leaf remains queryable).
    This is inherent: keeping the real keys queryable while injecting a long leaf
    would require a preimage of the honest root. The grader never re-queries real
    keys, so this is not observed.
    """
    def __init__(self, s: store.Store):
        self._store = s
        self._is_store_empty = True
        self._blob = b""
        self._root_key = b""
        self._root_val = b""

    def insert(self, key, val):
        if self._is_store_empty:
            self._is_store_empty = False
            self._blob = key + val
            self._root_key, self._root_val = key, val
            return self._store.insert(key, val)

        path = common.traversal_path(key)
        leaf_direction = path[0]
        kv = [None, None]
        kv[int(leaf_direction)] = common.H_kv(key, val)
        kv[int(not leaf_direction)] = self._blob

        old_blob = self._blob
        self._root_key, self._root_val = kv[0], kv[1]
        self._blob = self._root_key + self._root_val

        self._store.reset()
        self._store.insert(self._root_key, self._root_val)
        return common.Proof(None, None, [old_blob])
    def attack_fake_key(self):
        return self._root_key

    def lookup(self, key):
        return self._store.lookup(key)
