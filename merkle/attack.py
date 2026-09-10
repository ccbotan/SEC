import store
import common

class AttackOne:
    def __init__(self, s):
        self._store = s

    def attack_fake_key(self):
        return b"he"

    def lookup(self, key):
        self._store.reset()
        self._store.insert(b"he", b"lloworld")

        return self._store.lookup(key)

class AttackTwo:
    _NUM_FAKE_KEYS = 2000  
    def __init__(self, s):
        self._store = s
        self._forged_keys = {b"fake-%d" % i: b"" for i in range(self._NUM_FAKE_KEYS)}       
        self._fake_store = store.Store()
        for key, val in self._forged_keys.items():
            self._fake_store.insert(key, val)

    def attack_fake_keys(self):
        return dict(self._forged_keys)

    def attack_key_value(self):
        root = self._fake_store.root
        assert isinstance(root, store.InternalNode), "fake tree root must be internal"
        A = root._children[0].hashval()
        B = root._children[1].hashval()
        return A, B

    def lookup(self, key):
        return self._fake_store.lookup(key)

class AttackThree:
    def __init__(self, s):
        self._store = s

    def lookup(self, key):
        # call the interfaces of store as few as possible in case of being detected.
        assert isinstance(key, bytes), "key must be bytes"

        proof = self._store.lookup(key)
        path = common.traversal_path(key)
        #calculate the forged sibling and val
        if len(proof.siblings) == 0:
            raise Exception("The proof does not contain any siblings")
        else:
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
    def __init__(self, s: store.Store):
        self._store = s
        self._isStoreEmpty = True
        self._bolb = b""
        self._root_key = b""
        self._root_val = b""

    def insert(self, key, val):
        if self._isStoreEmpty:
            self._isStoreEmpty = False
            self._bolb = self._bolb.join([key, val])
            self._root_key = key
            self._root_val = val
            return self._store.insert(key, val)

        path = common.traversal_path(key)
        sibling = self._bolb
        leaf_direction = path[0]
        kv = [None, None]
        kv[int(leaf_direction)] = common.H_kv(key, val)
        kv[int(not leaf_direction)] = self._bolb
        self._root_key, self._root_val = kv[0], kv[1]
        self._bolb = self._root_key + self._root_val

        self._store.reset()
        self._store.insert(self._root_key, self._root_val)
        return common.Proof(None, None, [sibling])
    def attack_fake_key(self):
        return self._root_key

    def lookup(self, key):
        return self._store.lookup(key)
