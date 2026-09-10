A. The lookups failed with an exception of "Root hash mismatch". The client checks his root hash with the server's, and figure out that they are differed in it.

B. After a server restart, the root hash of client which is aligned with the original one cannot match the renewed hash of the server. If they didn't fail, then the adversary can attack the store and the cli is unconcious about it. 

C. There are 9 siblings that are included. the layers of the tree after we inserted pairs of (foo, bar) and (hello, world) reached 9, when the leaf nodes down there is (foo, bar) in the left and (hello, world) in the right. when we are traversing back, the top 8 left nodes are none which is represented by the hash of hash_empty(). 




Proof of subtree: key=b'foo', val=b'bar', node_hash=b'\xc3\xab\x8f\xf17 \xe8\xad\x90G\xdd9Fk<\x89t\xe5\x92\xc2\xfa8=J9`qL\xae\xf0\xc4\xf2'
Traversal path for b'foo' is left
Right sibling hash from proof is b'\x93j\x18\\\xaa\xa2f\xbb\x9c\xbe\x98\x1e\x9e\x05\xcbx\xcds+\x0b2\x80\xeb\x94D\x12\xbbo\x8f\x8f\x07\xaf'
Computed subtree hash: b'\n\xdcy\xb7\x97P\x16B~\xf0\xc39\x14\xee}4\xe6\xf5\x08\xcc\xde\xda\xfalt\xe9n\x00\x9d3\xcf\x84'
Traversal path for b'foo' is left
Right sibling hash from proof is b''
Computed subtree hash: b'qgg\x9f\xef\xec@\xaa\x8d\xec\x80|\xc0\x89\xe4y\xe8dl\xbd\x8c\xfa\x9f\xe2K>\x05\xa3F&\xb2\xf4'
Traversal path for b'foo' is left
Right sibling hash from proof is b''
Computed subtree hash: b't\xc7[b\xb4\xd6\xa6\xfb\n\xdf\x08S\x90\x88\xd7\x9b\x93\x1b\xf0\x91`\xf0\x85\x14F&\r\xaa\xe16\xaa!'
Traversal path for b'foo' is right
Left sibling hash from proof is b''
Computed subtree hash: b'\x9d"\xe4\x1d_\x7f+\x9a)B\x15G\x13\x02U\xab\x10\xfe\xbd\xc4U\x9b#\xa8\\1\xf3HZ\xcb\xd8\xdf'
Traversal path for b'foo' is right
Left sibling hash from proof is b''
Computed subtree hash: b"\xabt%iu\xb2Z\xfcC\xa1|\xffN[a2\x82Lxcx'l\x8f\xa7*\xbc\xa0\xa7B\x06\x83"
Traversal path for b'foo' is left
Right sibling hash from proof is b''
Computed subtree hash: b'\xe5H\xf0\xe9N<eFF\xc4o)\x9b\x90A\x8b\xf0\xf0\x99\xeaN4=\x11\x0f\xc6\n\x7f\xeb\xbb\x19\x1d'
Traversal path for b'foo' is right
Left sibling hash from proof is b''
Computed subtree hash: b'!9\x92\xc3ZBy\xff\xc2&\x89\xff\x02\x8e\xd7\xa4W<\xea\x95\xd0\xae]\x91\x15/O:\r\x1a\xf4a'
Traversal path for b'foo' is left
Right sibling hash from proof is b''
Computed subtree hash: b'\x18\x0fH\x08\xae\xe4\xec v\x15\rF\x13\x0c\xd5\xc2h\x04 \xd4\xd3\xc14Z\xf82:\xf1 #"\x08'
Traversal path for b'foo' is left
Right sibling hash from proof is b''
Computed subtree hash: b'\xfb\x93YM\xf9q\xe1\xe6\xf1\xa6\x98m\x19\x16\x08\xc3\xb9\xa2,\x15\x80\xdf\x96\xa7\xcd\x82\x94QU#\xc4\xe8'