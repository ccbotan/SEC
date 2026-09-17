A. The lookups failed with an exception of "Root hash mismatch". The client checks his root hash with the server's, and figure out that they are differed in it.

B. After a server restart, the root hash of client which is aligned with the original one cannot match the renewed hash of the server. If they didn't fail, then the adversary can attack the store and the cli is unconcious about it.

C. There are 9 siblings that are included. the layers of the tree after we inserted pairs of (foo, bar) and (hello, world) reached 9, when the leaf nodes down there is (foo, bar) in the left and (hello, world) in the right. when we are traversing back, the top 8 left nodes are none which is represented by the hash of hash_empty().
