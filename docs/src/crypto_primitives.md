# Crypto Primitives

## Pedersen Hash Function/Commitment

The Pedersen hash functions are nothing more than fixing an elliptic curve point `G`, and then
doing 
```
hash(x) = xG
```
for a given `x`, which is an element of a finite field. The Pedersen `parameters` are just the sampling of the `G`. Different values of `G` give rise to a different Pedersen Hash.

Note that there's a very important difference between popular hash functions like `Keccak`/`SHA3` and `Pedersen`: the input of `SHA3` is just an array of bytes of arbitrary length, and its output a fixed byte array. On the other hand, `Pedersen`'s input has to be a finite field element (and therefore cannot be of arbitrary length) and its output is an elliptic curve element. Indeed, this is the entire point of it; it's meant to be used in the context of ZK-SNARKS/circuits, where computation is done on elliptic curves over finite fields.

The above poses a problem for `Pedersen` however. When using it as the underlying hash function for a Merkle Tree, one needs to take a pair of leaves or nodes and hash both to produce the next node in the tree. When using something like `SHA3`, what we do is hash the concatenation of the leaves/nodes, so we can use the same hash function we use to hash leaves to hash pairs of inner nodes. In the `Pedersen` case we can't do this, because the length of its inputs is fixed; concatenating inputs will not work.

Because of this, `Pedersen` is usually divided into categories called `OneToOne`, `TwoToOne`, `FourToOne`, etc. `OneToOne` takes one input and produces one output, so it's used for hashing leaves; `TwoToOne` takes two inputs into one output and it's used for hashing pairs of leaves/nodes, and so on.

With this in mind, let's take a look at the `MerkleTree` struct defined in `Arkworks`:

```rust
pub struct MerkleTree<P: Config> {
    /// stores the non-leaf nodes in level order. The first element is the root node.
    /// The ith nodes (starting at 1st) children are at indices `2*i`, `2*i+1`
    non_leaf_nodes: Vec<TwoToOneDigest<P>>,
    /// store the hash of leaf nodes from left to right
    leaf_nodes: Vec<LeafDigest<P>>,
    /// Store the two-to-one hash parameters
    two_to_one_hash_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the height of the MerkleTree
    height: usize,
}
```

Here, the `leaf_nodes` are of type `LeafDigest`, which are different from the `non_leaf_nodes`, which are `TwoToOneDigest`. These are generic types that represent the output of a `OneToOne` and `TwoToOne` ZK-Friendly hash function (like `Pedersen`, but it could be another one), respectively.

Additionally, there are `leaf_hash_param` and `two_to_one_hash_param` fields, containing the parameters mentioned above for the `OneToOne` and `TwoToOne` hash functions, respectively.

If you're wondering, the generic type `Config` just contains the types of the two hash functions used:

```rust
pub trait Config {
    type LeafHash: CRH;
    type TwoToOneHash: TwoToOneCRH;
}
```

`CRH` stands for `Collision Resistant Hash`.

### Pedersen Commitment

So far we have only talked about the `Pedersen` hash function, not the commitment. Even though one usually thinks of all hash functions as commitments themselves, cryptographers do not consider the above `Pedersen` hash function as one. The reason is that a commitment must satisfy two properties:

- It must be `binding`. The commiter must not be able to open the commitment at a different value than they originally commited to. Let's go through a concrete example with hash functions to explain what this means. Let's say Alice and Bob go through a guessing game, where Alice chooses a number between 1 and 10 and Bob has to guess it.

    To make sure Alice isn't cheating, she first hashes the number and gives the hash to Bob. Thanks to this, when the game ends and Alice reveals the number `x` she chose, Bob can check whether Alice is lying or not by hashing it. This relies on one assumption, namely, that the hash function will not give the same result for two different values of `x` (this is known  as `collision resistance`).
-  It must be `hiding`. A commitment to some data should not reveal anything about it.

The `Pedersen` hash above is `binding`, as it's collision resistant, but it is not `hiding`. This is because the hash of the data reveals something about it, the hash itself. This might seem like a minor thing but it's actually a big deal.

Let's say we're working with a private blockchain, where a user's balance has to live on the blockchain for auditability, but needs to be private. One way to do it would be to store *hashes* of user balances. This way, users *commit* to their balance on-chain without revealing it. If we used the `Pedersen` hash to do this, however, we would run into a problem. People could precompute the hashes of common values and then check for them on-chain.

For instance, we could compute the hash of `0`, obtaining `hash(0)`. Then we would immediately know which users have zero balance, by just scanning for balances with the `hash(0)` value.

To fix this, the `Pedersen` commitment is introduced. It works in the same way as the hash, but in addition to doing `xG`, we sample another public random curve point `H` and then, to compute the commitment of `x`, we sample a random number `r`. Then, the pedersen commitment is

```
commit(x) = xG + rH
```

This is now hiding, as the random value `r` makes the result different each time we commit. In the blockchain example above, the `0` balance does not always give the same pedersen commitment, as different people will sample a different value for `r`. People can no longer precompute the commitment of `0`, because there's no such thing as the one commitment of `0`. The important bit here is that, in order for this to work, people should always use a different value for `r`, which is sometimes referred to as a `nonce`.
