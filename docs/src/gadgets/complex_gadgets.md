# Complex Gadgets/Merkle Tree Example

So far we've been discussing the circuit equivalent of primitive types that all programming languages support. Eventually, the need for custom types (i.e. structs) arises.

For this, let's go through an example of how this would work. The following will be taken from the `MerkleTree` example [here](https://github.com/Entropy1729/simpleworks/tree/main/examples/merkle-tree). The goal is to create a circuit that, given a merkle root, leaf and a path to the leaf, decides whether the leaf belongs to the tree or not.

So we don't reinvent the wheel, we are going to use a fixed height merkle tree implementation provided by the `crypto-primitives` package in arkworks. This gives us a struct 

```rust
pub struct MerkleTree<P: Config>
```

where the `Config` is just a generic type with the hash functions used for the tree (yes, it's functions in plural, check the [crypto primitives section](../crypto_primitives.md) for details on this). This struct provides us with methods to instantiate a merkle tree with 
a given list of leaves:

```rust
/// Returns a new merkle tree. `leaves.len()` should be power of two.
pub fn new<L: ToBytes>(
    leaf_hash_param: &LeafParam<P>,
    two_to_one_hash_param: &TwoToOneParam<P>,
    leaves: &[L],
) -> Result<Self, crate::Error>
```

and to generate a merkle path for a given leaf:

```rust
/// Returns the authentication path from leaf at `index` to root.
pub fn generate_proof(&self, index: usize) -> Result<Path<P>, crate::Error>
```

For our example, this is enough. So far we have a regular merkle tree Rust struct, but what we're looking for is an arkworks circuit to generate and verify ZK proofs of inclusion for this tree. What we'll do is create a second struct to represent this circuit:

```rust
#[derive(Clone)]
pub struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit.
    pub root: Root,
    pub leaf: u8,

    // This is the private witness to the circuit.
    pub authentication_path: Option<SimplePath>,
}
```

Don't worry too much about the `leaf_crh_params` and `two_to_one_crh_params`, they're just variables related to the hash functions being used.

If we recall the [overview](../overview.md#simple-circuit), to turn this struct into a circuit all we have to do is implement the `generate_constraints` method for the `ConstraintSynthetizer` trait. This pattern is a very common one throughout arkworks and it's the same one we used in the overview example, the idea is that the fields of our circuit struct are its constant, public and private inputs exposed as regular rust types.

In turn, each of these types has a corresponding `R1CS` equivalent, which allows creating constant, public or private inputs inside a circuit out of these regular rust types. The simplest example of this is the `UInt8` gadget we've already covered; it lets you define unsigned 8 bit integers inside a circuit, which is exactly what we need for our leaf public input.

The idea behind this pattern is to give an API to users that entirely abstracts them from the circuit logic. By providing a `MerkleTreeVerification` struct with regular types as fields, users of the circuit don't need to know what gadgets or constraints are.

All that being said, our `generate_constraints` method looks like this:

```rust
fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;
        let leaf = UInt8::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.authentication_path.as_ref().unwrap())
        })?;

        let leaf_bytes = vec![leaf; 1];

        let is_member = path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_bytes.as_slice(),
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
```

First we allocate a `RootVar` public input, which is the `R1CS` equivalent of a merkle root. This is a type provided by arkworks, which underneath implements the `AllocVar` trait discussed above. As a general rule, if a type ends with `Var`, then it's most likely the `R1CS` equivalent of a regular type. The value for our `RootVar` public input is `&self.root`, i.e., the `root` field value of our `MerkleTreeVerification` struct.

Next we allocate a `UInt8` public input representing our leaf and the constant values for `leaf_crh_params` and `two_to_one_crh_params`. Again, we're not going to go into much detail about these two parameters, but they're provided by arkworks and are the `R1CS` equivalent of the parameters required by our merkle tree hash functions (see [crypto primitives](../crypto_primitives.md#pedersen-commitment) for more details).

Finally, we have to allocate our private input representing the merkle path, of type:
```rust 
pub struct SimplePathVar = PathVar<crate::MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>
```
This is a gadget provided by arkworks, the `R1CS` equivalent of `Path<P: Config>`, it's a bit more complex than the other gadgets we've seen so far and it's at the crux of this entire circuit, so let's dive more into it.

As the `R1CS` equivalent of `Path`, `PathVar` consists of the following fields

```rust
pub struct PathVar<P, LeafH, TwoToOneH, ConstraintF>
{
    /// `path[i]` is 0 (false) iff ith non-leaf node from top to bottom is left.
    path: Vec<Boolean<ConstraintF>>,
    /// `auth_path[i]` is the entry of sibling of ith non-leaf node from top to bottom.
    auth_path: Vec<TwoToOneH::OutputVar>,
    /// The sibling of leaf.
    leaf_sibling: LeafH::OutputVar,
    /// Is this leaf the right child?
    leaf_is_right_child: Boolean<ConstraintF>,
}
```

(I'm ommiting the generic type definitions to reduce visual clutter). This struct implements the `AllocVar` trait to be able to create public, private or constant variables by implementing the `new_variable` method:

```rust
fn new_variable<T: Borrow<Path<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let leaf_sibling = LeafH::OutputVar::new_variable(
                ark_relations::ns!(cs, "leaf_sibling"),
                || Ok(val.borrow().leaf_sibling_hash.clone()),
                mode,
            )?;
            let leaf_position_bit = Boolean::new_variable(
                ark_relations::ns!(cs, "leaf_position_bit"),
                || Ok(val.borrow().leaf_index & 1 == 1),
                mode,
            )?;
            let pos_list: Vec<_> = val.borrow().position_list().collect();
            let path = Vec::new_variable(
                ark_relations::ns!(cs, "path_bits"),
                || Ok(&pos_list[..(pos_list.len() - 1)]),
                mode,
            )?;

            let auth_path = Vec::new_variable(
                ark_relations::ns!(cs, "auth_path_nodes"),
                || Ok(&val.borrow().auth_path[..]),
                mode,
            )?;
            Ok(PathVar {
                path,
                auth_path,
                leaf_sibling,
                leaf_is_right_child: leaf_position_bit,
            })
    })
}
```

When we called

```rust
SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
    Ok(self.authentication_path.as_ref().unwrap())
})?;
```

passing our `authentication_path` struct (i.e., our non-R1CS merkle path) in our circuit definition above, this internally called the `new_variable` method, which instantiates its internal fields by using the appropriate fields in our `authentication_path`.

After creating a merkle path variable in our circuit, we call its `verify_membership` method to check that the path is correct

```rust
let is_member = path.verify_membership(
    &leaf_crh_params,
    &two_to_one_crh_params,
    &root,
    &leaf_bytes.as_slice(),
)?;
```

this returns an `R1CS` `Boolean`, so we can then add a constraint to make sure it is true:

```rust
is_member.enforce_equal(&Boolean::TRUE)?;
```

Notice that the bulk of our `MerkleTree` circuit was just this gadget, which provides the `R1CS` API to use inside a circuit for checking merkle paths. Because it's a gadget, however, we can use it inside other circuits as part of more complex logic. For example, we could combine it with a gadget that verifies `Schnorr` signatures to create a circuit that takes a signed transaction updating some state in a merkle tree and checks both things: that the signature is valid and that the caller knew a leaf of the tree.
