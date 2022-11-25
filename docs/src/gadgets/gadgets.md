# Gadgets

Gadgets are essentially libraries that give you access to common types and operations when defining circuits.

Gadgets implement the traits `R1CSVar`, `AllocVar`, `EqGadget`, `ToBitsGadget`, `ToBytesGadget`, and `CondSelectGadget`, which provide common methods used when defining circuits.

### `AllocVar`

Lets you instantiate constant values or public/private inputs of the type implementing it on your circuit. It provides the methods `new_variable`, `new_constant`, `new_input` and `new_witness`.

### `R1CSVar`
Provides three methods that are usually used underneath when generating constraints: 
- `cs()` returns the underlying constraint system.
- `is_constant()` is self-explanatory.
- `value()` returns the underlying value of the variable.

### `EqGadget`

Has various methods for both checking or enforcing equality or inequality: `is_eq`, `is_neq`, `enforce_equal`, etc.

### `ToBitsGadget`

Has methods to convert the type to bits. Note that "bits" here does not mean regular 8 bit integers, but rather bits inside a circuit, i.e., zeroes or ones in the underlying finite field (they are represented as `Boolean`s, a gadget we'll talk about below). Methods include `to_bits_le`, `to_bits_be`, etc.

### `ToBytesGadget`
Gives you the `to_bytes()` method to  convert the type to a byte array (i.e. `Vec`). Once again, note that "byte" here does not mean the regular byte you're used to, but rather a byte representation in a finite field. This representation is provided by the `UInt8` gadget that we'll discuss below.

### `CondSelectGadget`
Lets you generate constraints to select between to values. There's `conditionally_select(cond, true_value, false_value)` (if `cond` is `true` it returns `true_value`, otherwise it returns `false_value`) and `conditionally_select_power_of_two_vector(position, values)` (returns an element of `values` whose index in represented by `position`. `position` is an array of boolean that represents an unsigned integer in big endian order). I don't know exactly where they're used for, they seem fairly low level.


## `Boolean`

Boolean type inside a circuit/R1CS. Example:

```rust
use ark_r1cs_std::bits::boolean::Boolean;
use ark_ed_on_bls12_381::Fq;

let a = Boolean::new_input(cs, || Ok(true))?;
a.enforce_equal(&Boolean::TRUE)?;

let not_a = Boolean::not(&a);
not_a.enforce_equal(&Boolean::FALSE)?;

let result = a.and(&not_a)?;
result.enforce_equal(&Boolean::TRUE)?;
```

For a more interesting one, here's sample code from arkworks that enforces the validity of a given transaction.
```rust
// Validate that the transaction signature and amount is correct.
tx.validate(
    &ledger_params,
    &sender_acc_info,
    &sender_pre_path,
    &sender_post_path,
    &recipient_acc_info,
    &recipient_pre_path,
    &recipient_post_path,
    &initial_root,
    &final_root,
)?.enforce_equal(&Boolean::TRUE)
```

The `validate` method is ultimately a very complex circuit using a variety of gadgets for Merkle proof and Schnorr signature verification that returns a `Boolean`.

This gadget is also a building block for pretty much all other types, as it's the finite field representation of a bit. This way, types like `UInt8` (see below) are implemented as arrays of `Boolean`s underneath.

## `UInt8`

Unsigned 8 bit integer type for circuits. Example:

```rust
use ark_r1cs_std::bits::uint8::UInt8;

let a = UInt8::new_input(cs, || Ok(1))?;

let result = a.xor(&a)?;
let zero = UInt8::constant(0);
result.enforce_equal(&zero)?;
```

As hinted above, it's important to understand that, underneath, a `UInt8` is nothing more than an array of finite field elements. This has consequences for its use. For example, the `verify` function provided by the `Marlin` crate expects to be passed an array of the corresponding circuit's public inputs. Because this API is pretty low level and operations all happen in a elliptic curve over a finite field, the elements of this array are expected to be of type `F: Field`.

However, when defining a circuit, you will usually be using high level constructs like `UInt8`. If you define a public input to be of type `UInt8`, when verifying you are responsible for making the conversion from it to `&[F]`. Note that this conversion is not simply using the `from` function given by finite fields, i.e., if your public inputs is a `UInt8` of value `1`, you can't do

```rust
F::from(1)
```

as the representation is actually

```rust
let one = F::from(1);
let zero = F::from(0);
let public_input = vec![one, zero, zero, zero, zero, zero, zero, zero]
```

There's a `to_bits_le` method defined by the `ToBitsGadget` that `UInt8` implements, but it gives you a `Vec<Boolean<F>>`, not a `Vec<F>`. Another extra conversion needs to be made from `Boolean` to `F`.

## `UInt16`, `UInt32`, `UInt64` and `UInt128`

Pretty self-explanatory, though they are defined through macros. Example:

```rust
use ark_r1cs_std::bits::uint16::UInt16;

let a = UInt16::new_input(cs, || Ok(1))?;
let b = UInt16::new_witness(cs, || Ok(2))?;
let c = UInt16::constant(3);

let result = UInt16::addmany(&[a, b]).unwrap();
result.enforce_equal(&c)?;
```

`addmany` is an associated function (the rust equivalent of a Java static method) defined for these types. For some reason, it's not defined for `UInt8`. Note that the default behaviour for `addmany` (at least when compiling in `release`) is to overflow without warning. That is, the result of `u16::MAX + 1` is simply `0`.

## Lower level cryptographic types

TODO: There's stuff for fields, elliptic curves, pairings, polynomials and polynomial evaluations.
