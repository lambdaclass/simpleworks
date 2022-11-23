# Substract instruction

We want to substract $y$ from $x$, i.e., compute $x-y$ and generate the appropriate constraints.

We can currently add any amount of unsigned integers and produce the constraints.

## Ideas

- We can first compute $-y$ (with its constraints) and then do `addmany([x, -y])`. This requires creating a function `fn additive_inverse(UInt64) -> Int64` that gives you the inverse and adds the constraints. Notice that this function will return a *SIGNED* integer, so the `addmany` would have to be performed on signed integers and then casted back. In particular, we would have to implement the `Int64` gadget and its `addmany` method.
- We could manually generate the constraints associated with doing $x-y$.

## How `addmany` works

The `addmany` function takes an array of `UInt64`s to sum. The high level idea of it is to enforce a constraint (i.e. an equation of the form $A  B = C$) that looks like this:

```
0 * 0 = x + y - (x + y)
```

This way, we only need to create one `LinearCombination` (`C` in the equation above) where we store `x`, `y` and their sum.

With that said, the function does the following:

- Initialize an `lc` of type `LinearCombination` as empty (i.e. zero) where we are going to add `x`, `y`, and `-(x + y)`.
- Initialize a `result_value` of type `BigUint` as zero; this will hold the result of `x + y` outside the circuit.
- For each operand (in our example just `x` and `y`):
    - add the value of the operand to `result_value`
    - for each bit of the operand:
        - add the `(coefficient * F::one, bit)` value to the linear combination `lc`, where `coefficient` is the bit number. The idea here is the first bit adds either $0$ or $1$ in the finite field, the second one adds $0$ or $2$, the thirds one $0$ or $4$, etc.
- For each bit of `result_value` (which now contains the result of $x+y$):
    - Create a `Boolean` witness variable with the value of the bit. We're creating these so we can return the result as a `UInt64`, which is just an array of `Boolean`s.
    - Substract from the linear combination `lc` the value `(coefficient * F::one, bit)`, where coefficient is the same as explained above.
- Enforce the constraint `(lc!(), lc!(), lc)`, i.e. `(0, 0, lc)`, setting `A` and `B` to zero and `C` to `x + y - (x + y)`.
- Return `x + y` as a `UInt64` using the witness variables constructed above.
