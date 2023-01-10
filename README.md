# Simpleworks

Arkworks made simple for us: the non cryptographer software plumbers.

This is still a WIP. We will publish many more examples and documentation in the upcoming weeks.
 
## Arkworks documentation and examples

There are five examples that serve as an introduction to arkworks. You can run them by doing:

``` shell
cargo test --example test-circuit
cargo test --example manual-constraints
cargo test --example merkle-tree
cargo test --example schnorr-signature
cargo test --example simple-payments
```

You can check out the code for them under the `examples` directory, and [a thorugh explanation of `test-circuit`, `manual-constraints` and `merkle-tree` on our site](https://entropy1729.github.io/simpleworks/overview.html) or by running it locally; with [mdbook](https://rust-lang.github.io/mdBook/) installed, you can do 

```
cd docs
mdbook serve --open
```

to serve the docs on your machine.
