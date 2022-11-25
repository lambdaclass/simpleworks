# Simpleworks

Arkworks made simple for us: the non cryptographer software plumbers.

This is still a WIP. We will publish many more examples and documentation in the upcoming weeks.
 
## Arkworks documentation and examples

There are five examples that serve as an introduction to arkworks. You can run them by doing:

``` shell
cargo test --release --example test-circuit
cargo test --release --example manual-constraints
cargo test --release --example merkle-tree
cargo test --release --example schnorr-signature
cargo test --release --example simple-payments
```

You can check out the code for them under the `examples` directory, and a thorugh explanation of:
- `test-circuit`
- `manual-constraints`
- `merkle-tree` [here](https://docs.cluster.entropy1729.com/arkworks/overview.html) (the Markdown source for it is [here](https://github.com/Entropy1729/docs/tree/main/mdbook/src/arkworks))
