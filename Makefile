.PHONY: clippy test

clippy:
	cargo clippy --all-features -- -D warnings

test:
	cargo test
