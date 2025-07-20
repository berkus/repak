build:
    cargo build --all-features

test-all: test cli-example

test:
    cargo test --all-features

[working-directory: 'examples/']
cli-example:
    # Clean up temporarily, in the future it should be able to update.
    rm -f b.repak b.idpak
    cargo run --example repak_from_json -- b.repak assets/manifest.json

fmt:
    cargo fmt

style:
    cargo clippy -- -D clippy::pedantic

lint: fmt style
