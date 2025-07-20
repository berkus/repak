# REPAK project

REPAK is a Rust infrastructure for reading and writing packaged resources files, similar to DOOM WAD or Quake PAK format. It is designed to be fast, simple and extensible. The file format specification is located in @doc/REPAK.md.

Main code is located in `src/` while there is also example code in `examples/repak_from_json` which uses the main library APIs and needs to be updated with relevant changes.

## Build & Commands

Build with `just build` to check all features (there are many individual features).
Run all tests with `just test-all`. Run individual tests with `cargo test` as you would normally.
Format code with `just fmt`.
Style check with `just style`.

## Code style

Follow the Rust code style as enforced by the `cargo fmt` command, check for style violations with `cargo clippy -- -D clippy::pedantic`.

## Testing

- DO NOT write tests, unless explicitly asked to.

## Architecture

The format is suited for streaming usage - you can set up an asset encoding pipeline and stream a file piece by piece into it and it will do all the corresponding steps (i.e. checksum, compress and encrypt, in this order) and then update the asset data record with all necessary information (checksummers used, generated checksums, compressor used, decompressed data size, any additional information about encryption, if necessary, like salt - but NOT the encryption key). Reading works the same way - based on the asset data record from the Index, a reading pipeline is set up and reader is set in the source file so that when you try to read from it, the pipeline will decrypt, decompress and checksum the data - once finished you can check that checksums matched the recorded ones.

## Git Workflow

- ALWAYS run all compilation, tests and style checks before committing
- Fix linting errors before committing
- NEVER use `git push --force` on the main branch
- Use `git push --force-with-lease` for feature branches if needed
- Always verify current branch before force operations

## General rules

- DO NOT explain every step.
- DO NOT provide summary of the changes you made.
