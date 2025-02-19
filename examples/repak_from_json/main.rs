use {
    argh::FromArgs,
    culpa::throws,
    serde::Deserialize,
    std::{fs::File, path::PathBuf},
};

///
/// Example of creating and updateing a REPAK file using a JSON manifest.
///
/// 1. deser json list of files
/// 2. open or create a repak file
/// 3. add files not present in the repak file
///

#[derive(Deserialize)]
struct GlobalOptions {
    compression: Compression,
    encryption: Encryption,
    checksums: Vec<Checksum>,
}

// @todo take these from REPAK itself?
#[derive(Deserialize)]
enum Compression {
    #[serde(rename = "best")]
    Best,
    #[serde(rename = "none")]
    None,
}

// @todo take these from REPAK itself?
#[derive(Deserialize)]
enum Encryption {
    #[serde(rename = "none")]
    None,
}

// @todo take these from REPAK itself?
#[derive(Deserialize)]
enum Checksum {
    #[serde(rename = "sha3")]
    Sha3,
    K12,
}

#[derive(Deserialize)]
struct Asset {
    path: PathBuf,
    name: String,
    compression: Option<Compression>,
    encryption: Option<Encryption>,
    checksums: Option<Vec<Checksum>>,
}

#[derive(Deserialize)]
struct Manifest {
    global_options: GlobalOptions,
    assets: Vec<Asset>,
}

/// Create or update a REPAK library from JSON manifest.
#[derive(FromArgs)]
struct Args {
    /// JSON manifest file describing all assets.
    #[argh(positional)]
    manifest_file: PathBuf,
}

#[throws(anyhow::Error)]
fn main() {
    let args: Args = argh::from_env();
    let m: Manifest = serde_json::from_reader(File::open(args.manifest_file)?)?;
}
