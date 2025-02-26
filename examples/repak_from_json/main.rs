#![allow(dead_code)]
#![allow(unused_imports)]

use {
    anyhow::{Context, Result},
    argh::FromArgs,
    culpa::throws,
    repak::AppendOptions,
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
    compression: Option<Compression>,
    encryption: Option<Encryption>,
    checksums: Vec<Checksum>,
}

// @todo take these from REPAK itself?
#[derive(Deserialize)]
enum Compression {
    #[serde(rename = "best")]
    Best,
    #[serde(rename = "zstd")]
    Zstd,
    #[serde(rename = "none")]
    None,
}

// @todo take these from REPAK itself?
#[derive(Deserialize)]
enum Encryption {
    #[serde(rename = "none")]
    None,
}

#[derive(Deserialize)]
enum Checksum {
    #[serde(rename = "sha3")]
    Sha3,
    #[serde(rename = "k12-256")]
    K12,
    #[serde(rename = "blake3-256")]
    Blake3,
    #[serde(rename = "xxhash3-256")]
    Xxhash3,
    #[serde(rename = "metrohash-128")]
    MetroHash,
    #[serde(rename = "seahash")]
    SeaHash,
    #[serde(rename = "cityhash")]
    CityHash,
}

impl From<Checksum> for repak::ChecksumKind {
    fn from(c: Checksum) -> Self {
        match c {
            Checksum::Sha3 => repak::ChecksumKind::SHA3,
            Checksum::K12 => repak::ChecksumKind::K12,
            Checksum::Blake3 => repak::ChecksumKind::BLAKE3,
            Checksum::Xxhash3 => repak::ChecksumKind::Xxhash3,
            Checksum::MetroHash => repak::ChecksumKind::MetroHash,
            Checksum::SeaHash => repak::ChecksumKind::SeaHash,
            Checksum::CityHash => repak::ChecksumKind::CityHash,
        }
    }
}

#[derive(Deserialize)]
struct Asset {
    path: PathBuf,
    name: Option<String>,
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
    /// REPAK file to create and/or update.
    #[argh(positional)]
    repak_file: PathBuf,

    /// JSON manifest file describing all assets.
    #[argh(positional)]
    manifest_file: PathBuf,
}

#[throws(anyhow::Error)]
fn main() {
    let args: Args = argh::from_env();
    let m: Manifest =
        serde_json::from_reader(File::open(args.manifest_file).context("Open JSON manifest file")?)
            .context("Parsing JSON manifest")?;

    let mut repak = if std::fs::exists(&args.repak_file)? {
        repak::open(&args.repak_file).context("Opening REPAK file")?
    } else {
        repak::create(&args.repak_file).context("Creating REPAK file")?
    };

    for asset in m.assets {
        let name = asset
            .name
            .unwrap_or_else(|| format!("{}", asset.path.display()));

        let entry = repak
            .lookup(name.clone())
            .context("Looking up REPAK resource")?;
        if entry.is_none() {
            repak
                .append(name, &asset.path, AppendOptions::default())
                .context("Adding REPAK resource")?;
            // @todo options
        }
    }

    repak.save()?;
}
