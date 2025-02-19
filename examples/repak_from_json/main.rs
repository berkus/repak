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
    compression: Option<Compression>,
    encryption: Option<Encryption>,
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
    let m: Manifest = serde_json::from_reader(File::open(args.manifest_file)?)?;

    let mut repak = repak::open(&args.repak_file)?;

    for asset in m.assets {
        let entry = repak.lookup(asset.name.clone())?;
        if entry.is_none() {
            repak.append(asset.name, &asset.path)?;
            // @todo options
        }
    }

    repak.save()?;
}
