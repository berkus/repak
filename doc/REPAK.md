Asset library format similar in idea to Quake PAK or DOOM WAD files. The file is append-only, making it easy to insert new entries at the end, but removing older entries may require repacking the whole file. It is a nice format to use when assembling assets in the final game build, for example.

# Overall file structure

| Offset   | Contents                                                                                                                                                                     |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0        | Binary contents of assets, one after another without spaces.                                                                                                                 |
| X        | Compressed asset index.                                                                                                                                                      |
| File end | Offset of index from the end of file recorded in rULEB64 format (a specific subset of VLQ encoding), seeking this number of bytes from the end of file should land you at X, the very beginning of the index. |

# REPAK index

| Offset | Size   | Content         | Description                                                                                          |
| ------ | ------ | --------------- | ---------------------------------------------------------------------------------------------------- |
| 0      | 5      | "REPAK"         | Format marker                                                                                               |
| 5      | 1 (uleb!)     | 0x01            | Version                                                                                              |
| 6      |        | ChecksumHeader  | Checksum structure for the Index, see below for format. The contents of the header starting from `count` below and up until but not including the index locator are checksummed. |

| ?      | uleb64 | count           | Number of following index entries (included in the checksum)                                                                                                    |
| ?      |        | entries\[count] | Variable-sized entries array (included in the checksum)                                                                                                    |

Immediately following the last index entry is the index offset (locator) field at the file end.

When attached to the REPAK file, the index is usually compressed using `zstd`. A stand-alone index may be uncompressed, this can be checked by reading the format marker (`REPAK`).

The Index is _ordered by Name_ (and attributes), so it's easier to look up names via binary search even
if you just read all entries into a Vec without using any sorted containers.

The recommended extension for REPAK files is `.repak`.
Index stored separately shall have the `.idpak` extension.

If an `.idpak` file is present, it is given preference - since detecting the presence of an Index inside the REPAK file is more involved.

# Index entry

Entries are variable sized,

| Offset | Size            | Content           | Description                                                                                                                                                                                                |
| ------ | --------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0      | uleb64          | Offset            | Location of the asset in file                                                                                                                                                                              |
| ?      | uleb64          | Size              | Size of the asset in file                                                                                                                                                                                  |
| ?      | uleb64          | Flags             | Flags indicate presence of encryption, compression and checksums and affect which of the following header fields are present.                                                                              |
|        | flags & 0x0001  | Encryption bit    | Encryption header is present and defines used encryption method.                                                                                                                                           |
|        | flags & 0x0002  | Compression bit   | Compression header is present and defines used compression for the data blob. The blobs do not have any additional fields, they are just payload.                                                          |
|        | flags & 0x0004  | Checksum bit      | Checksumming header is present and lists used checksumming methods and calculated payload checksums.                                                                                                       |
|        | All other flags | Reserved          | Must not be used.                                                                                                                                                                                          |
| ?      | uleb64          | Name length       | Length of the following name, there are no \0 terminators.                                                                                                                                                 |
| ?      | Name length     | Name              | UTF-8 name of the asset.<br><br>There are no limits on how asset names are structured as long as they are valid UTF-8 strings.<br><br>One can use plain names, paths, dot delimited names, whatever works. |
|        | uleb64 | Attributes count | How many attributes does this entry have, can be 0 |
|        | Attributes count | Attributes | An array of Attribute entities, sorted by key |
| ?      | ?               | EncryptionHeader  | Optional, present if Encryption bit is set in Flags                                                                                                                                                                |
| ?      | ?               | CompressionHeader | Optional, present if Compression bit is set in Flags                                                                                                                                                               |
| ?      | ?               | ChecksumHeader    | Optional, present if Checksum bit is set in Flags                                                                                                                                                                  |

Attributes are key-value pairs, sorted by key, where key is a String and value is a byte array.

| Offset | Size            | Content           | Description                                                                                                                                                                                                |
| ------ | --------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 | uleb64 | Length of the key string |
| ? | Length | Key serialized as a utf8 string |
| ? | uleb64 | Length of the value array |
| ? | Array length | Bytes comprising the value |

(FIXME: limit to 512 attributes of up to 1K size?)
(TODO: attributes compression scheme for repeated/reusable attributes - store only indices/offsets into the attributes table, which is a separate deduplicated entity - example below shows huge redundancy)
(TODO: have a separate attributes file/db? - this is production thing, final assets should probably not have that in storage)
(TODO: use cbor to store the value binary? can have semantics/types then)

An example asset categorization, that may be represented via attributes (to generate attributes, flatten the keys):

```json
{
  "id": "ASSET-000123",
  "name": "SM_StreetLamp_A",
  "type": "3DModel",
  "usage": ["environment", "prop"],
  "platform": ["PC", "Xbox", "PS5"],
  "lifecycle": { "stage": "approved", "version": "v1.4.0", "changedBy": "j.smith", "date": "2025-11-20" },
  "ownership": { "team": "Environment Art", "assignee": "j.smith", "vendor": null, "license": "studio-perpetual" },
  "runtime": { "bundle": "env_props_city", "addressableKey": "env/props/streetlamp_a", "lods": [0,1,2] },
  "technical": { "tris": 4820, "textureSet": "2x2k", "shader": "PBR_Standard", "memoryKB": 768 },
  "dependencies": ["MAT_Metal_Painted", "TX_StreetLamp_A_BaseColor", "TX_StreetLamp_A_Roughness"],
  "tags": ["city", "night", "modern"]
}
```

Attributes form:

```
dependencies: MAT_Metal_Painted
dependencies: TX_StreetLamp_A_BaseColor
dependencies: TX_StreetLamp_A_Roughness
id: ASSET-000123
lifecycle.changedBy: j.smith
lifecycle.date: 2025-11-20
lifecycle.stage: approved
lifecycle.version: v1.4.0
name: SM_StreetLamp_A
ownership.assignee: j.smith
ownership.license: studio-perpetual
ownership.team: Environment Art
ownership.vendor: null
platform: PC
platform: PS5
platform: Xbox
runtime.addressableKey: env/props/streetlamp_a
runtime.bundle: env_props_city
runtime.lods: [0,1,2]
tags: city
tags: modern
tags: night
technical.memoryKB: 768
technical.shader: PBR_Standard
technical.textureSet: 2x2k
technical.tris: 4820
type: 3DModel
usage: environment
usage: prop
```

Attributes form with CBOR:

```
"id": "ASSET-000123",
"name": "SM_StreetLamp_A",
"type": "3DModel",
"usage": (arr_str)["environment", "prop"],
"platform": (arr_str)["PC", "Xbox", "PS5"],
"lifecycle": (map){ "stage": "approved", "version": "v1.4.0", "changedBy": "j.smith", "date": (date)"2025-11-20" },
"ownership": (map){ "team": "Environment Art", "assignee": "j.smith", "vendor": null, "license": "studio-perpetual" },
"runtime": (map){ "bundle": "env_props_city", "addressableKey": "env/props/streetlamp_a", "lods": (arr_int)[0,1,2] },
"technical": (map){ "tris": 4820, "textureSet": "2x2k", "shader": "PBR_Standard", "memoryKB": 768 },
"dependencies": (arr_str)["MAT_Metal_Painted", "TX_StreetLamp_A_BaseColor", "TX_StreetLamp_A_Roughness"],
"tags": (arr_str)["city", "night", "modern"]
```

## Encryption

| Offset | Size   | Content      | Description                                  |
| ------ | ------ | ------------ | -------------------------------------------- |
| 0      | uleb64 | Algorithm ID | Encryption algorithm used, see below         |
| ?      | uleb64 | Size         | Size of Parameters                           |
| ?      | ?      | Parameters   | Algorithm-specific parameters, such as salt. |

Encryption algorithms are classified into standard and custom.

| Algorithm       | Type                               |
| --------------- | ---------------------------------- |
| 0x0000 - 0xEFFF | Standard reserved algorithms range |
| 0xF000 - 0xFFFF | Custom algorithms.                 |

The standard REPAK implementation will return an error when attempting to decrypt custom encrypted content. You can still extract the encrypted blob though.

| Algorithm ID | Algorithm        | Parameters size and format                              |
| ------------ | ---------------- | ------------------------------------------------------- |
| 0            | Reserved         | Do not use                                              |
| 1            | XOR              | Variable key length, the key is provided externally     |
| 2            | AES-XTS-256      | None, the keys are provided externally.                 |
| 3            | HCTR2*           | None, the keys are provided externally.                 |
| 4            | Adiantum         | None, the keys are provided externally.                 |
| 5            | Threefish-1024   | Block size in bits (256, 512 and 1024 bits block sizes) |

* HCTR2 is currently not implemented.

## Compression

| Offset | Size   | Content      | Description                                                        |
| ------ | ------ | ------------ | ------------------------------------------------------------------ |
| 0      | uleb64 | Algorithm ID | Compression algorithm used, see below                              |
| ?      | uleb64 | Size         | Size of Parameters                                                 |
| 6      | ?      | Parameters   | Algorithm-specific parameters, for example decompressed blob size. |

Compression algorithms are classified into standard and custom.

| Algorithm       | Type                               |
| --------------- | ---------------------------------- |
| 0x0000 - 0xEFFF | Standard reserved algorithms range |
| 0xF000 - 0xFFFF | Custom algorithms.                 |

The standard REPAK implementation will return an error when attempting to decompress custom content. You can still extract the compressed blob though.

| Algorithm ID | Algorithm | Parameters size and format                                |
| ------------ | --------- | --------------------------------------------------------- |
| 0x0000       | Reserved  | Do not use.                                               |
| 0x0001       | deflate   | RFC 1951, gzip-like, Generic decompression parameters     |
| 0x0002       | bzip2     | Generic decompression parameters                          |
| 0x0003       | zstd      | Generic decompression parameters                          |
| 0x0004       | lzma (xz) | Generic decompression parameters                          |
| 0x0005       | LZ4       | Generic decompression parameters                          |

### Generic decompression parameters

| Offset | Size   | Content           | Description                       |
| ------ | ------ | ----------------- | --------------------------------- |
| 0      | uleb64 | Decompressed Size | Size of the decompressed payload. |

This helps pre-allocate buffers and validate decompression.

## Checksum

Checksum header provides support for having one or more checksums over the original uncompressed unencrypted payload. The same header structure is used to checksum the Index.

| Offset | Size   | Content           | Description                                                    |
| ------ | ------ | ----------------- | -------------------------------------------------------------- |
| 0      | uleb64 | Count             | Count of checksum payloads included, 1 or more, no duplicates. |
| ?      | ?      | checksums\[count] | Array of checksums, one after another.                         |

Each checksum:

| Offset | Size   | Content      | Description                               |
| ------ | ------ | ------------ | ----------------------------------------- |
| 0      | uleb64 | Algorithm ID | Checksum algorithm used, see below        |
| ?      | uleb64 | Payload size | Size of the checksum payload              |
| ?      | ?      | Payload      | Calculated checksum in appropriate format (usually a byte array) |

Checksum algorithms are classified into standard and custom.

| Algorithm       | Type                               |
| --------------- | ---------------------------------- |
| 0x0000 - 0xEFFF | Standard reserved algorithms range |
| 0xF000 - 0xFFFF | Custom algorithms.                 |

The standard REPAK implementation will return an error when attempting to read content with a custom checksum. You can still extract the blob by using the _unverified_ API.

### Checksum payloads

Keep in mind that the purpose of these checksums is to validate integrity of the payload, i.e. that the decrypted and decompressed bytes are matching the original payload that was added. A HMAC-like validation of authenticity of the data is outside the scope of this format.

| Type ID | Checksum      | Payload format and size                         |
| ------- | ------------- | ----------------------------------------------- |
| 0x0000  | Reserved      | Do not use.                                     |
| 0x0001  | sha3-256      | 32 bytes of binary hash output                  |
| 0x0002  | k12-256       | K12_256_Payload                                 |
| 0x0003  | blake3-256    | 32 bytes of binary hash output                  |
| 0x0004  | xxhash3-128   | 16 bytes of binary hash output of XXH3_128.     |
| 0x0005  | seahash-64    | 8 bytes of binary hash output.                  |
| 0x0006  | cityhash-128  | 16 bytes of binary hash output.                 |

K12_256_Payload:

| Offset | Size   | Content          | Description                                                                 |
| ------ | ------ | ---------------- | --------------------------------------------------------------------------- |
| 0      | uleb64 | size_seed        | Size of the following seed byte array                                       |
| ?      | ?      | seed             | The seed used for starting K12 as a byte array to initialize k12 algorithm. |
| ?      | 32     | hash_output      | The 256 bit binary hash output                                              |

# Payloads

Data payloads are checksummed, compressed, then encrypted and placed into the REPAK file starting from the very beginning, one after another, in sequential order without any spacing or padding.

Some compression and encryption algorithms may impose their own limits on padding or structuring the data - these are followed per-algorithm to make these blobs extractable.

It is easy to read the index, detach it from the main file, append new files, and then reattach the index back because of the `Index locator`.

# Index locator

At the very end of the REPAK file there is a field to help locate the index.

It is written in the rULEB64 [VLQ](https://en.wikipedia.org/wiki/Variable-length_quantity) format, which stands for `reversed Unsigned Little Endian Binary 64-bit Variable Length Quantity` and does exactly what it says :D

The maximum size of the 64 bit quantity in VLQ format is (64+6)/7 = 10 bytes. However, to account for variable length the value is read from end to start, with the first byte of the locator value being the last byte in the file. Hence the name `reversed`.

```
<-------------------------+ read direction from right to left
0xXX | 0xXX | 0x01 | 0x89 |
-----+------+------+------+
                       ^ last byte in file
```

The easiest way to parse it as an ULEB format is to read the last 10 bytes of the file, reverse them and parse as a normal LEB64 number ignoring any extra values after the number has been completely parsed (keep in mind that maximum representable format is u64 in this case).

This much offset from the end will specify where the REPAK index header begins.

Index locator is not compressed when the Index itself is compressed. Index locator is not included in the checksum calculation for the Index.
