Asset library format similar in idea to Quake PAK or DOOM WAD files. The file is append-only, making it easy to insert new entries at the end, but removing older entries may require repacking the whole file.

# Overall file structure

| Offset   | Contents                                                                                                                                                                     |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0        | Binary contents of assets, one after another without spaces.                                                                                                                 |
| X        | Compressed asset index.                                                                                                                                                      |
| File end | Offset of index from the end of file recorded in rULEB64 format (a specific subset of VLQ encoding), seeking this number of bytes from the end of file should land you at X. |

# REPAK index

| Offset | Size   | Content         | Description                                                                                                                                                                                                        |
| ------ | ------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0      | 5      | "REPAK"         | Format marker                                                                                                                                                                                                      |
| 5      | 1      | 0x01            | Version                                                                                                                                                                                                            |
| 6      | 2      | 0x0000          | Reserved                                                                                                                                                                                                           |
| 8      | uleb64 | count           | Number of following index entries                                                                                                                                                                                  |
| ?      | uleb64 | size            | Size of the entire `entries[count]` array in bytes. To make it easier to allocate and read the entire variable-sized array in one go for parsing.                                                                  |
| ?      |        | entries\[count] | Variable-sized entries array                                                                                                                                                                                       |
| ?      |        | ChecksumHeader  | Checksum structure for the Index, see below for format. The checksum is calculated after the `size` field is calculated and written. The entire contents of the header starting from REPAK marker are checksummed. |

Immediately following the last index entry is the index offset field at the file end.

When attached to the REPAK file, the index is usually compressed using `lzma`. A stand-alone index may be uncompressed, this can be checked by reading the format marker.

The recommended extension for REPAK files is `.repak`.
Index stored separately shall have the `.idpak` extension.

If an `.idpak` file is present, it is given preference - as detecting the presence of an Index inside the REPAK file is more involved.

# Index entry

Entries are variable sized, 

| Offset | Size            | Content           | Description                                                                                                                                                                                  |
| ------ | --------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0      | uleb64          | Offset            | Location of the asset in file                                                                                                                                                                |
| ?      | uleb64          | Size              | Size of the asset in file                                                                                                                                                                    |
| ?      | uleb64          | Flags             | Flags indicate presence of encryption, compression and checksums and affect which of the following header fields are present.                                                                |
|        | flags & 0x0001  | Encryption bit    | Encryption header is present and defines used encryption method.                                                                                                                             |
|        | flags & 0x0002  | Compression bit   | Compression header is present and defines used compression for the data blob. The blobs do not have any additional fields, they are just payload.                                            |
|        | flags & 0x0004  | Checksum bit      | Checksumming header is present and lists used checksumming methods and calculated payload checksums.                                                                                         |
|        | All other flags | Reserved          | Must not be used.                                                                                                                                                                            |
| ?      | uleb64          | Name length       | Length of the following name, there are no \0 terminators.                                                                                                                                   |
| ?      | Name length     | Name              | UTF-8 name of the asset. There are no limits on how asset names are structured as long as they are valid UTF-8 strings. One can use plain names, paths, dot delimited names, whatever works. |
| ?      | ?               | EncryptionHeader  | Optional, if Encryption bit is set in Flags                                                                                                                                                  |
| ?      | ?               | CompressionHeader | Optional, if Compression bit is set in Flags                                                                                                                                                 |
| ?      | ?               | ChecksumHeader    | Optional, if Checksum bit is set in Flags                                                                                                                                                    |

## Encryption

| Offset | Size   | Content    | Description                                  |
| ------ | ------ | ---------- | -------------------------------------------- |
| 0      | uleb64 | Size       | Size of entire encryption header             |
| ?      | uleb64 | Algorithm  | Encryption algorithm used, see below         |
| ?      | ?      | Parameters | Algorithm-specific parameters, such as salt. |

Encryption algorithms are classified into standard and custom.

| Algorithm       | Type                               |
| --------------- | ---------------------------------- |
| 0x0000 - 0xEFFF | Standard reserved algorithms range |
| 0xF000 - 0xFFFF | Custom algorithms.                 |

The standard REPAK implementation will return an error when attempting to decrypt custom encrypted content. You can still extract the encrypted blob though.

| Algorithm ID | Algorithm                           | Parameters size and format |
| ------------ | ----------------------------------- | -------------------------- |
| @TODO        | Define some file encryption formats |                            |

## Compression

| Offset | Size   | Content    | Description                                                        |
| ------ | ------ | ---------- | ------------------------------------------------------------------ |
| 0      | uleb64 | Size       | Size of entire compression header                                  |
| ?      | uleb64 | Algorithm  | Compression algorithm used, see below                              |
| 6      | ?      | Parameters | Algorithm-specific parameters, for example decompressed blob size. |

Compression algorithms are classified into standard and custom.

| Algorithm       | Type                               |
| --------------- | ---------------------------------- |
| 0x0000 - 0xEFFF | Standard reserved algorithms range |
| 0xF000 - 0xFFFF | Custom algorithms.                 |

The standard REPAK implementation will return an error when attempting to decompress custom content. You can still extract the compressed blob though.

| Algorithm ID | Algorithm      | Parameters size and format                                |
| ------------ | -------------- | --------------------------------------------------------- |
| 0x0000       | No compression | 0 bytes                                                   |
| 0x0001       | deflate        | RFC 1951, Generic decompression parameters                |
| 0x0002       | gzip           | Generic decompression parameters                          |
| 0x0003       | bzip2          | Generic decompression parameters                          |
| 0x0004       | zstd           | Generic decompression parameters                          |
| 0x0005       | lzma (xz)      | Generic decompression parameters                          |
| 0x0006       | LZ4            | Generic decompression parameters                          |
| 0x0007       | fsst           | Fast String Compression, Generic decompression parameters |

There is usually no need to specify algorithm 0x0000 as it is exactly equivalent to just having an uncompressed blob.

### Generic decompression parameters

| Offset | Size   | Content           | Description                       |
| ------ | ------ | ----------------- | --------------------------------- |
| 0      | uleb64 | Decompressed Size | Size of the decompressed payload. |

This helps pre-allocate and/or validate decompression.

## Checksum

Checksum header provides support for having one or more checksums over the original uncompressed unencrypted payload. The same header is used to checksum the Index.

| Offset | Size           | Content           | Description                                                                                       |
| ------ | -------------- | ----------------- | ------------------------------------------------------------------------------------------------- |
| 0      | uleb64         | Size              | Size of the entire checksum header                                                                |
| ?      | uleb64         | Count             | Count of checksum payloads included                                                               |
| ?      | uleb64 * count | types\[count]     | Array of checksum types, one after another.                                                       |
| ?      | ?              | checksums\[count] | Array of checksum payloads, in the same order as types, type determines the size of each payload. |

Checksum algorithms are classified into standard and custom.

| Algorithm       | Type                               |
| --------------- | ---------------------------------- |
| 0x0000 - 0xEFFF | Standard reserved algorithms range |
| 0xF000 - 0xFFFF | Custom algorithms.                 |

The standard REPAK implementation will return an error when attempting to read content with a custom checksum. You can still extract the blob by using the _unverified_ API.

### Checksum payloads

Keep in mind that the purpose of these checksums is to validate integrity of the payload, i.e. that the decrypted and decompressed bytes are matching the original payload that was added. It is not a cryptographic hash. If one is needed - it should be added to the Encryption header with some MAC (a non-encrypting HMAC verification shall be possible via Encryption header also).

| Type ID | Checksum      | Payload format and size                         |
| ------- | ------------- | ----------------------------------------------- |
| 0x0000  | Reserved      | Do not use.                                     |
| 0x0001  | sha3          | 32 bytes of binary hash output                  |
| 0x0002  | k12-256       | K12_256_Payload                                 |
| 0x0003  | blake3-256    | 32 bytes of binary hash output                  |
| 0x0004  | xxhash3-128   | 16 bytes of binary hash output of XXH3_128.     |
| 0x0005  | metrohash-128 | 16 bytes of binary hash output of metrohash128. |
| 0x0006  | seahash       | 8 bytes of binary hash output.                  |
| 0x0008  | cityhash-128  | 16 bytes of binary hash output.                 |

K12_256_Payload:

| Offset | Size   | Content          | Description                                      |
| ------ | ------ | ---------------- | ------------------------------------------------ |
| 0      | uleb64 | size_seed_string | Size of the following string seed                |
| ?      | ?      | seed_string      | The seed used for starting K12 as a UTF-8 string |
| ?      | 32     | hash_output      | The 256 bit binary hash output                   |

# Payloads

Data payloads are checksummed, compressed, then encrypted and placed into the REPAK file starting from the very beginning, one after another, in sequential order without any spacing or padding.

Some compression and encryption algorithms may impose their own limits on padding or structuring the data - these are followed per-algorithm to make these blobs extractable.

It is easy to read the index, detach it from the main file, append new files, and then reattach the index back due to `Index locator`.

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

The easiest way to parse it as an ULEB format is to read the last 10 bytes of the file, reverse them and parse as a normal LEB64 number ignoring any extra values after number is completely parsed (keep in mind that maximum representable format is u64 in this case).
