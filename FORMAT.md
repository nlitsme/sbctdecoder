# SBCT disk-image format notes

Status: reverse-engineered from the supplied Surface Pro 8 and OEMCT image
sets. This is not an official specification. Fields marked **observed** are
supported directly by multiple samples; fields marked **inferred** remain
provisional.

All integers described below are little-endian. Offsets are hexadecimal unless
otherwise noted.

## 1. File family

A set has names resembling:

```text
NAME.wim.4096.sbct.header
NAME.wim.4096.sbct.vol.p04.header
NAME.wim.4096.sbct.vol.p04.hash
NAME.wim.4096.sbct.vol.p04.s0000000000
NAME.wim.4096.sbct.vol.p04.s0000000001
```

The number between `.wim.` and `.sbct` is the logical sector size used by the
reconstructed volume. In the examined Surface image this is 4096 bytes.

The files have these apparent roles:

| File | Role | Confidence |
| --- | --- | --- |
| `sbct.header` | Set header and GPT-like partition descriptions | High |
| `vol.pNN.header` | Per-volume parameters | Medium |
| `vol.pNN.hash` | Integrity information | Low; not decoded |
| `vol.pNN.s*` | Ordered record stream containing volume data | High |
| `*.unattend.xml` | Windows Setup answer files | Certain |
| `*.Intl.txt`, `*.DefaultTimeZone.txt`, etc. | Plain-text deployment settings | Certain |

The `s*` files are physical splits of one stream. A record can begin in one
file and continue in the next. They must therefore be concatenated logically
in numeric/physical order; each file must not be parsed independently.

## 2. Byte-order and GUID conventions

Integers are little-endian. Partition type and unique identifiers use the
usual on-disk GUID byte order used by GPT: the first three GUID components are
little-endian and the last eight bytes retain byte order.

For example:

```text
28 73 2a c1 1f f8 d2 11 ba 4b 00 a0 c9 3e c9 3b
```

represents the EFI System Partition type GUID
`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`.

## 3. Set header (`0x11111111`)

The main `sbct.header` starts with magic `11 11 11 11`.

Observed fixed prefix:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| `00` | 4 | Magic, `0x11111111` |
| `04` | 4 | Format version; observed value `6` |
| `08` | 4 | Header size or related size; observed `0x550` |
| `0c` | 4 | Unknown; observed `3` |
| `10` | 4 | Partition-entry count; observed `4` |
| `14` | varies | Unknown/reserved metadata |

### 3.1 Partition entries

In the examined header, four `0x90`-byte entries start at offset `0xb0`.
Their layout is GPT-like but contains byte offsets and lengths rather than GPT
first/last LBAs.

| Entry offset | Size | Meaning |
| ---: | ---: | --- |
| `00` | 8 | Enabled/present; observed `1` |
| `08` | 8 | Partition start in bytes |
| `10` | 8 | Partition length in bytes |
| `18` | 8 | Partition number/index |
| `20` | 16 | GPT partition type GUID |
| `30` | 16 | Unique partition GUID |
| `40` | 8 | GPT attributes |
| `48` | 72 | UTF-16LE partition name, NUL-padded |

Observed names and types include:

| Name | Type GUID |
| --- | --- |
| `EFI system partition` | `c12a7328-f81f-11d2-ba4b-00a0c93ec93b` |
| `Microsoft reserved partition` | `e3c9e316-0b5c-4db8-817d-f92df00215ae` |
| `Basic data partition` | `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7` |

Data after the partition table is not yet decoded. Some nonzero regions may be
digests, identifiers, or flags.

## 4. Per-volume header (`0x33333333`)

A `vol.pNN.header` starts with magic `33 33 33 33`.

Observed prefix from `p03`:

| Offset | Size | Example | Tentative meaning |
| ---: | ---: | ---: | --- |
| `00` | 4 | `0x33333333` | Magic |
| `04` | 4 | `6` | Version |
| `08` | 4 | `0x154` | Header size |
| `0c` | 4 | `0` | Unknown |
| `10` | 4 | `1` | Unknown |
| `14` | 4 | `2` | Unknown |
| `18` | 4 | `3` | Partition number, inferred |
| `1c` | 4 | `0x1000` | Logical sector size, inferred |
| `20` | 8 | `0x3ffff` | Sector count or last sector, inferred |
| `28` | 8 | `0x40000000` | Allocated/nominal volume size, inferred |
| `30` | 4 | `0x1000` | Allocation or block granularity, unknown |
| `34` | 4 | `0xcd8` | Count, unknown |
| `38` | 4 | `0` | Reserved/unknown |
| `3c` | 32 | varies | Digest or identifier, unknown |

Most of the remainder is zero in the examined sample. A nonzero value
`20 00 01 00` occurs near offset `0x13c`; its purpose is unknown.

## 5. Volume record stream (`0x55555555`)

Each volume stream is a sequence of records. Records are not aligned to a
sector or fixed byte boundary. Record framing may cross an `s*` file boundary.

Each record consists of a `0x20`-byte outer header, a `0x1c`-byte inner header,
and a payload:

```text
outer header (0x20)
inner header (0x1c)
payload      (compressed_size bytes)
```

The payload starts `0x3c` bytes after the record start.

### 5.1 Outer header

| Offset | Size | Field | Notes |
| ---: | ---: | --- | --- |
| `00` | 4 | `magic` | Always `0x55555555` in observed data |
| `04` | 4 | `record_size` | Bytes following the outer header |
| `08` | 4 | `index` | Observed as zero; exact purpose unknown |
| `0c` | 4 | `algorithm` | `1` = raw; `4` = XPRESS-Huffman selected |
| `10` | 8 | `plain_size` | Declared logical span of this record |
| `18` | 8 | `logical_offset` | Byte offset in the reconstructed volume |

The exclusive end of the record in the input stream is:

```text
record_start + 0x20 + record_size
```

### 5.2 Inner header

| Record offset | Size | Field | Notes |
| ---: | ---: | --- | --- |
| `20` | 8 | `tag` | Varies; low bytes are often stable, meaning unknown |
| `28` | 8 | `inner_plain_size_1` | Equals `plain_size` in observed records |
| `30` | 8 | `inner_plain_size_2` | Equals `plain_size` in observed records |
| `38` | 4 | `compressed_size` | Payload byte count |

Consistency relation:

```text
record_size == 0x1c + compressed_size
```

The logical output range declared by the record is:

```text
[logical_offset, logical_offset + plain_size)
```

Observed records do not overlap.

### 5.3 Raw fallback

An algorithm value of `4` does not guarantee that the payload is compressed.
When:

```text
compressed_size == plain_size
```

the observed payload is stored verbatim. This appears to be a fallback used
when XPRESS compression would not reduce the record size. Interpreting such a
payload as a Huffman table immediately produces invalid match offsets.

Algorithm `1` also represents raw data and is expected to have equal stored and
plain sizes.

## 6. XPRESS-Huffman payloads

Algorithm `4` payloads with unequal stored and plain sizes contain a sequence
of XPRESS-Huffman chunks. The coding follows Microsoft's LZ77+Huffman XPRESS
variant, with SBCT-specific chunk framing behavior described below.

### 6.1 Chunk layout

Each observed chunk starts with:

```text
256-byte Huffman code-length table
variable-length Huffman/LZ bitstream
```

There is no observed explicit compressed-length field before a chunk. The next
table begins at the compressed byte cursor after the current chunk has produced
its nominal output amount.

An SBCT chunk produces at most `0x10000` (65536) output bytes. Some final LZ
matches describe a few padding bytes beyond this boundary. The extractor clips
those matches at the 64 KiB boundary before processing the next table. Allowing
the overrun to shift the following chunk corrupts known NTFS structures.

This clipping rule is an **SBCT observation/inference**. Generic MS-XCA
descriptions allow block termination after output has reached or crossed the
nominal boundary, so a generic XPRESS implementation is not necessarily a
drop-in decoder for this container.

### 6.2 Huffman code-length table

The table describes 512 symbols using two four-bit lengths per byte:

```text
symbol 2*i     length = table[i] & 0x0f
symbol 2*i + 1 length = table[i] >> 4
```

Length zero means the symbol is unused. Maximum observed/permitted length is
15. Codes are canonical: sort by code length and then symbol number.

### 6.3 Bitstream

The bitstream is consumed using little-endian 16-bit input words loaded into a
32-bit shift register and decoded from its most-significant end. Implementations
must account for bytes prefetched into that register when locating interleaved
raw match-length bytes and the next chunk.

### 6.4 Symbols

Symbols `0..255` are literal output bytes.

For a symbol `S` in `256..511`:

```text
M                 = S - 256
offset_bit_count  = M >> 4
length_code       = M & 0x0f
match_offset      = (1 << offset_bit_count) | read_bits(offset_bit_count)
```

The match length is:

```text
if length_code != 15:
    match_length = length_code + 3
else:
    x = read_raw_u8()
    if x != 255:
        match_length = x + 15 + 3
    else:
        x = read_raw_u16_le()
        if x < 15: invalid
        match_length = x + 3
```

The raw byte/word is interleaved at the compressed byte cursor. Offset bits
remain in the bit register. Match copying is byte-by-byte and may overlap, as
with ordinary LZ77.

Match offsets refer to all output already produced for the record, not merely
the current 64 KiB chunk.

### 6.5 End padding

Several full records have two payload bytes left after the declared output has
been produced. These appear to be harmless bitstream termination/prefetch
padding. Larger trailing regions usually indicate incorrect chunk-boundary or
match-length handling.

## 7. Sparse partial records

Some compressed payloads end after producing fewer bytes than `plain_size`.
The missing bytes are not present as compressed all-zero chunks. They represent
a sparse region within the record's declared logical span.

Observed examples:

| Volume/record | Declared span | Decoded chunks | Missing bytes |
| --- | ---: | ---: | ---: |
| p03 record 0 | `0x7c7000` | `0x30000` | `0x797000` |
| p03 record 1 | `0x511000` | approximately `0x50000` | approximately `0x4c1000` |
| p04 record 5 | `0x4f9000` | `0x50000` | `0x4a9000` |

The current extractor uses this provisional placement rule:

* a partial record at logical offset zero is left-aligned and followed by a
  sparse zero suffix;
* a later partial record is right-aligned and preceded by a sparse zero prefix.

Right-aligning p04 record 5 places five valid NTFS `$LogFile` chunks at
`0x13c9a000..0x13cea000`; their signatures include `RSTR` and `RCRD`. This is
strong evidence for that particular placement. It is **not yet proof of a
general SBCT rule**. No decoded bitmap or per-chunk logical index has yet been
identified in the record header or payload.

Do not silently treat all missing bytes as a suffix. That produced a plausible
NTFS boot sector but placed later metadata incorrectly.

## 8. Stream reconstruction

A conservative reconstruction procedure is:

1. Open all `s*` files for one `vol.pNN` in physical order as one virtual byte
   stream.
2. Read a record header at the current stream position, even if it crosses a
   physical-file boundary.
3. Validate both size fields and calculate the complete record end.
4. Read the payload across physical-file boundaries if necessary.
5. If the payload is raw, copy it directly.
6. Otherwise decode successive 64 KiB XPRESS-Huffman chunks.
7. Place decoded data in the declared logical output span, applying sparse
   placement only when supported by evidence.
8. Seek in the output image and write decoded bytes. Unwritten ranges remain
   sparse/zero-filled.
9. Set the output file length to the greatest declared logical end.

The output should be opened as a sparse-capable file. A volume may contain very
large unwritten gaps between records.

## 9. Completeness and NTFS observations

A successfully framed and decompressed stream is not necessarily a complete,
standalone filesystem image.

For the examined p04 reconstruction:

* the NTFS boot sector is valid and declares 4096-byte sectors and clusters;
* `$MFTMirr` at `0x2000` contains four valid 1024-byte `FILE` records;
* the boot sector and `$MFTMirr` record 0 both place the primary `$MFT` at LCN
  `0x13caa`, byte offset `0x13caa000`;
* the primary `$MFT` is absent from the reconstructed data;
* no other consecutive aligned `FILE` records occur in the image;
* p04 record 5 contains `$LogFile` pages, not `$MFT` data.

This indicates that the SBCT set is probably a sparse/differential restore
artifact, or that another reconstruction layer/data source is required. It
must not be assumed that each `vol.pNN` becomes a mountable filesystem merely
by decoding its records.

Copying the four `$MFTMirr` records to the primary MFT location may be useful as
a diagnostic on a disposable copy, but cannot restore the rest of the MFT.

## 10. Validation under Linux

For an NTFS output image, useful read-only checks are:

```sh
ntfsinfo -m image.raw
ntfsls -l -p / image.raw
ntfsls -l -R -p / image.raw
fsstat image.raw
fls -r image.raw
```

`ntfsls` successfully listing `/` proves that the boot sector, primary MFT,
and root directory are readable. It does not prove that all records or file
contents are present.

When mounting an image whose NTFS boot sector declares 4096-byte sectors,
create the loop device with matching geometry:

```sh
loopdev=$(sudo losetup --find --show --read-only \
    --sector-size 4096 image.raw)
sudo mount -t ntfs3 -o ro "$loopdev" mnt
```

Without `--sector-size 4096`, Linux normally exposes a 512-byte loop sector and
`ntfs3` reports a sector-size mismatch.

## 11. Unknowns and next research steps

The following remain unresolved:

* the expansion and official name of `SBCT`;
* the exact semantics of the main and per-volume header fields;
* the `.hash` file format and integrity algorithm;
* the meaning of the 64-bit inner `tag`;
* whether `index` selects a substream, copy, or sparse-placement mode;
* the authoritative encoding of sparse chunk positions;
* whether missing filesystem metadata comes from another SBCT volume, a base
  image, the WIM application process, or generated metadata;
* exact end-marker and padding requirements around XPRESS chunks;
* whether algorithms other than observed values `1` and `4` are permitted.

Useful next evidence would include:

* comparing `.hash` entries with SHA-1/SHA-256 hashes of compressed and decoded
  chunks;
* obtaining two images with the same volume layout but different allocated
  blocks and comparing sparse-record headers;
* tracing the Windows recovery program that consumes these files;
* finding the consumer's references to magic values `0x11111111`,
  `0x33333333`, and `0x55555555`;
* checking whether the inner tag splits into a fixed magic/version portion and
  a checksum or flags field;
* logging the first bytes and hashes of every decoded 64 KiB chunk to correlate
  them with known NTFS metadata locations.

## 12. Known magic values

| Value | Context |
| ---: | --- |
| `0x11111111` | Main set header |
| `0x33333333` | Per-volume header |
| `0x55555555` | Volume data record |

## 13. References

* Microsoft Open Specifications, [MS-XCA: Xpress Compression
  Algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8)
* The companion reverse-engineering implementation: `sbct-extract.rs`
