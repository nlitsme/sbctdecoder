# SBCT volume extractor

This project reconstructs raw partition images from Microsoft Surface/OEM
recovery files whose names contain `.sbct.vol.pNN`. The data files contain a
stream of SBCT records holding raw or XPRESS-Huffman-compressed ranges of the
target volume.

The format was reverse-engineered from observed recovery-image sets. It is not
an official Microsoft implementation or a complete specification of every
SBCT variant.

The code in this project was mostly written by chatgpt.

## Files

| File | Purpose |
| --- | --- |
| `sbct-extract.rs` | Reconstructs a raw volume image from one or more ordered `s*` stream files. |
| `sbct-inspect.py` | Reads record and XPRESS structure without reconstructing or printing decoded data. |
| `FORMAT.md` | Detailed reverse-engineering notes and binary field layouts. |

The extractor currently operates on the data stream for one volume, such as
`vol.p04.s0000000000`. It does not consume the top-level `.sbct.header`, the
per-volume `.header`, or the `.hash` file, and it does not construct a complete
GPT disk containing all partitions.

The current decoder handles the raw and XPRESS-Huffman record forms found in
the examined images, including records crossing physical file boundaries. See
[`FORMAT.md`](FORMAT.md) for the supported record layout, compression details,
observations, and unresolved fields.

## Building the extractor

A Cargo project is not required. Build the standalone Rust source directly:

```sh
rustc -O sbct-extract.rs -o sbct-extract
```

To compile and run its built-in tests:

```sh
rustc --test sbct-extract.rs -o sbct-extract-tests
./sbct-extract-tests
```

The inspector requires Python 3.9 or later and uses only the standard library:

```sh
python3 sbct-inspect.py --self-test
```

## Reconstructing a volume

Pass the output filename followed by every physical stream file belonging to
one `vol.pNN`, in numeric order:

```sh
./sbct-extract p04.raw \
    image.wim.4096.sbct.vol.p04.s0000000000 \
    image.wim.4096.sbct.vol.p04.s0000000001
```

Do not run the extractor separately on each split. A record may begin near the
end of one file and continue in the next. The arguments are treated as one
continuous byte stream.

Records are written at their declared logical offsets. Unwritten gaps and
declared zero suffixes normally become sparse regions in the output file. The
logical size reported by `ls -l` can therefore be much larger than the physical
space reported by `du`.

The extractor prints record headers and XPRESS block boundaries while running.
There is currently no quiet or verbosity option.

## Inspecting a failure

`sbct-inspect.py` is intended for investigating a record without exposing its
decoded contents. It reports structural metadata, code-length histograms,
compressed cursors, output positions, and match statistics. It does not build
the plaintext.

Inspect a record by its zero-based index:

```sh
python3 sbct-inspect.py --record 75 --mode spec \
    image.wim.4096.sbct.vol.p02.s0000000000
```

If the record crosses a physical split, supply all relevant files in order:

```sh
python3 sbct-inspect.py --record 19 --mode spec \
    image.wim.4096.sbct.vol.p04.s0000000000 \
    image.wim.4096.sbct.vol.p04.s0000000001
```

Select a record directly by its offset in the combined stream:

```sh
python3 sbct-inspect.py --offset 0x35c6ab --mode spec stream.s0000000000
```

Probe a suspected Huffman table at a payload-relative offset:

```sh
python3 sbct-inspect.py --record 75 --mode spec \
    --table-at 0x422798 stream.s0000000000
```

Useful options include:

| Option | Meaning |
| --- | --- |
| `--record N` | Select record number `N` by scanning preceding record sizes. |
| `--offset N` | Select a record at combined-stream offset `N`. |
| `--records N` | Inspect consecutive records. |
| `--mode spec` | Finish a complete match before testing the 64 KiB threshold; this is the behavior used by the extractor. |
| `--mode clip` | Diagnostic comparison with the earlier block-clipping hypothesis. |
| `--mode both` | Run both policies; this is the default. |
| `--table-at N` | Validate a table at payload-relative offset `N`. |
| `--every N` | Print every Nth block while still reporting failures and crossings. |
| `--max-record-mib N` | Raise the default 64 MiB per-record safety limit. |
| `--block-limit N` | Raise the maximum number of inspected blocks. |

The report omits input filenames, literal values, raw bytes, decoded data,
UUIDs, hashes, and code-to-symbol mappings. It still contains sizes, offsets,
flags, and compression statistics, so review it before sharing.

## Checking the reconstructed filesystem

For an NTFS volume, start with read-only filesystem tools:

```sh
ntfsinfo -m p04.raw
ntfsls -l -p / p04.raw
ntfsls -l -R -p / p04.raw
```

If `ntfsls` can list the root directory, the NTFS boot sector, primary MFT, and
directory metadata are readable. That is a strong structural check, but it
does not prove that every file stream is correct. Extracting selected files and
checking known hashes or file formats provides a stronger content test.

The observed images can declare 4096-byte NTFS sectors. For a read-only Linux
mount, create a loop device with the matching sector size:

```sh
mkdir -p mnt
loopdev=$(sudo losetup --find --show --read-only \
    --sector-size 4096 p04.raw)
sudo mount -t ntfs3 -o ro "$loopdev" mnt
```

Unmount and detach it afterwards:

```sh
sudo umount mnt
sudo losetup -d "$loopdev"
```

Using an ordinary 512-byte-sector loop device can make `ntfs3` reject an
otherwise valid image because the media and NTFS sector sizes differ.

Keep the reconstructed image read-only until it has been validated. Running
`chkdsk`, `ntfsfix`, or mounting read-write can modify evidence and conceal
decoder errors.

## Limitations and unresolved fields

- Only the record variants observed in the examined recovery sets are
  supported.
- The `.hash`, set-header, and per-volume-header files are not used during
  extraction.
- Short compressed records currently produce an explicitly reported,
  zero-filled suffix; that remains an unverified recovery assumption.
- Successful decompression and `ntfsls` output do not establish byte-for-byte
  correctness of every file.

See [`FORMAT.md`](FORMAT.md) for the complete list of unresolved format
questions.

## References

- [MS-XCA: Xpress Compression Algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8)
- [MS-XCA 2.1.4.3: LZ77+Huffman encoder](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c7ec7ba9-ca8f-448f-bb85-027c1516db1c)
- [MS-XCA 2.2.4: LZ77+Huffman decoder](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b)
- [MS-XCA 3.2: LZ77+Huffman test data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/f59ff967-3032-4331-b108-0d2b4c09ee27)
