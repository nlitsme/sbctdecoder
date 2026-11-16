#!/usr/bin/env python3
"""Local-only structural inspection of SBCT records (Python 3.9+, stdlib only).

Examples:
  python3 sbct-inspect.py --record 3 p02.s0000000000
  python3 sbct-inspect.py --offset 0x35c6ab p02.s0000000000
  python3 sbct-inspect.py --record 3 --table-at 0x16c4a0 part0 part1
  python3 sbct-inspect.py --self-test

Inputs are opened read-only and concatenated in command-line order. Only one
record's compressed payload is held in memory; no decompressed bytes are built.
There is no networking, subprocess execution, telemetry, or output-file writing.
Reports omit input names, literal values, raw bytes, code-to-symbol mappings,
UUIDs, and hashes. They DO expose sizes, positions, flags, aggregate code-length
counts, and compression statistics. Review even these metadata before sharing.

The two boundary policies are diagnostic, NOT two proven SBCT interpretations:
  spec: copy a complete match before checking the 64 KiB block threshold.
  clip: discard the part of a match crossing that threshold, as the old tool did.
Both use canonical-table and strict input-bounds validation. The only accepted
incomplete table is the observed SBCT singleton with one one-bit code: code 0
selects that symbol and code 1 is rejected. Neither invents a
sparse suffix or repairs malformed data. 'clip' is not a byte-for-byte emulation
of the old Rust decoder's missing table checks and zero-filled short reads.

This is an independent structural walker, not a reference-certified decoder or
a filesystem validator. Reaching the declared size does not prove correctness;
remaining input and buffered bits may include a terminator, padding, or data.
The walker stops at the declared output size without certifying those leftovers.
Strict lookahead reads may also flag variants that omit end padding.

Supports the FF + zero-u16 + u32 long-match form from the encoder description
in MS-XCA 2.1.4.3; that case is omitted from the 2.2.4 decoder pseudocode.

Basis: MS-XCA 2.1.4.3 (encoding), 2.2.4 (processing), 3.2 (public test vectors):
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/c7ec7ba9-ca8f-448f-bb85-027c1516db1c
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/f59ff967-3032-4331-b108-0d2b4c09ee27

Note: code written by chatgpt.
"""

import argparse
from array import array
from contextlib import ExitStack
from dataclasses import dataclass
import struct
import sys


HEADER_SIZE = 0x3C
TABLE_SIZE = 256
BLOCK_SIZE = 65536
CODE_SPACE = 32768


class InspectionError(Exception):
    """Messages contain structural metadata only, never input bytes/paths."""


def say(message):
    print(message, flush=True)


class Segments:
    def __init__(self, paths, stack):
        self.files = []
        self.size = 0
        for number, path in enumerate(paths):
            try:
                handle = stack.enter_context(open(path, "rb"))
                handle.seek(0, 2)
                size = handle.tell()
            except OSError as error:
                raise InspectionError(
                    f"cannot open input#{number}: errno={error.errno}"
                ) from None
            self.files.append((handle, self.size, size))
            self.size += size

    def read_at(self, position, count):
        if position < 0 or count < 0 or position + count > self.size:
            raise InspectionError(
                f"stream bounds: offset={position:#x}, requested={count:#x}, "
                f"stream_size={self.size:#x}"
            )
        chunks = []
        for handle, start, size in self.files:
            if not count:
                break
            if start <= position < start + size:
                amount = min(count, start + size - position)
                handle.seek(position - start)
                data = handle.read(amount)
                if len(data) != amount:
                    raise InspectionError("short input read (file may have changed)")
                chunks.append(data)
                position += amount
                count -= amount
        if count:
            raise InspectionError("input segment mapping failed")
        return b"".join(chunks)


@dataclass
class Header:
    size1: int
    unk0: int
    unk1: int
    dstsize: int
    dstofs: int
    magic2: int
    hdrsize: int
    flags: int
    size2: int
    size3: int
    compsize: int

    @classmethod
    def parse(cls, data):
        if len(data) != HEADER_SIZE:
            raise InspectionError("short SBCT record header")
        fields = struct.unpack("<IIIIQQIHHQQI", data)
        if fields[0] != 0x55555555:
            raise InspectionError("SBCT record magic mismatch")
        result = cls(*fields[1:])
        if result.size1 != result.compsize + 0x1C:
            raise InspectionError("size1 != compsize + 0x1c")
        if not result.dstsize == result.size2 == result.size3:
            raise InspectionError("declared output sizes disagree")
        return result


def code_lengths(payload, position):
    if len(payload) - position < TABLE_SIZE:
        raise InspectionError(
            f"short Huffman table: available={max(0, len(payload)-position):#x}"
        )
    lengths = []
    for value in payload[position:position + TABLE_SIZE]:
        lengths.extend((value & 15, value >> 4))
    return lengths


def table_stats(lengths):
    counts = [0] * 16
    for length in lengths:
        counts[length] += 1
    used = sum(counts[length] << (15 - length) for length in range(1, 16))
    return counts, used


def build_table(lengths):
    counts, used = table_stats(lengths)
    # Observed SBCT singleton variant, not a general incomplete-tree waiver.
    singleton = counts[0] == 511 and counts[1] == 1
    if used != CODE_SPACE and not singleton:
        kind = "over-subscribed" if used > CODE_SPACE else "incomplete"
        raise InspectionError(
            f"{kind} Huffman table: coverage={used}/{CODE_SPACE}"
        )
    # Packed entries: low 9 bits are symbol, high bits are code length.
    table = array("H")
    for length in range(1, 16):
        for symbol, size in enumerate(lengths):
            if size == length:
                table.extend(array("H", [(length << 9) | symbol]) *
                             (1 << (15 - length)))
    if singleton:
        # Canonical code 0 selects the symbol; code 1 remains invalid.
        table.extend(array("H", [0]) * (CODE_SPACE - used))
    return table


class Bits:
    def __init__(self, data, position):
        self.data = data
        self.position = position
        self.bits = 0
        self.available = 0
        self.consumed = 0

    def byte(self):
        if self.position >= len(self.data):
            raise InspectionError("truncated extended match length (byte)")
        value = self.data[self.position]
        self.position += 1
        return value

    def word(self, purpose):
        if self.position + 2 > len(self.data):
            raise InspectionError(f"truncated {purpose} (16-bit read)")
        value = struct.unpack_from("<H", self.data, self.position)[0]
        self.position += 2
        return value

    def dword(self, purpose):
        if self.position + 4 > len(self.data):
            raise InspectionError(f"truncated {purpose} (32-bit read)")
        value = struct.unpack_from("<I", self.data, self.position)[0]
        self.position += 4
        return value

    def initialize(self):
        self.bits = (self.word("initial lookahead") << 16) | self.word("initial lookahead")
        self.available = 32

    def peek(self, count):
        return self.bits >> (32 - count) if count else 0

    def consume(self, count):
        self.bits = (self.bits << count) & 0xFFFFFFFF
        self.available -= count
        self.consumed += count
        if self.available < 16:
            self.bits |= self.word("bit-buffer refill") << (16 - self.available)
            self.available += 16


@dataclass
class WalkResult:
    ok: bool
    produced: int
    cursor: int
    blocks: int
    crossings: int
    discarded: int


def walk(payload, expected, policy, emit=say, every=1, block_limit=4096):
    """Parse tokens and count output. Deliberately never reconstruct literals."""
    output = cursor = block = crossings = discarded = 0
    stream = None
    stage = "table"
    table_position = 0
    counts = None
    try:
        while output < expected:
            if block >= block_limit:
                raise InspectionError("block limit reached (raise --block-limit)")
            table_position = cursor
            stage = "table"
            counts = None
            lengths = code_lengths(payload, cursor)
            counts, used = table_stats(lengths)
            table = build_table(lengths)
            cursor += TABLE_SIZE
            stream = Bits(payload, cursor)
            stage = "initial lookahead"
            stream.initialize()
            begin = output
            threshold = begin + BLOCK_SIZE
            limit = min(threshold, expected)
            literals = matches = block_crossings = block_discarded = 0
            while output < limit:
                stage = "Huffman symbol"
                entry = table[stream.peek(15)]
                if entry == 0:
                    raise InspectionError("unused Huffman code in singleton table")
                symbol = entry & 511
                stream.consume(entry >> 9)
                if symbol < 256:
                    literals += 1
                    output += 1
                    continue

                token = symbol - 256
                length = token & 15
                offset_bits = token >> 4
                stage = "extended match length"
                if length == 15:
                    extension = stream.byte()
                    if extension == 255:
                        length = stream.word("extended match length")
                        if length == 0:
                            length_position = stream.position
                            length = stream.dword("32-bit extended match length")
                            emit(f"[{policy}] extended32 at={length_position:#x} "
                                 f"match_length={length + 3:#x} output={output:#x}")
                        if length < 15:
                            raise InspectionError("invalid extended match length (<15)")
                    else:
                        length = 15 + extension
                length += 3
                stage = "match offset"
                distance = (1 << offset_bits) + stream.peek(offset_bits)
                stream.consume(offset_bits)
                if distance > output:
                    raise InspectionError(
                        f"match precedes output: distance={distance:#x}, length={length:#x}"
                    )
                matches += 1
                if output + length > threshold:
                    crossings += 1
                    block_crossings += 1
                if policy == "clip":
                    copied = min(length, limit - output)
                    block_discarded += length - copied
                    discarded += length - copied
                    output += copied
                else:
                    if output + length > expected:
                        raise InspectionError(
                            f"match exceeds declared record output by "
                            f"{output + length - expected:#x} bytes"
                        )
                    output += length

            cursor = stream.position
            if block % every == 0 or output == expected or block_crossings or block_discarded:
                emit(
                    f"[{policy}] block={block} table={table_position:#x} "
                    f"cursor={cursor:#x} output={begin:#x}..{output:#x} "
                    f"literals={literals} matches={matches} "
                    f"crossings={block_crossings} discarded={block_discarded:#x} "
                    f"buffered_bits={stream.available}"
                )
            block += 1

        emit(
            f"[{policy}] SIZE_REACHED output={output:#x}/{expected:#x} "
            f"cursor={cursor:#x}/{len(payload):#x} unread={len(payload)-cursor:#x} "
            f"blocks={block} crossings={crossings} discarded={discarded:#x}"
        )
        emit(f"[{policy}] Not a content check; any terminator/padding/unread data is unverified.")
        return WalkResult(True, output, cursor, block, crossings, discarded)
    except InspectionError as error:
        if stage != "table" and stream is not None:
            cursor = stream.position
        emit(
            f"[{policy}] FAIL block={block} stage={stage} table={table_position:#x} "
            f"cursor={cursor:#x} output={output:#x}/{expected:#x}: {error}"
        )
        if counts is not None:
            emit(f"[{policy}] code_length_counts[0..15]=" + ",".join(map(str, counts)))
        if stage != "table" and stream is not None:
            emit(f"[{policy}] buffered_bits={stream.available} consumed_bits={stream.consumed}")
        emit(f"[{policy}] No missing bytes have been assumed to be zero.")
        return WalkResult(False, output, cursor, block, crossings, discarded)


def inspect_table(payload, position):
    say(f"[probe] payload-relative table={position:#x}")
    lengths = code_lengths(payload, position)
    counts, used = table_stats(lengths)
    say("[probe] code_length_counts[0..15]=" + ",".join(map(str, counts)))
    say(f"[probe] coverage={used}/{CODE_SPACE}")
    build_table(lengths)
    if counts[0] == 511 and counts[1] == 1:
        say("[probe] singleton variant accepted: code 0 assigned, code 1 invalid.")
    else:
        say("[probe] canonical code space is complete; this alone does not prove a table boundary.")


def nonnegative(value):
    result = int(value, 0)
    if result < 0:
        raise ValueError
    return result


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error may echo user-provided filenames or values.
        self.exit(2, "Invalid command-line options; see --help.\n")


def self_test():
    # MS-XCA 3.2: the 300-byte 'abc' repetition, represented by public test data.
    table = bytearray(TABLE_SIZE)
    table[48], table[49], table[128], table[143] = 0x30, 0x23, 2, 0x20
    payload = bytes(table) + bytes.fromhex("a8 dc 00 00 ff 26 01")
    quiet = lambda message: None
    for policy in ("spec", "clip"):
        result = walk(payload, 300, policy, quiet)
        assert result.ok and result.produced == 300 and result.cursor == len(payload)
        assert not walk(payload[:-1], 300, policy, quiet).ok
    # The public alphabet vector exercises 16-bit lookahead refills as well.
    alphabet_table = bytearray(TABLE_SIZE)
    for symbol in list(range(97, 123)) + [256]:
        length = 5 if symbol < 119 else 4
        alphabet_table[symbol // 2] |= length << (4 * (symbol % 2))
    alphabet = bytes(alphabet_table) + bytes.fromhex(
        "d8 52 3e d7 94 11 5b e9 19 5f f9 d6 7c df 8d 04 00 00 00 00")
    result = walk(alphabet, 26, "spec", quiet)
    assert result.ok and result.produced == 26
    for bad in (bytes(TABLE_SIZE), b"\x11" * TABLE_SIZE):
        try:
            build_table(code_lengths(bad, 0))
        except InspectionError:
            pass
        else:
            raise AssertionError("invalid table accepted")
    # Synthetic one-literal + long-match block crossing the 64 KiB threshold.
    cross_table = bytearray(TABLE_SIZE)
    cross_table[32] = cross_table[135] = 0x10
    cross = bytes(cross_table) + bytes.fromhex("00 40 00 00 ff ff ff")
    spec = walk(cross, 65539, "spec", quiet)
    clip = walk(cross, 65539, "clip", quiet)
    assert spec.ok and spec.produced == 65539 and spec.crossings == 1
    assert not clip.ok and clip.produced == 65536 and clip.discarded == 3
    assert not walk(cross, 65538, "spec", quiet).ok
    # A 128 KiB match span uses FF + zero-u16 + little-endian u32(length-3).
    # The next table must follow the complete match, not a 64 KiB clipped copy.
    long_size = 0x20000
    long_payload = (bytes(cross_table) + bytes.fromhex("00 40 00 00 ff 00 00")
                    + struct.pack("<I", long_size - 4))
    result = walk(long_payload, long_size, "spec", quiet)
    assert result.ok and result.produced == long_size and result.cursor == len(long_payload)
    combined = walk(long_payload + payload, long_size + 300, "spec", quiet)
    assert combined.ok and combined.blocks == 2 and combined.cursor == len(long_payload + payload)
    assert not walk(long_payload, long_size - 1, "spec", quiet).ok
    for cut in range(1, 5):
        assert not walk(long_payload[:-cut], long_size, "spec", quiet).ok
    for invalid_length in (0, 1, 14):
        invalid_payload = long_payload[:-4] + struct.pack("<I", invalid_length)
        assert not walk(invalid_payload, long_size, "spec", quiet).ok
    # A very large encoded length must fail the record bound, not wrap at +3.
    assert not walk(long_payload[:-4] + b"\xff" * 4, long_size, "spec", quiet).ok
    # A match without any preceding output must be rejected.
    before_output = bytes(cross_table) + bytes.fromhex("00 80 00 00 00")
    assert not walk(before_output, 18, "spec", quiet).ok
    # Observed singleton variant: consume one bit, rejecting the unused branch.
    singleton = bytearray(TABLE_SIZE)
    singleton[32] = 0x10
    literal_block = bytes(singleton) + bytes(4)
    assert walk(literal_block, 8, "spec", quiet).ok
    assert not walk(bytes(singleton) + bytes.fromhex("00 80 00 00"),
                    8, "spec", quiet).ok
    singleton[32] = 0x20
    for extra in (0, 0x20):
        singleton[33] = extra
        try:
            build_table(code_lengths(singleton, 0))
        except InspectionError:
            pass
        else:
            raise AssertionError("other incomplete table accepted")
    singleton = bytearray(TABLE_SIZE)
    singleton[135] = 0x10
    match_block = bytes(singleton) + bytes.fromhex("00 00 00 00 ff fd ff")
    assert not walk(match_block, 0x10000, "spec", quiet).ok
    result = walk(long_payload + match_block, 0x30000, "spec", quiet)
    assert result.ok and result.blocks == 2 and result.produced == 0x30000
    # Check header layout without writing a fixture to disk.
    raw = struct.pack("<IIIIQQIHHQQI", 0x55555555, 0x1C + len(payload),
                      0, 4, 300, 0x3000000, 0xC0E5510A, 0x18, 0x042D,
                      300, 300, len(payload))
    header = Header.parse(raw)
    assert header.dstsize == 300 and header.dstofs == 0x3000000
    # A split inside the header, an empty segment, and a split in the payload.
    from io import BytesIO
    record = raw + payload
    source = Segments.__new__(Segments)
    source.files = []
    source.size = 0
    for chunk in (record[:7], b"", record[7:65], record[65:]):
        source.files.append((BytesIO(chunk), source.size, len(chunk)))
        source.size += len(chunk)
    assert source.read_at(0, HEADER_SIZE) == raw
    assert source.read_at(HEADER_SIZE, len(payload)) == payload
    assert source.read_at(source.size, 0) == b""
    try:
        source.read_at(source.size, 1)
    except InspectionError:
        pass
    else:
        raise AssertionError("out-of-bounds stream read accepted")
    say("SELF-TEST PASS: public vectors, 32-bit lengths, singleton/unused code, bad tables, short reads, crossing, overrun, backref, header, splits.")


def main():
    parser = PrivateArgumentParser(description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="*", help="split files, in physical order")
    select = parser.add_mutually_exclusive_group()
    select.add_argument("--record", type=nonnegative, default=None,
                        help="zero-based record index (default 0); skips prior payloads")
    select.add_argument("--offset", type=nonnegative, default=None,
                        help="record header offset in the concatenated input stream")
    parser.add_argument("--records", type=nonnegative, default=1,
                        help="number of consecutive records to inspect (default 1)")
    parser.add_argument("--mode", choices=("both", "spec", "clip"), default="both")
    parser.add_argument("--table-at", type=nonnegative,
                        help="also validate a table at this PAYLOAD-relative offset")
    parser.add_argument("--every", type=nonnegative, default=1,
                        help="print every Nth block; failures/crossings always printed")
    parser.add_argument("--max-record-mib", type=nonnegative, default=64,
                        help="compressed/declared size safety cap (default 64 MiB each)")
    parser.add_argument("--block-limit", type=nonnegative, default=4096)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.inputs or not all((args.records, args.every, args.max_record_mib, args.block_limit)):
        parser.error("missing input or zero limit")

    say("SBCT-INSPECT v3; read-only, local-only; NO decoded data or raw bytes in report.")
    say("Report contains structural metadata. Review it before sharing.")
    say("Table/cursor offsets are payload-relative; output positions are record-relative.")
    failed = False
    with ExitStack() as stack:
        source = Segments(args.inputs, stack)
        say(f"inputs={len(source.files)} combined_size={source.size:#x}")
        position = args.offset if args.offset is not None else 0
        for _ in range(args.record or 0):
            header = Header.parse(source.read_at(position, HEADER_SIZE))
            position += 0x20 + header.size1
            if position > source.size:
                raise InspectionError("skipped record extends beyond input stream")
        for relative_record in range(args.records):
            header = Header.parse(source.read_at(position, HEADER_SIZE))
            payload_start = position + HEADER_SIZE
            end = payload_start + header.compsize
            if end > source.size:
                raise InspectionError("record extends beyond input stream; supply remaining split files")
            say(f"record_selection_index={relative_record} stream={position:#x}..{end:#x} "
                f"payload_start={payload_start:#x}")
            say(f"size1={header.size1:#x} unk0={header.unk0:#x} unk1={header.unk1:#x} "
                f"dstsize={header.dstsize:#x} dstofs={header.dstofs:#x} compsize={header.compsize:#x}")
            say(f"magic2_expected={header.magic2 == 0xC0E5510A} "
                f"hdrsize={header.hdrsize:#x} flags={header.flags:#x}; sizes_consistent=True")
            cap = args.max_record_mib * 1024 * 1024
            if max(header.compsize, header.dstsize) > cap:
                raise InspectionError("record safety cap exceeded; raise --max-record-mib")
            if header.unk1 != 4:
                raise InspectionError("unobserved +0x0c value; no decoding policy defined")
            if header.compsize == header.dstsize:
                say("Equal stored/plain size: raw-storage candidate; XPRESS inspection skipped.")
                position = end
                continue
            payload = source.read_at(payload_start, header.compsize)
            if args.table_at is not None:
                try:
                    inspect_table(payload, args.table_at)
                except InspectionError as error:
                    say(f"[probe] FAIL: {error}")
                    failed = True
            policies = ("spec", "clip") if args.mode == "both" else (args.mode,)
            for policy in policies:
                say(f"[{policy}] BEGIN")
                result = walk(payload, header.dstsize, policy, say, args.every, args.block_limit)
                failed |= not result.ok
            del payload
            position = end
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except InspectionError as error:
        say(f"FAIL: {error}")
        sys.exit(1)
    except OSError as error:
        print(f"I/O failure: errno={error.errno} (path omitted)", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        # No traceback/source lines or exception message that could expose data.
        print(f"Internal failure: {type(error).__name__} (details suppressed)", file=sys.stderr)
        sys.exit(2)
