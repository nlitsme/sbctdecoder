// Note: code written by chatgpt
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const RECORD_MAGIC: u32 = 0x5555_5555;
const OUTER_HEADER_SIZE: u64 = 0x20;
const INNER_HEADER_SIZE: u64 = 0x1c;
const PAYLOAD_OFFSET: u64 = OUTER_HEADER_SIZE + INNER_HEADER_SIZE;

struct InputSegment {
    path: PathBuf,
    file: File,
    stream_start: u64,
    size: u64,
}

struct SegmentedInput {
    segments: Vec<InputSegment>,
    position: u64,
    size: u64,
}

impl SegmentedInput {
    fn open(paths: &[String]) -> io::Result<Self> {
        let mut segments = Vec::with_capacity(paths.len());
        let mut stream_start = 0u64;

        for name in paths {
            let path = PathBuf::from(name);
            let file = File::open(&path)?;
            let size = file.metadata()?.len();
            segments.push(InputSegment {
                path,
                file,
                stream_start,
                size,
            });
            stream_start = checked_add(stream_start, size, "input stream size")?;
        }

        Ok(Self {
            segments,
            position: 0,
            size: stream_start,
        })
    }

    fn segment_index(&self, position: u64) -> Option<usize> {
        self.segments.iter().position(|segment| {
            position >= segment.stream_start
                && position < segment.stream_start.saturating_add(segment.size)
        })
    }

    fn describe_position(&self, position: u64) -> String {
        if let Some(index) = self.segment_index(position) {
            let segment = &self.segments[index];
            return format!(
                "{}:{:#x}",
                segment.path.display(),
                position - segment.stream_start
            );
        }

        if position == self.size {
            if let Some(segment) = self.segments.last() {
                return format!("{}:{:#x}", segment.path.display(), segment.size);
            }
        }

        format!("stream:{position:#x}")
    }

    fn source_at(&self, position: u64) -> Option<(&Path, u64, u64)> {
        let segment = &self.segments[self.segment_index(position)?];
        Some((
            &segment.path,
            position - segment.stream_start,
            segment.size,
        ))
    }
}

impl Read for SegmentedInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0usize;

        while done < buf.len() && self.position < self.size {
            let index = self.segment_index(self.position).ok_or_else(|| {
                invalid(format!("no input segment at stream offset {:#x}", self.position))
            })?;
            let segment = &mut self.segments[index];
            let local_offset = self.position - segment.stream_start;
            let available = usize::try_from(segment.size - local_offset)
                .unwrap_or(usize::MAX)
                .min(buf.len() - done);

            segment.file.seek(SeekFrom::Start(local_offset))?;
            let count = segment.file.read(&mut buf[done..done + available])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("unexpected EOF in {}", segment.path.display()),
                ));
            }
            done += count;
            self.position += count as u64;
        }

        Ok(done)
    }
}

impl Seek for SegmentedInput {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let position = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.size) + i128::from(delta),
        };
        if position < 0 || position > i128::from(self.size) {
            return Err(invalid(format!("input seek outside stream: {position:#x}")));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[derive(Debug)]
struct RecordHeader {
    record_size: u32,
    unk0: u32,
    unk1: u32,
    plain_size: u64,
    logical_offset: u64,
    magic2: u32,
    inner_header_size: u16,
    flags: u16,
    inner_size_1: u64,
    inner_size_2: u64,
    compressed_size: u32,
}

fn le_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn le_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
}

fn le_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn checked_add(a: u64, b: u64, what: &str) -> io::Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid(format!("integer overflow while computing {what}")))
}

fn read_record_header(
    input: &mut SegmentedInput,
    stream_offset: u64,
) -> io::Result<RecordHeader> {
    let mut buf = [0u8; PAYLOAD_OFFSET as usize];
    input.seek(SeekFrom::Start(stream_offset))?;
    input.read_exact(&mut buf)?;

    let magic = le_u32(&buf, 0x00);
    if magic != RECORD_MAGIC {
        return Err(invalid(format!(
            "bad record magic {magic:#010x} at {}",
            input.describe_position(stream_offset)
        )));
    }

    Ok(RecordHeader {
        record_size: le_u32(&buf, 0x04),
        unk0: le_u32(&buf, 0x08),
        unk1: le_u32(&buf, 0x0c),
        plain_size: le_u64(&buf, 0x10),
        logical_offset: le_u64(&buf, 0x18),
        magic2: le_u32(&buf, 0x20),
        inner_header_size: le_u16(&buf, 0x24),
        flags: le_u16(&buf, 0x26),
        inner_size_1: le_u64(&buf, 0x28),
        inner_size_2: le_u64(&buf, 0x30),
        compressed_size: le_u32(&buf, 0x38),
    })
}

fn check_output_range(
    ranges: &mut BTreeMap<u64, (u64, PathBuf, u64)>,
    start: u64,
    end: u64,
    input_path: &Path,
    file_offset: u64,
) -> io::Result<()> {
    if let Some((&other_start, (other_end, other_path, other_file_offset))) =
        ranges.range(..=start).next_back()
    {
        if *other_end > start {
            return Err(invalid(format!(
                "output range {start:#x}..{end:#x} from {}:{file_offset:#x} overlaps \
                 {other_start:#x}..{other_end:#x} from {}:{other_file_offset:#x}",
                input_path.display(),
                other_path.display()
            )));
        }
    }

    if let Some((&other_start, (other_end, other_path, other_file_offset))) =
        ranges.range(start..).next()
    {
        if other_start < end {
            return Err(invalid(format!(
                "output range {start:#x}..{end:#x} from {}:{file_offset:#x} overlaps \
                 {other_start:#x}..{other_end:#x} from {}:{other_file_offset:#x}",
                input_path.display(),
                other_path.display()
            )));
        }
    }

    ranges.insert(start, (end, input_path.to_owned(), file_offset));
    Ok(())
}

const XPRESS_SYMBOLS: usize = 512;
const XPRESS_TABLE_BYTES: usize = XPRESS_SYMBOLS / 2;
const XPRESS_BLOCK_SIZE: usize = 1 << 16;
const NO_NODE: usize = usize::MAX;

#[derive(Clone, Copy)]
struct HuffmanNode {
    children: [usize; 2],
    is_leaf: bool,
    symbol: u16,
}

struct XpressBitStream<'a> {
    data: &'a [u8],
    position: usize,
    bits: u32,
    available: u32,
}

impl<'a> XpressBitStream<'a> {
    fn new(data: &'a [u8]) -> io::Result<Self> {
        let mut stream = Self {
            data,
            position: 0,
            bits: 0,
            available: 0,
        };
        stream.bits = (stream.read_u16()? << 16) | stream.read_u16()?;
        stream.available = 32;
        Ok(stream)
    }

    fn read_raw<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let end = self.position.checked_add(N)
            .ok_or_else(|| invalid("XPRESS raw-read offset overflow"))?;
        let bytes = self.data.get(self.position..end).ok_or_else(|| {
            invalid(format!(
                "truncated XPRESS raw read: need {N} bytes at bitstream offset {:#x}",
                self.position
            ))
        })?;
        self.position = end;
        Ok(bytes.try_into().unwrap())
    }

    fn read_u16(&mut self) -> io::Result<u32> {
        Ok(u32::from(u16::from_le_bytes(self.read_raw()?)))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.read_raw()?))
    }

    fn read_byte(&mut self) -> io::Result<u8> {
        Ok(self.read_raw::<1>()?[0])
    }

    fn peek(&self, count: u32) -> u32 {
        if count == 0 {
            0
        } else {
            self.bits >> (32 - count)
        }
    }

    fn consume(&mut self, count: u32) -> io::Result<()> {
        self.bits = self.bits.wrapping_shl(count);
        self.available -= count;
        if self.available < 16 {
            self.bits |= self.read_u16()? << (16 - self.available);
            self.available += 16;
        }
        Ok(())
    }
}

fn read_xpress_match_length(
    stream: &mut XpressBitStream<'_>,
    length_header: u32,
) -> io::Result<usize> {
    // MS-XCA 2.1.4.3: FF + 0000 introduces a raw little-endian u32.
    // All extended-length bytes precede consumption/refill of offset bits.
    let mut length = u64::from(length_header);
    if length_header == 15 {
        let extension = stream.read_byte()?;
        if extension == 255 {
            length = u64::from(stream.read_u16()?);
            if length == 0 {
                length = u64::from(stream.read_u32()?);
            }
            if length < 15 {
                return Err(invalid("invalid XPRESS extended match length (<15)"));
            }
        } else {
            length = 15 + u64::from(extension);
        }
    }
    // Widen before adding the minimum match length, so u32::MAX cannot wrap.
    usize::try_from(length + 3)
        .map_err(|_| invalid("XPRESS match length is too large for this platform"))
}

fn add_huffman_leaf(
    nodes: &mut [HuffmanNode],
    leaf_index: usize,
    code: u32,
    mut bits: u32,
) -> Option<usize> {
    let mut current = 0usize;
    let mut next_free = leaf_index + 1;

    while bits > 1 {
        bits -= 1;
        let child = usize::try_from((code >> bits) & 1).ok()?;
        if nodes.get(current)?.children[child] == NO_NODE {
            nodes.get_mut(next_free)?.is_leaf = false;
            nodes.get_mut(current)?.children[child] = next_free;
            next_free += 1;
        }
        current = nodes.get(current)?.children[child];
    }

    let child = usize::try_from(code & 1).ok()?;
    nodes.get_mut(current)?.children[child] = leaf_index;
    Some(next_free)
}

fn build_xpress_tree(compressed: &[u8]) -> io::Result<Vec<HuffmanNode>> {
    if compressed.len() < XPRESS_TABLE_BYTES {
        return Err(invalid("truncated XPRESS-Huffman code-length table"));
    }

    let mut symbols = Vec::with_capacity(XPRESS_SYMBOLS);
    for (index, byte) in compressed[..XPRESS_TABLE_BYTES].iter().copied().enumerate() {
        symbols.push((byte & 0x0f, u16::try_from(index * 2).unwrap()));
        symbols.push((byte >> 4, u16::try_from(index * 2 + 1).unwrap()));
    }
    let coverage: u32 = symbols.iter()
        .filter(|(length, _)| *length != 0)
        .map(|(length, _)| 1u32 << (15 - u32::from(*length)))
        .sum();
    // Observed SBCT singleton variant: only canonical code 0 is assigned.
    // Leave code 1 absent; do not accept arbitrary incomplete trees.
    let singleton = symbols.iter().filter(|(length, _)| *length != 0).count() == 1
        && symbols.iter().any(|(length, _)| *length == 1);
    if coverage != 1 << 15 && !singleton {
        return Err(invalid(format!(
            "invalid XPRESS-Huffman table: code-space coverage {coverage}/32768"
        )));
    }
    symbols.sort_unstable();

    let empty = HuffmanNode {
        children: [NO_NODE, NO_NODE],
        is_leaf: false,
        symbol: 0,
    };
    let mut nodes = vec![empty; 1024];
    let first_used = symbols.iter().take_while(|(length, _)| *length == 0).count();
    let mut code = 0u32;
    let mut previous_length = 1u32;
    let mut leaf_index = 1usize;

    for &(length, symbol) in &symbols[first_used..] {
        let length = u32::from(length);
        if length == 0 || length > 15 {
            return Err(invalid("invalid XPRESS-Huffman code length"));
        }

        let leaf = nodes
            .get_mut(leaf_index)
            .ok_or_else(|| invalid("over-subscribed XPRESS-Huffman tree"))?;
        leaf.symbol = symbol;
        leaf.is_leaf = true;

        code = code.wrapping_shl(length - previous_length);
        previous_length = length;
        leaf_index = add_huffman_leaf(&mut nodes, leaf_index, code, length)
            .ok_or_else(|| invalid("over-subscribed XPRESS-Huffman tree"))?;
        code = code.wrapping_add(1);
    }

    Ok(nodes)
}

fn decode_xpress_symbol(
    stream: &mut XpressBitStream<'_>,
    nodes: &[HuffmanNode],
) -> io::Result<u16> {
    let mut node_index = 0usize;
    loop {
        let node = nodes
            .get(node_index)
            .ok_or_else(|| invalid("XPRESS-Huffman tree index out of range"))?;
        if node.is_leaf {
            return Ok(node.symbol);
        }

        let bit = usize::try_from(stream.peek(1)).unwrap();
        stream.consume(1)?;
        node_index = node.children[bit];
        if node_index == NO_NODE {
            return Err(invalid("invalid or truncated XPRESS-Huffman bitstream"));
        }
    }
}

fn decompress_xpress_huffman(compressed: &[u8], output_size: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(output_size);
    let mut compressed_position = 0usize;
    let mut block_number = 0usize;

    while output.len() < output_size && compressed_position < compressed.len() {
        let table_end = compressed_position
            .checked_add(XPRESS_TABLE_BYTES)
            .ok_or_else(|| invalid("XPRESS-Huffman table offset overflow"))?;
        let table = compressed
            .get(compressed_position..table_end)
            .ok_or_else(|| {
                invalid(format!(
                    "truncated XPRESS-Huffman table for block {block_number} at payload offset \
                     {compressed_position:#x}"
                ))
            })?;
        let tree = build_xpress_tree(table).map_err(|error| invalid(format!(
            "block {block_number}, table at payload {compressed_position:#x}: {error}"
        )))?;
        let table_position = compressed_position;
        compressed_position = table_end;

        let block_output_start = output.len();
        let block_output_limit = block_output_start
            .saturating_add(XPRESS_BLOCK_SIZE)
            .min(output_size);
        let bitstream_position = compressed_position;
        let mut stream = XpressBitStream::new(&compressed[bitstream_position..])?;

        while output.len() < block_output_limit {
            let symbol = decode_xpress_symbol(&mut stream, &tree)?;

            if symbol < 256 {
                output.push(symbol as u8);
                continue;
            }

            let match_symbol = u32::from(symbol) - 256;
            let offset_bits = match_symbol >> 4;
            let match_offset = (1usize << offset_bits)
                | usize::try_from(stream.peek(offset_bits)).unwrap();

            // The extended match length is a raw byte, word, or dword interleaved at
            // the compressed-byte cursor.  Read it before consuming the offset
            // bits: consuming those bits may refill the bit buffer and advance
            // that cursor.
            let length_header = match_symbol & 0x0f;
            let match_length = read_xpress_match_length(&mut stream, length_header)
                .map_err(|error| invalid(format!(
                    "block {block_number}, output {:#x}, payload cursor {:#x}: {error}",
                    output.len(), bitstream_position + stream.position
                )))?;
            stream.consume(offset_bits)?;

            if match_offset == 0 || match_offset > output.len() {
                return Err(invalid(format!(
                    "XPRESS-Huffman match offset {match_offset:#x} precedes output; block \
                     {block_number}, output position {:#x}, block output position {:#x}, \
                     payload byte position {:#x}, symbol {symbol:#x}, match symbol \
                     {match_symbol:#x}, offset bits {offset_bits}, match length {match_length:#x}",
                    output.len(),
                    output.len() - block_output_start,
                    bitstream_position.saturating_add(stream.position)
                )));
            }
            if match_length > output_size - output.len() {
                return Err(invalid(format!(
                    "XPRESS-Huffman match in block {block_number} exceeds declared record \
                     output: position {:#x}, length {match_length:#x}, limit {output_size:#x}",
                    output.len()
                )));
            }

            // 64 KiB is a block-ending threshold, not a match-copy limit.
            // Finish the entire match before beginning the next Huffman table.
            for _ in 0..match_length {
                let byte = output[output.len() - match_offset];
                output.push(byte);
            }
        }

        let block_output_end = output.len();
        compressed_position = bitstream_position.saturating_add(stream.position);
        if compressed_position > compressed.len() {
            return Err(invalid(format!(
                "XPRESS-Huffman block {block_number} read past the compressed payload by \
                 {:#x} bytes",
                compressed_position - compressed.len()
            )));
        }
        eprintln!(
            "    XPRESS block {block_number:4}: table {table_position:#08x}, bitstream \
             {bitstream_position:#08x}..{compressed_position:#08x}, output \
             {block_output_start:#010x}..{block_output_end:#010x}, produced {:#x}",
            block_output_end - block_output_start
        );
        block_number += 1;
    }

    if output.len() < output_size {
        eprintln!(
            "    WARNING: short XPRESS output: decoded {:#x} of {output_size:#x} bytes; \
             zero-filling the {:#x}-byte suffix is an unverified assumption",
            output.len(),
            output_size - output.len()
        );
    } else if compressed_position != compressed.len() {
        eprintln!(
            "    XPRESS trailing payload: {:#x} bytes at {compressed_position:#x}..{:#x}",
            compressed.len() - compressed_position,
            compressed.len()
        );
    }

    Ok(output)
}

fn print_record_header(
    input: &SegmentedInput,
    record_number: u64,
    stream_offset: u64,
    record_end: u64,
    payload_stream_offset: u64,
    header: &RecordHeader,
    compressed: &[u8],
) {
    let output_end = header.logical_offset.saturating_add(header.plain_size);
    let payload_end = payload_stream_offset.saturating_add(u64::from(header.compressed_size));
    let source = input.describe_position(stream_offset);
    let record_end_location = input.describe_position(record_end);
    let payload_start_location = input.describe_position(payload_stream_offset);
    let payload_end_location = input.describe_position(payload_end);
    let source_file_size = input
        .source_at(stream_offset)
        .map(|(_, _, size)| size)
        .unwrap_or(0);
    let preview = compressed
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    eprintln!("record {record_number} header:");
    eprintln!("  source:              {source}");
    eprintln!(
        "  source file size:    {source_file_size:#x} ({source_file_size})"
    );
    eprintln!("  stream offset:       {stream_offset:#x}");
    eprintln!("  record file range:   {source}..{record_end_location}");
    eprintln!("  magic:               {RECORD_MAGIC:#010x}");
    eprintln!(
        "  outer record size:   {:#x} ({})",
        header.record_size, header.record_size
    );
    eprintln!("  unknown +0x08:       {:#x} ({})", header.unk0, header.unk0);
    eprintln!("  unknown +0x0c:       {:#x} ({})", header.unk1, header.unk1);
    eprintln!(
        "  plain size:          {:#x} ({})",
        header.plain_size, header.plain_size
    );
    eprintln!("  logical offset:      {:#x}", header.logical_offset);
    eprintln!("  logical output end:  {output_end:#x}");
    eprintln!("  magic2:              {:#010x}", header.magic2);
    eprintln!(
        "  inner header size:   {:#x} ({})",
        header.inner_header_size, header.inner_header_size
    );
    eprintln!("  flags:               {:#06x}", header.flags);
    eprintln!("  inner plain size 1:  {:#x}", header.inner_size_1);
    eprintln!("  inner plain size 2:  {:#x}", header.inner_size_2);
    eprintln!(
        "  compressed size:     {:#x} ({})",
        header.compressed_size, header.compressed_size
    );
    eprintln!(
        "  payload file range:  {payload_start_location}..{payload_end_location}"
    );
    eprintln!("  payload first bytes: {preview}");

    let stored_uncompressed =
        usize::try_from(header.plain_size).ok() == Some(compressed.len());

    if header.unk1 == 4 && stored_uncompressed {
        eprintln!("  storage mode:         raw fallback (stored size equals plain size)");
    } else if header.unk1 == 4 && compressed.len() >= XPRESS_TABLE_BYTES {
        let mut histogram = [0usize; 16];
        for byte in &compressed[..XPRESS_TABLE_BYTES] {
            histogram[usize::from(byte & 0x0f)] += 1;
            histogram[usize::from(byte >> 4)] += 1;
        }
        let nonzero_symbols = XPRESS_SYMBOLS - histogram[0];
        let histogram = histogram
            .iter()
            .enumerate()
            .map(|(length, count)| format!("{length}:{count}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("  Huffman table bytes: {XPRESS_TABLE_BYTES:#x}");
        eprintln!("  coded symbols:       {nonzero_symbols}/{XPRESS_SYMBOLS}");
        eprintln!("  code-length counts:  {histogram}");
        eprintln!(
            "  bitstream start:     {}",
            input.describe_position(
                payload_stream_offset.saturating_add(XPRESS_TABLE_BYTES as u64)
            )
        );
    }
}

fn decompress(header: &RecordHeader, compressed: &[u8]) -> io::Result<Vec<u8>> {
    let expected_size = usize::try_from(header.plain_size)
        .map_err(|_| invalid("uncompressed record is too large for this platform"))?;

    match header.unk1 {
        // All observed records contain 4 at +0x0c. Their payload is either
        // XPRESS-Huffman data or, when stored and plain sizes are equal, the
        // literal bytes. The field's actual name and enum are not established.
        4 if compressed.len() == expected_size => {
            eprintln!(
                "    payload stored uncompressed: {expected_size:#x} bytes"
            );
            Ok(compressed.to_vec())
        }
        4 => decompress_xpress_huffman(compressed, expected_size),

        value => Err(invalid(format!(
            "unsupported value {value:#x} in record header field +0x0c"
        ))),
    }
}

fn process_inputs(
    input_names: &[String],
    output: &mut File,
    ranges: &mut BTreeMap<u64, (u64, PathBuf, u64)>,
    record_number: &mut u64,
    maximum_output_end: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let mut input = SegmentedInput::open(input_names)?;
    let input_size = input.size;
    let mut stream_offset = 0u64;

    while stream_offset < input_size {
        let remaining = input_size - stream_offset;
        if remaining < PAYLOAD_OFFSET {
            return Err(invalid(format!(
                "input stream has {remaining:#x} trailing bytes at {}, too few for a header",
                input.describe_position(stream_offset)
            ))
            .into());
        }

        let (input_path, file_offset, _) = input
            .source_at(stream_offset)
            .ok_or_else(|| invalid(format!("no source at stream offset {stream_offset:#x}")))?;
        let input_path = input_path.to_owned();
        let header = read_record_header(&mut input, stream_offset)?;

        if u64::from(header.record_size) < INNER_HEADER_SIZE {
            return Err(invalid(format!(
                "record at {}:{file_offset:#x} has invalid size {:#x}",
                input_path.display(),
                header.record_size
            ))
            .into());
        }

        let record_end = checked_add(
            stream_offset,
            checked_add(
                OUTER_HEADER_SIZE,
                u64::from(header.record_size),
                "record length",
            )?,
            "record end",
        )?;

        if record_end > input_size {
            return Err(invalid(format!(
                "record at {}:{file_offset:#x} ends at stream offset {record_end:#x}, past combined input size {input_size:#x}",
                input_path.display(),
            ))
            .into());
        }

        let expected_record_size = checked_add(
            INNER_HEADER_SIZE,
            u64::from(header.compressed_size),
            "inner header and payload size",
        )?;
        if u64::from(header.record_size) != expected_record_size {
            return Err(invalid(format!(
                "record at {}:{file_offset:#x}: outer size {:#x}, but inner header + payload is {expected_record_size:#x}",
                input_path.display(),
                header.record_size
            ))
            .into());
        }

        if header.inner_size_1 != header.plain_size || header.inner_size_2 != header.plain_size {
            return Err(invalid(format!(
                "record at {}:{file_offset:#x}: inconsistent plain sizes {:#x}, {:#x}, {:#x}",
                input_path.display(),
                header.plain_size,
                header.inner_size_1,
                header.inner_size_2
            ))
            .into());
        }

        let payload_size = usize::try_from(header.compressed_size)
            .map_err(|_| invalid("compressed record is too large for this platform"))?;
        let payload_stream_offset =
            checked_add(stream_offset, PAYLOAD_OFFSET, "payload offset")?;
        let mut compressed = vec![0u8; payload_size];
        input.seek(SeekFrom::Start(payload_stream_offset))?;
        input.read_exact(&mut compressed)?;

        print_record_header(
            &input,
            *record_number,
            stream_offset,
            record_end,
            payload_stream_offset,
            &header,
            &compressed,
        );

        let plain = decompress(&header, &compressed).map_err(|error| {
            invalid(format!(
                "{}:{file_offset:#x}, record {}: {error}",
                input_path.display(),
                *record_number
            ))
        })?;

        let output_end = checked_add(
            header.logical_offset,
            header.plain_size,
            "logical output end",
        )?;
        check_output_range(
            ranges,
            header.logical_offset,
            output_end,
            &input_path,
            file_offset,
        )?;

        let decoded_size = u64::try_from(plain.len())
            .map_err(|_| invalid("decoded record is too large for this platform"))?;
        let sparse_suffix_size = header.plain_size - decoded_size;
        if sparse_suffix_size != 0 {
            let sparse_start = header.logical_offset + decoded_size;
            eprintln!(
                "    SBCT sparse suffix: output {sparse_start:#x}..{output_end:#x} \
                 ({sparse_suffix_size:#x} zero bytes)"
            );
        }

        output.seek(SeekFrom::Start(header.logical_offset))?;
        output.write_all(&plain)?;
        *maximum_output_end = (*maximum_output_end).max(output_end);

        println!(
            "record {:5}  file {:#010x}  unk0 {:#x}  output {:#012x}..{:#012x}  \
             decoded {:#x}/{:#x}  compressed {:#x}  unk1 {:#x}  flags {:#06x}",
            *record_number,
            file_offset,
            header.unk0,
            header.logical_offset,
            output_end,
            plain.len(),
            header.plain_size,
            header.compressed_size,
            header.unk1,
            header.flags
        );

        *record_number += 1;
        stream_offset = record_end;
    }

    Ok(())
}

fn usage(program: &str) {
    eprintln!("usage: {program} OUTPUT.raw INPUT.s0000000000 [INPUT.s0000000001 ...]");
    eprintln!();
    eprintln!("Pass all split files from one sbct.vol.pXX set in physical order.");
    eprintln!("Records may cross an input-file boundary.");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage(&args[0]);
        std::process::exit(2);
    }

    let output_path = Path::new(&args[1]);
    let mut output = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output_path)?;

    let mut ranges = BTreeMap::new();
    let mut record_number = 0u64;
    let mut maximum_output_end = 0u64;

    for name in &args[2..] {
        eprintln!("input segment {}", Path::new(name).display());
    }
    process_inputs(
        &args[2..],
        &mut output,
        &mut ranges,
        &mut record_number,
        &mut maximum_output_end,
    )?;

    output.set_len(maximum_output_end)?;
    output.flush()?;

    eprintln!(
        "wrote {} records, logical image size {maximum_output_end:#x}, to {}",
        record_number,
        output_path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abc_vector() -> Vec<u8> {
        // MS-XCA 3.2: three literals followed by a distance-3 length-297 match.
        let mut data = vec![0u8; XPRESS_TABLE_BYTES];
        data[48] = 0x30;
        data[49] = 0x23;
        data[128] = 0x02;
        data[143] = 0x20;
        data.extend_from_slice(&[0xa8, 0xdc, 0, 0, 0xff, 0x26, 0x01]);
        data
    }

    fn long_run(size: u32) -> Vec<u8> {
        // Two one-bit codes: literal A (0), distance-1 extended match (1).
        // The first literal accounts for one byte; the encoded length omits 3.
        assert!(size >= 0x10004);
        let mut data = vec![0u8; XPRESS_TABLE_BYTES];
        data[32] = 0x10;
        data[135] = 0x10;
        data.extend_from_slice(&[0, 0x40, 0, 0, 0xff, 0, 0]);
        data.extend_from_slice(&(size - 4).to_le_bytes());
        data
    }

    #[test]
    fn public_abc_example() {
        assert_eq!(decompress_xpress_huffman(&abc_vector(), 300).unwrap(),
                   b"abc".repeat(100));
    }

    #[test]
    fn long_match_is_not_clipped() {
        let data = long_run(0x20000);
        assert_eq!(decompress_xpress_huffman(&data, 0x20000).unwrap(),
                   vec![b'A'; 0x20000]);
    }

    #[test]
    fn next_table_follows_the_complete_long_match() {
        let mut data = long_run(0x20000);
        data.extend(abc_vector());
        let mut expected = vec![b'A'; 0x20000];
        expected.extend(b"abc".repeat(100));
        assert_eq!(decompress_xpress_huffman(&data, expected.len()).unwrap(), expected);
    }

    #[test]
    fn truncated_dword_is_rejected() {
        let data = long_run(0x20000);
        for cut in 1..=4 {
            assert!(decompress_xpress_huffman(&data[..data.len() - cut], 0x20000).is_err());
        }
    }

    #[test]
    fn overrun_and_invalid_extended_lengths_are_rejected() {
        let data = long_run(0x20000);
        assert!(decompress_xpress_huffman(&data, 0x1ffff).is_err());
        for length in [0u32, 1, 14, u32::MAX] {
            let mut invalid_data = data[..data.len() - 4].to_vec();
            invalid_data.extend_from_slice(&length.to_le_bytes());
            assert!(decompress_xpress_huffman(&invalid_data, 0x20000).is_err());
        }
    }

    #[test]
    fn extended_length_is_read_before_offset_refill() {
        let data = [0xff, 0, 0, 0, 0, 1, 0, 0x34, 0x12];
        let mut stream = XpressBitStream {
            data: &data, position: 0, bits: 0, available: 16,
        };
        assert_eq!(read_xpress_match_length(&mut stream, 15).unwrap(), 0x10003);
        assert_eq!(stream.position, 7);
        stream.consume(15).unwrap();
        assert_eq!(stream.position, 9);
        assert_eq!(stream.available, 17);
        assert_eq!(stream.bits, 0x1234 << 15);
    }

    #[test]
    fn singleton_literal_and_unused_branch() {
        let mut data = vec![0u8; XPRESS_TABLE_BYTES];
        data[32] = 0x10; // Literal A, canonical code 0.
        data.extend_from_slice(&[0; 4]);
        assert_eq!(decompress_xpress_huffman(&data, 8).unwrap(), vec![b'A'; 8]);
        data[XPRESS_TABLE_BYTES + 1] = 0x80; // First code bit is 1.
        assert!(decompress_xpress_huffman(&data, 8).is_err());
    }

    #[test]
    fn singleton_match_uses_previous_block_history() {
        let mut block = vec![0u8; XPRESS_TABLE_BYTES];
        block[135] = 0x10; // Distance-1 match with extended length, code 0.
        block.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xfd, 0xff]);
        assert!(decompress_xpress_huffman(&block, 0x10000).is_err());
        let mut data = long_run(0x20000);
        data.extend(block);
        assert_eq!(decompress_xpress_huffman(&data, 0x30000).unwrap(),
                   vec![b'A'; 0x30000]);
    }

    #[test]
    fn invalid_tables_and_short_lookahead_are_rejected() {
        assert!(build_xpress_tree(&[0; 256]).is_err());
        assert!(build_xpress_tree(&[0x11; 256]).is_err());
        let mut incomplete = [0u8; 256];
        incomplete[32] = 0x20; // Singleton with a two-bit code is not allowed.
        assert!(build_xpress_tree(&incomplete).is_err());
        incomplete[33] = 0x20; // Nor two two-bit codes.
        assert!(build_xpress_tree(&incomplete).is_err());
        assert!(XpressBitStream::new(&[0, 0, 0]).is_err());
    }
}
