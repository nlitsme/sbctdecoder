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

#[derive(Debug)]
struct RecordHeader {
    record_size: u32,
    index: u32,
    algorithm: u32,
    plain_size: u64,
    logical_offset: u64,
    tag: u64,
    inner_size_1: u64,
    inner_size_2: u64,
    compressed_size: u32,
}

fn le_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
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

fn read_record_header(input: &mut File, file_offset: u64) -> io::Result<RecordHeader> {
    let mut buf = [0u8; PAYLOAD_OFFSET as usize];
    input.seek(SeekFrom::Start(file_offset))?;
    input.read_exact(&mut buf)?;

    let magic = le_u32(&buf, 0x00);
    if magic != RECORD_MAGIC {
        return Err(invalid(format!(
            "bad record magic {magic:#010x} at file offset {file_offset:#x}"
        )));
    }

    Ok(RecordHeader {
        record_size: le_u32(&buf, 0x04),
        index: le_u32(&buf, 0x08),
        algorithm: le_u32(&buf, 0x0c),
        plain_size: le_u64(&buf, 0x10),
        logical_offset: le_u64(&buf, 0x18),
        tag: le_u64(&buf, 0x20),
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
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            bits: 0,
            available: 0,
        }
    }

    fn read_u16(&mut self) -> u32 {
        let lo = self.data.get(self.position).copied().unwrap_or(0);
        let hi = self.data.get(self.position + 1).copied().unwrap_or(0);
        self.position = self.position.saturating_add(2);
        u32::from(lo) | (u32::from(hi) << 8)
    }

    fn read_byte(&mut self) -> u8 {
        let byte = self.data.get(self.position).copied().unwrap_or(0);
        self.position = self.position.saturating_add(1);
        byte
    }

    // XPRESS bit coding uses little-endian 16-bit units whose bits are
    // consumed most-significant first.  Fetch units only when required:
    // literal match-length bytes are interleaved at `position`, so eagerly
    // prefetching an extra unit would make those byte reads skip two bytes.
    fn ensure(&mut self, count: u32) {
        if self.available < count {
            self.bits |= self.read_u16() << (16 - self.available);
            self.available += 16;
        }
    }

    fn peek(&self, count: u32) -> u32 {
        if count == 0 {
            0
        } else {
            self.bits >> (32 - count)
        }
    }

    fn consume(&mut self, count: u32) {
        self.bits = self.bits.wrapping_shl(count);
        self.available -= count;
    }
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
    stream.ensure(15);
    let mut node_index = 0usize;
    loop {
        let node = nodes
            .get(node_index)
            .ok_or_else(|| invalid("XPRESS-Huffman tree index out of range"))?;
        if node.is_leaf {
            return Ok(node.symbol);
        }

        let bit = usize::try_from(stream.peek(1)).unwrap();
        stream.consume(1);
        node_index = node.children[bit];
        if node_index == NO_NODE {
            return Err(invalid("invalid or truncated XPRESS-Huffman bitstream"));
        }
    }
}

fn decompress_xpress_huffman(compressed: &[u8], output_size: usize) -> io::Result<Vec<u8>> {
    let tree = build_xpress_tree(compressed)?;
    let bitstream_data = compressed
        .get(XPRESS_TABLE_BYTES..)
        .ok_or_else(|| invalid("truncated XPRESS-Huffman stream"))?;
    let mut stream = XpressBitStream::new(bitstream_data);
    let mut output = Vec::with_capacity(output_size);

    // SBCT records use one Huffman table for the entire compressed record.
    // In particular, there is no new table at each 64 KiB output boundary.
    while output.len() < output_size {
        let symbol = decode_xpress_symbol(&mut stream, &tree)?;

        if symbol < 256 {
            output.push(symbol as u8);
            continue;
        }

        let match_symbol = u32::from(symbol) - 256;
        let offset_bits = match_symbol >> 4;
        stream.ensure(16);
        let match_offset = (1usize << offset_bits)
            | usize::try_from(stream.peek(offset_bits)).unwrap();
        stream.consume(offset_bits);

        let length_header = match_symbol & 0x0f;
        let mut match_length = length_header;
        if length_header == 0x0f {
            match_length = u32::from(stream.read_byte()) + 0x0f;
            if match_length == 0x10e {
                let lo = u32::from(stream.read_byte());
                let hi = u32::from(stream.read_byte());
                match_length = lo | (hi << 8);
            }
        }
        match_length += 3;
        let match_length = usize::try_from(match_length).unwrap();

        if match_offset == 0 || match_offset > output.len() {
            return Err(invalid(format!(
                "XPRESS-Huffman match offset {match_offset:#x} precedes output; \
                 output position {:#x}, bitstream byte position {:#x} \
                 (payload position about {:#x}), symbol {symbol:#x}, \
                 match symbol {match_symbol:#x}, offset bits {offset_bits}, \
                 match length {match_length:#x}",
                output.len(),
                stream.position,
                XPRESS_TABLE_BYTES.saturating_add(stream.position)
            )));
        }
        if match_length > output_size - output.len() {
            return Err(invalid(format!(
                "XPRESS-Huffman match overruns output by {:#x} bytes",
                match_length - (output_size - output.len())
            )));
        }

        for _ in 0..match_length {
            let byte = output[output.len() - match_offset];
            output.push(byte);
        }
    }

    Ok(output)
}

fn algorithm_name(algorithm: u32) -> &'static str {
    match algorithm {
        1 => "uncompressed",
        4 => "XPRESS-Huffman",
        _ => "unknown",
    }
}

fn print_record_header(
    input_path: &Path,
    input_size: u64,
    record_number: u64,
    file_offset: u64,
    record_end: u64,
    payload_file_offset: u64,
    header: &RecordHeader,
    compressed: &[u8],
) {
    let output_end = header.logical_offset.saturating_add(header.plain_size);
    let payload_end = payload_file_offset.saturating_add(u64::from(header.compressed_size));
    let preview = compressed
        .iter()
        .take(32)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    eprintln!("record {record_number} header:");
    eprintln!("  source:              {}", input_path.display());
    eprintln!("  source file size:    {input_size:#x} ({input_size})");
    eprintln!("  record file range:   {file_offset:#x}..{record_end:#x}");
    eprintln!("  magic:               {RECORD_MAGIC:#010x}");
    eprintln!(
        "  outer record size:   {:#x} ({})",
        header.record_size, header.record_size
    );
    eprintln!("  record index:        {:#x} ({})", header.index, header.index);
    eprintln!(
        "  algorithm:           {:#x} ({}, {})",
        header.algorithm,
        header.algorithm,
        algorithm_name(header.algorithm)
    );
    eprintln!(
        "  plain size:          {:#x} ({})",
        header.plain_size, header.plain_size
    );
    eprintln!("  logical offset:      {:#x}", header.logical_offset);
    eprintln!("  logical output end:  {output_end:#x}");
    eprintln!("  tag/checksum:        {:#018x}", header.tag);
    eprintln!("  inner plain size 1:  {:#x}", header.inner_size_1);
    eprintln!("  inner plain size 2:  {:#x}", header.inner_size_2);
    eprintln!(
        "  compressed size:     {:#x} ({})",
        header.compressed_size, header.compressed_size
    );
    eprintln!("  payload file range:  {payload_file_offset:#x}..{payload_end:#x}");
    eprintln!("  payload first bytes: {preview}");

    if header.algorithm == 4 && compressed.len() >= XPRESS_TABLE_BYTES {
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
            "  bitstream file start:{:#x}",
            payload_file_offset.saturating_add(XPRESS_TABLE_BYTES as u64)
        );
    }
}

fn decompress(header: &RecordHeader, compressed: &[u8]) -> io::Result<Vec<u8>> {
    let expected_size = usize::try_from(header.plain_size)
        .map_err(|_| invalid("uncompressed record is too large for this platform"))?;

    match header.algorithm {
        // Windows CompressAlgorithm::NullAlgorithm.
        1 => {
            if compressed.len() != expected_size {
                return Err(invalid(format!(
                    "uncompressed record has {:#x} payload bytes, expected {:#x}",
                    compressed.len(),
                    expected_size
                )));
            }
            Ok(compressed.to_vec())
        }

        // Windows CompressAlgorithm::XpressHuff.
        4 => decompress_xpress_huffman(compressed, expected_size),

        algorithm => Err(invalid(format!(
            "unsupported compression algorithm {algorithm}"
        ))),
    }
}

fn process_file(
    input_path: &Path,
    output: &mut File,
    ranges: &mut BTreeMap<u64, (u64, PathBuf, u64)>,
    record_number: &mut u64,
    maximum_output_end: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let mut input = File::open(input_path)?;
    let input_size = input.metadata()?.len();
    let mut file_offset = 0u64;

    while file_offset < input_size {
        let remaining = input_size - file_offset;
        if remaining < PAYLOAD_OFFSET {
            return Err(invalid(format!(
                "{} has {remaining:#x} trailing bytes at {file_offset:#x}, too few for a header",
                input_path.display()
            ))
            .into());
        }

        let header = read_record_header(&mut input, file_offset)?;

        if u64::from(header.record_size) < INNER_HEADER_SIZE {
            return Err(invalid(format!(
                "record at {}:{file_offset:#x} has invalid size {:#x}",
                input_path.display(),
                header.record_size
            ))
            .into());
        }

        let record_end = checked_add(
            file_offset,
            checked_add(
                OUTER_HEADER_SIZE,
                u64::from(header.record_size),
                "record length",
            )?,
            "record end",
        )?;

        if record_end > input_size {
            return Err(invalid(format!(
                "record at {}:{file_offset:#x} ends at {record_end:#x}, past file size {input_size:#x}",
                input_path.display()
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
        let payload_file_offset = checked_add(file_offset, PAYLOAD_OFFSET, "payload offset")?;
        let mut compressed = vec![0u8; payload_size];
        input.seek(SeekFrom::Start(payload_file_offset))?;
        input.read_exact(&mut compressed)?;

        print_record_header(
            input_path,
            input_size,
            *record_number,
            file_offset,
            record_end,
            payload_file_offset,
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
            input_path,
            file_offset,
        )?;

        output.seek(SeekFrom::Start(header.logical_offset))?;
        output.write_all(&plain)?;
        *maximum_output_end = (*maximum_output_end).max(output_end);

        println!(
            "record {:5}  file {:#010x}  index {:5}  output {:#012x}..{:#012x}  \
             plain {:#x}  compressed {:#x}  algorithm {}  tag {:#018x}",
            *record_number,
            file_offset,
            header.index,
            header.logical_offset,
            output_end,
            header.plain_size,
            header.compressed_size,
            header.algorithm,
            header.tag
        );

        *record_number += 1;
        file_offset = record_end;
    }

    Ok(())
}

fn usage(program: &str) {
    eprintln!("usage: {program} OUTPUT.raw INPUT.s0000000000 [INPUT.s0000000001 ...]");
    eprintln!();
    eprintln!("Pass the s* files from one sbct.vol.pXX set in lexical order.");
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
        let input_path = Path::new(name);
        eprintln!("processing {}", input_path.display());
        process_file(
            input_path,
            &mut output,
            &mut ranges,
            &mut record_number,
            &mut maximum_output_end,
        )?;
    }

    output.set_len(maximum_output_end)?;
    output.flush()?;

    eprintln!(
        "wrote {} records, logical image size {maximum_output_end:#x}, to {}",
        record_number,
        output_path.display()
    );

    Ok(())
}
