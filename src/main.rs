use crate::md5_reader::ReadHasher;
use crate::md5_reader::Md5Reader;
use std::io::ErrorKind;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use byteorder::{ReadBytesExt, LE};
use std::fmt;

mod md5_reader;

// TODO Figure out a more friendly way to write these out.
const MAGIC_PKT: [u8; 8] = [b'P', b'A', b'R', b'2', 0, b'P', b'K', b'T'];
const TYPE_MAIN: [u8; 16] = [b'P', b'A', b'R', b' ', b'2', b'.', b'0', 0, b'M', b'a', b'i', b'n', 0, 0, 0, 0];
const TYPE_FILEDESC: [u8; 16] = [b'P', b'A', b'R', b' ', b'2', b'.', b'0', 0, b'F', b'i', b'l', b'e', b'D', b'e', b's', b'c'];
const TYPE_IFSC: [u8; 16] = [b'P', b'A', b'R', b' ', b'2', b'.', b'0', 0, b'I', b'F', b'S', b'C', 0, 0, 0, 0];
const TYPE_RECVSLICE: [u8; 16] = [b'P', b'A', b'R', b' ', b'2', b'.', b'0', 0, b'R', b'e', b'c', b'v', b'S', b'l', b'i', b'c'];
const TYPE_CREATOR: [u8; 16] = [b'P', b'A', b'R', b' ', b'2', b'.', b'0', 0, b'C', b'r', b'e', b'a', b't', b'o', b'r', 0];

const HEADER_LEN: usize = 8 + 8 + 16 + 16 + 16;
const FILEDESC_LEN: usize = 16 + 16 + 16 + 8;

// TODO make headers print prettier
#[derive(Default)]
pub struct Header {
    pub magic: [u8; 8], // {'P', 'A', 'R', '2', '\0', 'P', 'K', 'T'}
    pub length: u64,

    pub packet_md5: [u8; 16], // TODO change to md5::Digest
    pub recovery_set_id: [u8; 16], // TODO create new ID type

    pub t: [u8; 16], // TODO rename type
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
         // TODO change the unwrap to or_else show hex
         .field("magic", &String::from_utf8(self.magic.to_vec()).unwrap())
         .field("length", &self.length)
         .field("packet_md5", &md5::Digest(self.packet_md5))
         .field("recovery_set_id", &md5::Digest(self.recovery_set_id))

         // TODO change the unwrap to or_else show hex
         .field("type", &String::from_utf8(self.t.to_vec()).unwrap())
         .finish()
    }
}


fn read_header<R: Read>(reader: &mut Md5Reader<R>) -> std::io::Result<Option<Header>> {
    let mut header = Header::default();

    // Read the magic, but special case UnexpectedEof.
    // We allow this to fail with a normal Eof. This is a little buggy
    // as in if we read half the magic, we will still say Eof.
    match reader.read_exact(&mut header.magic) {
        Ok(_) => {},
        Err(err) => match err.kind() {
            ErrorKind::UnexpectedEof => return Ok(None),
            _ => return Err(err),
        }

    }

    // TODO Test magic
    assert!(header.magic == MAGIC_PKT);

    header.length = reader.read_u64::<LE>()?;
    reader.read_exact(&mut header.packet_md5)?;

    reader.reset();
    reader.read_exact(&mut header.recovery_set_id)?;
    reader.read_exact(&mut header.t)?;

    Ok(Some(header))
}

#[derive(Debug, Default)]
pub struct MainPacket {
    pub size: u64,
    pub files: u32,

    pub recovery_set: Vec<[u8; 16]>, //  md5::Digest in sorted order
    pub non_recovery_set: Vec<[u8; 16]>, //  md5::Digest in sorted order
}

fn read_main_packet<R: Read>(mut reader: R, header: &Header) -> std::io::Result<MainPacket> {
    let mut pkt = MainPacket::default();

    pkt.size = reader.read_u64::<LE>()?;
    pkt.files = reader.read_u32::<LE>()?;

    // TODO Do I want to load all these, or just mmap this?
    //      There could be 2^32 files!
    pkt.recovery_set.reserve(pkt.files as usize);
    pkt.non_recovery_set.reserve(pkt.files as usize);

    let mut pos = header.length as usize - HEADER_LEN - 8 - 4;

    for _ in 0..pkt.files {
        let mut id = [0u8; 16];
        reader.read_exact(&mut id)?;
        pkt.recovery_set.push(id);

        pos -= 16;
    }


    while pos > 0 {
        let mut id = [0u8; 16];
        reader.read_exact(&mut id)?;
        pkt.non_recovery_set.push(id);

        pos -= 16;
    }

    println!("{:?}", pkt);
    Ok(pkt)
}

#[derive(Default)]
pub struct FileDescPacket {
    pub id: [u8; 16],
    pub md5: [u8; 16],
    /// md5 hash of the first 16kb
    pub md5_16k: [u8; 16],
    pub length: u64,

    /// ASCII name string (TODO see an extension for Unicode name).
    pub name: String, // TODO Change to a filename type
}

impl fmt::Debug for FileDescPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileDescPacket")
         .field("id", &md5::Digest(self.id))
         .field("name", &self.name)
         .field("md5", &md5::Digest(self.md5))
         .field("md5_16k", &md5::Digest(self.md5_16k))
         .field("length", &self.length)
         .finish()
    }
}

fn read_file_desc_packet<R: Read>(mut reader: R, header: &Header) -> std::io::Result<FileDescPacket> {
    let mut pkt = FileDescPacket::default();

    reader.read_exact(&mut pkt.id)?;
    reader.read_exact(&mut pkt.md5)?;
    reader.read_exact(&mut pkt.md5_16k)?;

    pkt.length = reader.read_u64::<LE>()?;

    let mut name = vec![0u8; header.length as usize - HEADER_LEN - FILEDESC_LEN];
    reader.read_exact(&mut name)?;
    // TODO strip trailing zeros/nulls.
    
    pkt.name = String::from_utf8(name).unwrap(); // TODO

    println!("{:?}", pkt);
    Ok(pkt)
}

#[derive(Default)]
pub struct IFSCPair {
    pub md5: [u8; 16], // TODO change to md5::Digest
    pub crc32: u32,
}

impl fmt::Debug for IFSCPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("")
         .field("md5", &md5::Digest(self.md5))
         .field("crc32", &self.crc32) // TODO as hex
         .finish()
    }
}


#[derive(Default)]
pub struct InputFileSliceChecksumPacket {
    pub id: [u8; 16],
    
    pub hashes : Vec<IFSCPair>,
}

impl fmt::Debug for InputFileSliceChecksumPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IFSCPacket")
         .field("id", &md5::Digest(self.id))
         .field("hashes", &self.hashes)
         .finish()
    }
}

fn read_ifsc_packet<R: Read>(mut reader: R, header: &Header) -> std::io::Result<InputFileSliceChecksumPacket> {
    let mut pkt = InputFileSliceChecksumPacket::default();

    reader.read_exact(&mut pkt.id)?;

    // TODO header.length as usize we should make sure it fits usize
    let mut pos = header.length as usize - HEADER_LEN - 16;
    while pos > 0 {
        let mut hashes = IFSCPair::default();

        reader.read_exact(&mut hashes.md5)?;
        hashes.crc32 = reader.read_u32::<LE>()?;

        pkt.hashes.push(hashes);

        pos -= 20;
    }

    println!("{:?}", pkt);
    Ok(pkt)
}

fn main() -> std::io::Result<()> {
    let file = File::open("testdata.par2")?;
    let reader = BufReader::new(file);
    let mut reader = Md5Reader::new(reader);

    loop {
        // TODO allow the first header to return EOF
        let header = match read_header(&mut reader)? {
            Some(header) => header,
            None => break,
        };

        let remaining = header.length as usize - HEADER_LEN;

        // Constain the reader to the specific bytes
        let reader_pkt = &mut reader
            .by_ref()
            .take(remaining.try_into().unwrap());

        // TODO implement reader.take(remaining)
        match header.t {
            TYPE_MAIN => {
                read_main_packet(reader_pkt, &header)?;
            }
            TYPE_FILEDESC => {
                read_file_desc_packet(reader_pkt, &header)?;
            }
            TYPE_IFSC => {
                read_ifsc_packet(reader_pkt, &header)?;
            }
            _ => {
                println!("Unknown {:?}", header);

                // Fully read the unknown packet (this is so we can check the md5sum)
                std::io::copy(reader_pkt, &mut std::io::sink())?;
            }
        }

        // TODO check the hash are correct.
        println!("{:?} {:?}", md5::Digest(header.packet_md5), reader.compute());
    }

    Ok(())
}
