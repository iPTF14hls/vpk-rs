use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;
use nom::number::Endianness;
use nom::{
    count, do_parse, many_till, map, map_res, named, preceded, switch, take, tuple,
    u16, u32, verify, take_till, named_args, many0, complete,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;
    use crate::vpk::header;
    //Defines path to test file.
    const TEST_SAMPLES: &[&str] = &[
        "./test-samples/t0/hl2_misc_dir.vpk",
        "./test-samples/t1/hl2_pak_dir.vpk",
        "./test-samples/t2/hl2_sound_misc_dir.vpk",
        "./test-samples/t3/hl2_sound_vo_english_dir.vpk",
        "./test-samples/t4/hl2_textures_dir.vpk",
        "./test-samples/t5/tf2_textures_dir.vpk",
        "./test-samples/t6/pak01_dir.vpk",
        "./test-samples/t7/portal_pak_dir.vpk",
        "./test-samples/t8/pak01_dir.vpk",
        "./test-samples/t9/tf2_misc_dir.vpk",
        "./test-samples/t10/tf2_sound_misc_dir.vpk",
        "./test-samples/t11/tf2_sound_vo_english_dir.vpk",
    ];

    #[test]
    fn testing_header_parsing() {
        let cannonical = TEST_SAMPLES
            .iter()
            .map(PathBuf::from)
            .map(|path| fs::canonicalize(path).unwrap());

        for path in cannonical {
            println!("{:?}", path);
            let mut data = fs::File::open(path).unwrap();
            let mut buffer = Vec::<u8>::new();
            let _ = data.read_to_end(&mut buffer).unwrap();

            let (_, header) = header(&buffer).unwrap();
            println!("{:?}", header);
        }
    }
}

#[derive(Debug)]
pub struct V1Header {
    tree_size: u32,
}

#[derive(Debug)]
pub struct V2Header {
    tree_size: u32,
    file_data_section_size: u32,
    archive_md5_size: u32,
    other_md5_section_size: u32,
    signature_section_size: u32,
}

#[derive(Debug)]
pub enum Header {
    V1(V1Header),
    V2(V2Header),
}

named_args!(sections(tree_size: u32, file_data_section_size: u32, archive_md5_size: u32, other_md5_section_size: u32, signature_section_size: u32)<(&[u8], &[u8], &[u8], &[u8], &[u8])>,
    tuple!(take!(tree_size), take!(file_data_section_size), take!(archive_md5_size), take!(other_md5_section_size), take!(signature_section_size))
);

#[derive(Debug)]
pub struct VpkDirectoryEntry {
    crc: u32,
    archive_index: u16,
    entry_offset: u32,
    entry_length: u32,
    pre_loaded: Vec<u8>,
}

named!(fixed_arr_16<[u8; 16]>, map!(take!(16), |buff: &[u8]|{
    let mut data = [0; 16];
    data.copy_from_slice(buff);
    data
}));

#[derive(Debug)]
struct VpkArchiveMd5Section {
    archive_index: u32,
    starting_offset: u32,
    count: u32,
    md5_checksum: [u8; 16],
}

named!(archive_md5<VpkArchiveMd5Section>, map!(tuple!(u32!(Endianness::Little), u32!(Endianness::Little), u32!(Endianness::Little), fixed_arr_16), 
    |(archive_index, starting_offset, count, md5_checksum):(u32, u32, u32, [u8; 16])|{
        VpkArchiveMd5Section{
            archive_index, starting_offset, count, md5_checksum,
        }
    })
);

#[derive(Debug)]
struct VpkOtherMd5Section {
    tree_checksum: [u8; 16],
    archive_md5_section_checksum: [u8; 16],
    _unknown: [u8; 16], //It's not known what this represents yet
}

named!(other_md5_section<VpkOtherMd5Section>, map!(tuple!(fixed_arr_16, fixed_arr_16, fixed_arr_16),
    |(tree_checksum, archive_md5_section_checksum, _unknown)|{
        VpkOtherMd5Section{
            tree_checksum, archive_md5_section_checksum, _unknown
        }
    }));

#[derive(Debug)]
struct VpkSignatureSection<'a> {
    public_key: &'a [u8],
    signature: &'a [u8],
}

named!(signature_section<VpkSignatureSection>, do_parse!(
    public_key_size: u32!(Endianness::Little) >>
    public_key: take!(public_key_size) >> 
    signature_size: u32!(Endianness::Little) >>
    signature: take!(signature_size) >> 
    (VpkSignatureSection{public_key, signature})
));


//The integers are in little edian order so
named!(
    check_signature<u32>,
    verify!(u32!(Endianness::Little), |val: &u32| *val == 0x55aa_1234)
);
named!(version<u32>, u32!(Endianness::Little));
named!(v1_header<u32>, u32!(Endianness::Little));
//We know the length of the header, so we just make it into a tuple for easy access later.
named!(v2_header<Vec<u32>>, count!(u32!(Endianness::Little), 5));

named!(
    pub header<Header>,
    preceded!(
        check_signature,
        switch!(version,
            1 => map!(v1_header, |tree_size: u32| Header::V1(V1Header{tree_size}))|
            2 => map!(v2_header, |vals: Vec<u32>| Header::V2(V2Header{tree_size: vals[0], file_data_section_size: vals[1], archive_md5_size: vals[2], other_md5_section_size: vals[3], signature_section_size: vals[4]}))
        )
    )
);

named!(
    pub cstring<String>,
    map_res!(do_parse!(
        bytes: take_till!(|c: u8|c==0) >> 
        _null: take!(1) >> 
        (bytes)
    ), |bytes: &[u8]| String::from_utf8(Vec::from(bytes)))
);

named!(
    empty_string<String>,
    verify!(cstring, |s: &String| s.is_empty())
);

named!(
    terminator<u16>,
    verify!(u16!(Endianness::Little), |val: &u16| *val == 0xffff)
);
named!(
    dir_data<(u32, u16, u32, u32, &[u8])>,
    do_parse!(
        crc: u32!(Endianness::Little)
            >> preload_bytes: u16!(Endianness::Little)
            >> archive_index: u16!(Endianness::Little)
            >> entry_offset: u32!(Endianness::Little)
            >> entry_length: u32!(Endianness::Little)
            >> _terminator: terminator
            >> pre_loaded: take!(preload_bytes)
            >> ((crc, archive_index, entry_offset, entry_length, pre_loaded))
    )
);

named!(
    directory_entry<VpkDirectoryEntry>,
    map!(dir_data, |(
        crc,
        archive_index,
        entry_offset,
        entry_length,
        pre_loaded,
    )| VpkDirectoryEntry {
        crc,
        archive_index,
        entry_offset,
        entry_length,
        pre_loaded: Vec::from(pre_loaded),
    })
);

pub type FileLayer = Vec<(String, VpkDirectoryEntry)>;
pub type PathLayer = Vec<(String, FileLayer)>;
pub type ExtensionLayer = Vec<(String, PathLayer)>; 

named!(
    read_file<FileLayer>,
    map!(
        many_till!(tuple!(cstring, directory_entry), empty_string),
        |(dir_entry, _)| dir_entry
    )
);

named!(
    read_path<PathLayer>, 
    map!(
        many_till!(tuple!(cstring, read_file), empty_string),
        |(path_entry, _)| path_entry
    )
);

named!(
    pub read_directory<ExtensionLayer>, 
    map!(
        many_till!(tuple!(cstring, read_path), empty_string),
        |(ext_entry, _)| ext_entry
    )
);

#[derive(Debug)]
pub enum ReadError {
    Io(std::io::Error),
    Nom,
    DataChecksum((u32, [u8; 16], [u8; 16])),
    OtherChecksum(([u8; 16], [u8; 16])),
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> Self {
        ReadError::Io(err)
    }
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for ReadError {
    fn from(_: nom::Err<(&[u8], nom::error::ErrorKind)>) -> ReadError {
        ReadError::Nom
    }
}

pub struct IncomingVpk<'a> {
    path: &'a Path,
    pub directory: ExtensionLayer,
    file_data: Rc<[u8]>,
    cached_data: HashMap<u32, Option<Rc<[u8]>>>,
}

impl<'a> IncomingVpk<'a> {
    pub fn new(path: &'a Path, directory: ExtensionLayer, file_data: Vec<u8>) -> Self {
        IncomingVpk {
            path, directory, file_data: Rc::from(file_data.into_boxed_slice()), cached_data: HashMap::new(),
        }
    }
    
    pub fn archive_data(&mut self, index: u32) -> Option<Rc<[u8]>> {
        match index {
            0x7fff => {
                Some(self.file_data.clone())
            }
            i => {
                let data = {
                    match self.cached_data.get(&index) {
                        Some(data) => Some(data.clone()),
                        None => None
                    }
                };
                if let Some(data) = data {
                    if let Some(reference) = data {
                        Some(reference)
                    } else {
                        None
                    }
                }
                else {
                    //First we need to get the file we're looking for.
                    use regex::Regex;
                    let re = Regex::new(r"(.+)_dir\.vpk").unwrap();
                    
                    let filename = self.path.file_name().unwrap().to_str().unwrap();
                    let dir = self.path.parent().unwrap();
                    let beginning = re.captures_iter(filename).next().unwrap();
                    let new_name = format!("{}_{:03}.vpk", &beginning[1], i);
                    let new_file = dir.join(new_name.as_str());
                    //Now we have that file, we can get the data from within it.
                    let buffer: Option<Rc<[u8]>> = if let Ok(mut file) = File::open(new_file) {
                        let mut buffer = Vec::<u8>::new();
                        let _ = file.read_to_end(&mut buffer); 
                        Some(Rc::from(buffer.into_boxed_slice()))
                    } else {
                        None
                    };

                    self.cached_data.insert(i, buffer.clone());
                    buffer
                }
            }
        }
    }
}

use std::fs::File;
use std::path::Path;
use std::io::Read;

/*
#[derive(Debug)]
pub struct V2Header {
    tree_size: u32,
    file_data_section_size: u32,
    archive_md5_size: u32,
    other_md5_section_size: u32,
    signature_section_size: u32,
}
 */

named!(read_entries<Vec<VpkArchiveMd5Section>>, many0!(complete!(archive_md5)));


pub fn vpk_from_file(path: &Path) -> Result<IncomingVpk, ReadError> {
    use md5::compute;
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let buff = data.as_ref();
    let (buff, header) = header(buff)?;
    

    let (ts, fdss, ams, omss, sss) = match header {
        Header::V1(v1) => {
            (v1.tree_size, 0, 0, 0, 0)
        }
        Header::V2(v2) => {
            (v2.tree_size, v2.file_data_section_size, v2.archive_md5_size, v2.other_md5_section_size, v2.signature_section_size)
        }
    };

    let (_, (tree, file_data, archive_md5, other_md5, _)) = sections(buff, ts, fdss, ams, omss, sss)?;
    let (tree_checksum, archive_md5_checksum) = (compute(tree).0, compute(archive_md5).0);
    println!("Parsing Directory");
    let (_, directory) = read_directory(tree)?;
    let mut ivpk = IncomingVpk::new(path, directory, Vec::from(file_data));
    
    println!("Reading entries");
    //We check the archives to see whats up
    let (_, entries) = read_entries(archive_md5)?;
    for entry in entries {
        println!("Processing {:?}", entry);
        let data = ivpk.archive_data(entry.archive_index).unwrap();
        let (s, e) = (entry.starting_offset as usize, (entry.starting_offset + entry.count) as usize);
        let slice = &data[s..e];
        let hash = compute(slice).0;
        if entry.md5_checksum.iter().zip(hash.iter()).any(|(a, b)|a!=b) {
            return Err(ReadError::DataChecksum((entry.archive_index, entry.md5_checksum, hash)));
        }
    }

    if !other_md5.is_empty() {
        println!("Parsing other md5 sections.");
        let (_, checksums) = other_md5_section(other_md5)?;
        if checksums.tree_checksum.iter().zip(tree_checksum.iter()).any(|(a, b)|a!=b) {
            return Err(ReadError::OtherChecksum((checksums.tree_checksum, tree_checksum)));
        }
        if checksums.archive_md5_section_checksum.iter().zip(archive_md5_checksum.iter()).any(|(a, b)|a!=b) {
            return Err(ReadError::OtherChecksum((checksums.archive_md5_section_checksum, archive_md5_checksum)));
        }
    }

    println!("Done");
    Ok(ivpk)
}
