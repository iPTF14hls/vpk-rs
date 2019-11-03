use nom::number::Endianness;
use nom::{
    count, do_parse, many_till, map, map_res, named, preceded, switch, take, tuple,
    u16, u32, verify, take_till, named_args, many0, complete,
};

//This is where the heart of the parser is. 
//Data flows in here, get's converted and spit back out.
//Read up the nom docs to understand what the majority of this does.
//TODO: add descriptive comments to this stuff to make it more legable.

#[derive(Debug)]
pub struct V1Header {
    pub tree_size: u32,
}

#[derive(Debug)]
pub struct V2Header {
    pub tree_size: u32,
    pub file_data_section_size: u32,
    pub archive_md5_size: u32,
    pub other_md5_section_size: u32,
    pub signature_section_size: u32,
}

#[derive(Debug)]
pub enum Header {
    V1(V1Header),
    V2(V2Header),
}

named_args!(pub sections(tree_size: u32, file_data_section_size: u32, archive_md5_size: u32, other_md5_section_size: u32, signature_section_size: u32)<(&[u8], &[u8], &[u8], &[u8], &[u8])>,
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
pub struct VpkArchiveMd5Section {
    pub archive_index: u32,
    pub starting_offset: u32,
    pub count: u32,
    pub md5_checksum: [u8; 16],
}

named!(
    pub read_entries<Vec<VpkArchiveMd5Section>>,
    many0!(complete!(archive_md5))
);

named!(archive_md5<VpkArchiveMd5Section>, map!(tuple!(u32!(Endianness::Little), u32!(Endianness::Little), u32!(Endianness::Little), fixed_arr_16), 
    |(archive_index, starting_offset, count, md5_checksum):(u32, u32, u32, [u8; 16])|{
        VpkArchiveMd5Section{
            archive_index, starting_offset, count, md5_checksum,
        }
    })
);

#[derive(Debug)]
pub struct VpkOtherMd5Section {
    pub tree_checksum: [u8; 16],
    pub archive_md5_section_checksum: [u8; 16],
    pub _unknown: [u8; 16], //It's not known what this represents yet
}

named!(pub other_md5_section<VpkOtherMd5Section>, map!(tuple!(fixed_arr_16, fixed_arr_16, fixed_arr_16),
    |(tree_checksum, archive_md5_section_checksum, _unknown)|{
        VpkOtherMd5Section{
            tree_checksum, archive_md5_section_checksum, _unknown
        }
    }));

#[derive(Debug)]
pub struct VpkSignatureSection<'a> {
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
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
        crc: u32!(Endianness::Little) >> 
        preload_bytes: u16!(Endianness::Little) >> 
        archive_index: u16!(Endianness::Little) >> 
        entry_offset: u32!(Endianness::Little) >> 
        entry_length: u32!(Endianness::Little) >> 
        _terminator: terminator >> 
        pre_loaded: take!(preload_bytes) >> 
        ((crc, archive_index, entry_offset, entry_length, pre_loaded))
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
