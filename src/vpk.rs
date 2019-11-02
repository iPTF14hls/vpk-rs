use std::collections::HashMap;
use std::rc::Rc;
use crate::vpk_nom::{
    header, other_md5_section, read_directory, read_entries, sections, ExtensionLayer, Header,
};

//Everything that has been developed here was based off of documentation
//from here: https://developer.valvesoftware.com/wiki/VPK_File_Format
//most of the parsing is done in vpk_nom. 
//So if you want to change aspects of parsing go there.
//This is just the glue for vpk_nom

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
            path,
            directory,
            file_data: Rc::from(file_data.into_boxed_slice()),
            cached_data: HashMap::new(),
        }
    }
    pub fn get_archive_data(&mut self, index: u32) -> Option<Rc<[u8]>> {
        match index {
            0x7fff => Some(self.file_data.clone()),
            i => {
                if let Some(data) = self.cached_data.get(&index).cloned() {
                    data
                } else {
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
use std::io::Read;
use std::path::Path;

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

pub fn vpk_from_file(path: &Path) -> Result<IncomingVpk, ReadError> {
    use md5::compute;
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let buff = data.as_ref();
    let (buff, header) = header(buff)?;

    let (ts, fdss, ams, omss, sss) = match header {
        Header::V1(v1) => (v1.tree_size, 0, 0, 0, 0),
        Header::V2(v2) => (
            v2.tree_size,
            v2.file_data_section_size,
            v2.archive_md5_size,
            v2.other_md5_section_size,
            v2.signature_section_size,
        ),
    };

    let (_, (tree, file_data, archive_md5, other_md5, _)) =
        sections(buff, ts, fdss, ams, omss, sss)?;
    let (tree_checksum, archive_md5_checksum) = (compute(tree).0, compute(archive_md5).0);
    let (_, directory) = read_directory(tree)?;
    let mut ivpk = IncomingVpk::new(path, directory, Vec::from(file_data));
    //We check the archives to see whats up
    let (_, entries) = read_entries(archive_md5)?;
    for entry in entries {
        let data = ivpk.get_archive_data(entry.archive_index).unwrap();
        let (s, e) = (
            entry.starting_offset as usize,
            (entry.starting_offset + entry.count) as usize,
        );
        let slice = &data[s..e];
        let hash = compute(slice).0;
        if entry
            .md5_checksum
            .iter()
            .zip(hash.iter())
            .any(|(a, b)| a != b)
        {
            return Err(ReadError::DataChecksum((
                entry.archive_index,
                entry.md5_checksum,
                hash,
            )));
        }
    }

    if !other_md5.is_empty() {
        let (_, checksums) = other_md5_section(other_md5)?;
        if checksums
            .tree_checksum
            .iter()
            .zip(tree_checksum.iter())
            .any(|(a, b)| a != b)
        {
            return Err(ReadError::OtherChecksum((
                checksums.tree_checksum,
                tree_checksum,
            )));
        }
        if checksums
            .archive_md5_section_checksum
            .iter()
            .zip(archive_md5_checksum.iter())
            .any(|(a, b)| a != b)
        {
            return Err(ReadError::OtherChecksum((
                checksums.archive_md5_section_checksum,
                archive_md5_checksum,
            )));
        }
    }

    Ok(ivpk)
}
