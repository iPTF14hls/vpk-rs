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
    archive_md5: Box<[u8]>, 
    other_md5: Box<[u8]>, 
    tree_checksum: [u8; 16], 
    archive_md5_checksum: [u8; 16],
}
#[derive(Debug)]
struct HashCompair {
    expect: [u8; 16],
    got: [u8; 16],
}
#[derive(Debug)]
pub enum IntegrityError {
    Nom,
    Mismatch(Vec<HashMismatch>),
}
#[derive(Debug)]
pub enum HashMismatch {
    Data((u32, HashCompair)), 
    Other(HashCompair),
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for IntegrityError {
    fn from(_: nom::Err<(&[u8], nom::error::ErrorKind)>) -> IntegrityError {
        IntegrityError::Nom
    }
}

impl<'a> IncomingVpk<'a> {
    pub fn new(path: &'a Path, directory: ExtensionLayer, file_data: Vec<u8>, archive_md5: Box<[u8]>, other_md5: Box<[u8]>, tree_checksum: [u8; 16], archive_md5_checksum: [u8; 16]) -> Self {
        IncomingVpk {
            path,
            directory,
            file_data: Rc::from(file_data.into_boxed_slice()),
            cached_data: HashMap::new(),
            archive_md5, other_md5, tree_checksum, archive_md5_checksum,
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
                    let filename = self.path.file_stem().unwrap().to_str().unwrap();
                    let dir = self.path.parent().unwrap();
                    let name = filename.replace("_dir", "");
                    let new_name = format!("{}_{:03}.vpk", name, i);
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

    pub fn integrity_check(&mut self) -> Result<(), IntegrityError> {
        use md5::compute;
        //We check the archives to see whats up
        let (_, entries) = {
            let archive_md5 = &self.archive_md5[..];
            read_entries(archive_md5)?
        };

        //We want to know EVERY failure that happens in here.
        let mut failures = Vec::new();

        for entry in entries {
            let data = self.get_archive_data(entry.archive_index).unwrap();
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
                failures.push(HashMismatch::Data((
                    entry.archive_index,
                    HashCompair {
                        expect: entry.md5_checksum,
                        got: hash,
                    }
                )));
            }
        }

        let (other_md5, tree_checksum, archive_md5_checksum) = (&self.other_md5[..], self.tree_checksum, self.archive_md5_checksum);
        
        if !other_md5.is_empty() {
            let (_, checksums) = other_md5_section(other_md5)?;
            if checksums
                .tree_checksum
                .iter()
                .zip(tree_checksum.iter())
                .any(|(a, b)| a != b)
            {
                failures.push(HashMismatch::Other(HashCompair {
                    expect: checksums.tree_checksum,
                    got: tree_checksum
                }
                ));
            }
            if checksums
                .archive_md5_section_checksum
                .iter()
                .zip(archive_md5_checksum.iter())
                .any(|(a, b)| a != b)
            {
                failures.push(HashMismatch::Other(HashCompair {
                    expect: checksums.archive_md5_section_checksum,
                    got: archive_md5_checksum,
                }));
            }
        }

        if failures.is_empty() {
            Ok(())
        }
        else {
            Err(IntegrityError::Mismatch(failures))
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
    let ivpk = IncomingVpk::new(path, directory, Vec::from(file_data), Box::from(archive_md5), Box::from(other_md5), tree_checksum, archive_md5_checksum);

    Ok(ivpk)
}
