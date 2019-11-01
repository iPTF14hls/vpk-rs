mod vpk;
mod bin_pack;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::vpk::vpk_from_file;
fn main() {
    let path =  "./test-samples/t0/hl2_misc_dir.vpk";
    let path = Path::new(&path);

    let vpk = vpk_from_file(path).unwrap();
    println!("{:?}", vpk.directory);
}
