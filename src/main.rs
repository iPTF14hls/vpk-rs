mod vpk;
mod vpk_nom;
mod bin_pack;
use std::path::Path;

use crate::vpk::vpk_from_file;
fn main() {
    let path =  "./test-samples/t0/hl2_misc_dir.vpk";
    let path = Path::new(&path);

    let vpk = vpk_from_file(path).unwrap();
    println!("{:?}", vpk.directory);
}
