//! The retired hyphenated V3A label must not appear anywhere in this crate.

use std::path::{Path, PathBuf};

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("directory entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if name != "target" && name != ".git" && name != "vendor" {
                files_under(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}

#[test]
fn retired_v3a_label_spelling_is_absent() {
    // Built from parts so this file does not match itself.
    let retired = ["V3", "-A"].concat();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    files_under(root, &mut files);
    let hits: Vec<String> = files
        .iter()
        .filter(|p| std::fs::read(p).is_ok_and(|b| String::from_utf8_lossy(&b).contains(&retired)))
        .map(|p| p.strip_prefix(root).unwrap().display().to_string())
        .collect();
    assert!(hits.is_empty(), "retired label found in: {hits:?}");
}
