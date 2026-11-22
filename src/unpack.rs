//! gzip and zip, with every read capped. A report attachment is either the
//! file itself, a gzip of it, or a zip holding exactly one file; which one is
//! decided by the leading bytes, not by the content type the sender chose.

use std::fmt;
use std::io::{Cursor, Read};

use flate2::read::MultiGzDecoder;

/// Why an attachment couldn't be unpacked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnpackError {
    /// The output would pass the cap.
    TooLarge,
    /// A zip holding some number of entries other than one.
    ZipEntries(usize),
    /// The one zip entry is a directory or a link.
    NotAFile,
    /// The gzip or zip stream doesn't decode.
    Corrupt(String),
}

impl fmt::Display for UnpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnpackError::TooLarge => f.write_str("attachment unpacks past the size limit"),
            UnpackError::ZipEntries(n) => write!(f, "zip must hold exactly one file, this one holds {n}"),
            UnpackError::NotAFile => f.write_str("zip entry is not a file"),
            UnpackError::Corrupt(why) => write!(f, "attachment is damaged: {why}"),
        }
    }
}

impl std::error::Error for UnpackError {}

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

/// Unpacks `data` if it's a gzip or a zip, and returns it as it is
/// otherwise. Nothing returned is larger than `cap` bytes.
pub fn unpack(data: &[u8], cap: u64) -> Result<Vec<u8>, UnpackError> {
    if data.starts_with(GZIP_MAGIC) {
        gunzip(data, cap)
    } else if data.starts_with(ZIP_MAGIC) {
        unzip(data, cap)
    } else if data.len() as u64 > cap {
        Err(UnpackError::TooLarge)
    } else {
        Ok(data.to_vec())
    }
}

/// Reads at most `cap + 1` bytes through `reader`, so an output of exactly
/// `cap` bytes is accepted and one byte more is refused without reading on.
fn read_capped(reader: impl Read, cap: u64) -> Result<Vec<u8>, UnpackError> {
    let mut out = Vec::new();
    reader.take(cap.saturating_add(1)).read_to_end(&mut out).map_err(|e| UnpackError::Corrupt(e.to_string()))?;
    if out.len() as u64 > cap {
        return Err(UnpackError::TooLarge);
    }
    Ok(out)
}

/// Every member of a gzip stream, concatenated, up to `cap` bytes.
pub fn gunzip(data: &[u8], cap: u64) -> Result<Vec<u8>, UnpackError> {
    read_capped(MultiGzDecoder::new(data), cap)
}

/// Exactly one entry, and it must be a file. Its declared size is checked
/// first, and the read is capped anyway, since the declared size is the
/// sender's word.
pub fn unzip(data: &[u8], cap: u64) -> Result<Vec<u8>, UnpackError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).map_err(|e| UnpackError::Corrupt(e.to_string()))?;
    if archive.len() != 1 {
        return Err(UnpackError::ZipEntries(archive.len()));
    }
    let file = archive.by_index(0).map_err(|e| UnpackError::Corrupt(e.to_string()))?;
    if !file.is_file() {
        return Err(UnpackError::NotAFile);
    }
    if file.size() > cap {
        return Err(UnpackError::TooLarge);
    }
    read_capped(file, cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn plain_data_passes_through() {
        assert_eq!(unpack(b"<feedback/>", 100).unwrap(), b"<feedback/>");
        assert_eq!(unpack(b"0123456789", 9), Err(UnpackError::TooLarge));
    }

    #[test]
    fn gzip_unpacks_up_to_the_cap() {
        let data = vec![b'a'; 1000];
        assert_eq!(unpack(&gzip(&data), 1000).unwrap(), data);
        assert_eq!(unpack(&gzip(&data), 999), Err(UnpackError::TooLarge));
    }

    #[test]
    fn gzip_bomb_is_refused() {
        // 64 MiB of zeros compresses to about 64 KiB.
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..64 {
            enc.write_all(&chunk).unwrap();
        }
        let bomb = enc.finish().unwrap();
        assert!(bomb.len() < 1024 * 1024);
        assert_eq!(unpack(&bomb, crate::Limits::DEFAULT.max_unpacked_bytes), Err(UnpackError::TooLarge));
    }

    #[test]
    fn zip_with_one_file_unpacks() {
        let z = zip_of(&[("google.com!example.com!1!2.xml", b"<feedback/>")]);
        assert_eq!(unpack(&z, 100).unwrap(), b"<feedback/>");
    }

    #[test]
    fn zip_with_two_entries_is_refused() {
        let z = zip_of(&[("a.xml", b"<feedback/>"), ("b.xml", b"<feedback/>")]);
        assert_eq!(unpack(&z, 100), Err(UnpackError::ZipEntries(2)));
    }

    #[test]
    fn zip_bomb_is_refused() {
        let big = vec![0u8; 40 * 1024 * 1024];
        let z = zip_of(&[("report.xml", &big)]);
        assert!(z.len() < 1024 * 1024);
        assert_eq!(unpack(&z, crate::Limits::DEFAULT.max_unpacked_bytes), Err(UnpackError::TooLarge));
    }

    #[test]
    fn zip_that_lies_about_its_size_is_still_capped() {
        // Rewrite the declared uncompressed size to 10 bytes in both the
        // local header and the central directory; the read cap must still
        // stop at the real size.
        let big = vec![b'x'; 4096];
        let mut z = zip_of(&[("report.xml", &big)]);
        let real = (big.len() as u32).to_le_bytes();
        let fake = 10u32.to_le_bytes();
        let mut i = 0;
        while i + 4 <= z.len() {
            if z[i..i + 4] == real {
                z[i..i + 4].copy_from_slice(&fake);
            }
            i += 1;
        }
        match unpack(&z, 100) {
            Err(UnpackError::TooLarge) | Err(UnpackError::Corrupt(_)) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn damaged_gzip_is_corrupt() {
        assert!(matches!(unpack(&[0x1f, 0x8b, 0, 0, 0], 100), Err(UnpackError::Corrupt(_))));
    }
}
