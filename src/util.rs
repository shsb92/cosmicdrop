use std::path::Path;

/// Determine the Apple UTI type from magic bytes of a file.
/// This is a simplified version of fleep-based detection.
pub fn get_uti_type(bytes: &[u8]) -> &'static str {
    // JPEG
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "public.jpeg";
    }
    // PNG
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return "public.png";
    }
    // GIF
    if bytes.starts_with(b"GIF8") {
        return "com.compuserve.gif";
    }
    // BMP
    if bytes.starts_with(b"BM") {
        return "public.image";
    }
    // ZIP
    if bytes.starts_with(b"PK") {
        return "public.zip-archive";
    }
    // GZIP
    if bytes.starts_with(&[0x1F, 0x8B]) {
        return "org.gnu.gnu-zip-archive";
    }
    // TAR
    if bytes.starts_with(b"ustar")
        || (bytes.len() >= 262 && bytes[257..262].starts_with(b"ustar"))
    {
        return "public.data";
    }
    // PDF
    if bytes.starts_with(b"%PDF") {
        return "com.adobe.pdf";
    }
    // Default
    "public.content"
}

/// Generate a simple preview icon for image files.
/// Returns None on failure (non-image or read error).
#[allow(dead_code)]
pub fn generate_file_icon(path: &Path) -> Option<Vec<u8>> {
    let mut img = image::open(path).ok()?;
    img = img.thumbnail(540, 540);
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Jpeg)
        .ok()?;
    Some(out.into_inner())
}
