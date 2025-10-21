use crate::types::{FileType, SearchSpec, SearchType, MEGABYTE};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// TOML-friendly wrapper for search specifications
#[derive(Serialize, Deserialize)]
struct SearchSpecsConfig {
    specs: Vec<TomlSearchSpec>,
}

/// TOML-friendly search specification
#[derive(Serialize, Deserialize)]
struct TomlSearchSpec {
    file_type: String,
    suffix: String,
    max_len: usize,
    header: Vec<u8>,
    footer: Option<Vec<u8>>,
    case_sensitive: bool,
    search_type: String,
    markers: Vec<Vec<u8>>,
    comment: String,
}

impl From<SearchSpec> for TomlSearchSpec {
    fn from(spec: SearchSpec) -> Self {
        Self {
            file_type: format!("{:?}", spec.file_type),
            suffix: spec.suffix,
            max_len: spec.max_len,
            header: spec.header,
            footer: spec.footer,
            case_sensitive: spec.case_sensitive,
            search_type: format!("{:?}", spec.search_type),
            markers: spec.markers.into_iter().map(|m| m.value).collect(),
            comment: spec.comment,
        }
    }
}

impl From<TomlSearchSpec> for SearchSpec {
    fn from(toml_spec: TomlSearchSpec) -> Self {
        let file_type = match toml_spec.file_type.as_str() {
            "Jpeg" => FileType::Jpeg,
            "Gif" => FileType::Gif,
            "Bmp" => FileType::Bmp,
            "Mpg" => FileType::Mpg,
            "Pdf" => FileType::Pdf,
            "Doc" => FileType::Doc,
            "Avi" => FileType::Avi,
            "Wmv" => FileType::Wmv,
            "Htm" => FileType::Htm,
            "Zip" => FileType::Zip,
            "Mov" => FileType::Mov,
            "Xls" => FileType::Xls,
            "Ppt" => FileType::Ppt,
            "Wpd" => FileType::Wpd,
            "Cpp" => FileType::Cpp,
            "Ole" => FileType::Ole,
            "Gzip" => FileType::Gzip,
            "Riff" => FileType::Riff,
            "Wav" => FileType::Wav,
            "VJpeg" => FileType::VJpeg,
            "Sxw" => FileType::Sxw,
            "Sxc" => FileType::Sxc,
            "Sxi" => FileType::Sxi,
            "Png" => FileType::Png,
            "Rar" => FileType::Rar,
            "Exe" => FileType::Exe,
            "Elf" => FileType::Elf,
            "Reg" => FileType::Reg,
            "Docx" => FileType::Docx,
            "Xlsx" => FileType::Xlsx,
            "Pptx" => FileType::Pptx,
            "Mp4" => FileType::Mp4,
            "Config" => FileType::Config,
            _ => FileType::Config, // default fallback
        };

        let search_type = match toml_spec.search_type.as_str() {
            "Forward" => SearchType::Forward,
            "Reverse" => SearchType::Reverse,
            "ForwardNext" => SearchType::ForwardNext,
            "Ascii" => SearchType::Ascii,
            _ => SearchType::Forward, // default fallback
        };

        let mut spec = SearchSpec::new(
            file_type,
            &toml_spec.suffix,
            &toml_spec.header,
            toml_spec.footer.as_deref(),
            toml_spec.max_len,
            toml_spec.case_sensitive,
            search_type,
        );

        // Add markers
        for marker_bytes in toml_spec.markers {
            spec.add_marker(&marker_bytes);
        }

        spec.comment = toml_spec.comment;
        spec
    }
}

/// Initialize all built-in search specifications
pub fn init_all_search_specs() -> Vec<SearchSpec> {
    let mut specs = Vec::new();
    
    // JPEG files
    let jpeg = SearchSpec::new(
        FileType::Jpeg,
        "jpg",
        &[0xff, 0xd8, 0xff],
        Some(&[0xff, 0xd9]),
        20 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(jpeg);

    // GIF files
    let mut gif = SearchSpec::new(
        FileType::Gif,
        "gif",
        &[0x47, 0x49, 0x46, 0x38], // "GIF8"
        Some(&[0x00, 0x3b]),
        MEGABYTE,
        true,
        SearchType::Forward,
    );
    gif.add_marker(&[0x00, 0x00, 0x3b]);
    specs.push(gif);

    // BMP files
    let bmp = SearchSpec::new(
        FileType::Bmp,
        "bmp",
        b"BM",
        None,
        2 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(bmp);

    // PDF files
    let mut pdf = SearchSpec::new(
        FileType::Pdf,
        "pdf",
        b"%PDF-1.",
        Some(b"%%EOF"),
        40 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    pdf.add_marker(b"/L ");
    pdf.add_marker(b"obj");
    pdf.add_marker(b"/Linearized");
    pdf.add_marker(b"/Length");
    specs.push(pdf);

    // ZIP files
    let zip = SearchSpec::new(
        FileType::Zip,
        "zip",
        &[0x50, 0x4B, 0x03, 0x04],
        Some(&[0x50, 0x4b, 0x05, 0x06]),
        100 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(zip);

    // PNG files
    let png = SearchSpec::new(
        FileType::Png,
        "png",
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        Some(b"IEND"),
        MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(png);

    // MPEG files
    let mut mpg = SearchSpec::new(
        FileType::Mpg,
        "mpg",
        &[0x00, 0x00, 0x01, 0xba],
        Some(&[0x00, 0x00, 0x01, 0xb9]),
        50 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    mpg.add_marker(&[0x00, 0x00, 0x01]);
    specs.push(mpg);

    // RAR files
    let rar = SearchSpec::new(
        FileType::Rar,
        "rar",
        &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00],
        Some(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        100 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(rar);

    // EXE files
    let exe = SearchSpec::new(
        FileType::Exe,
        "exe",
        b"MZ",
        None,
        MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(exe);

    // HTML files
    let htm = SearchSpec::new(
        FileType::Htm,
        "htm",
        b"<html",
        Some(b"</html>"),
        MEGABYTE,
        false,
        SearchType::Forward,
    );
    specs.push(htm);

    // OLE/Office files
    let ole = SearchSpec::new(
        FileType::Ole,
        "ole",
        &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        None,
        10 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(ole);

    // WMV files
    let wmv = SearchSpec::new(
        FileType::Wmv,
        "wmv",
        &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11],
        Some(&[0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9]),
        40 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(wmv);

    // MOV files
    let mov = SearchSpec::new(
        FileType::Mov,
        "mov",
        b"moov",
        None,
        40 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(mov);

    // MP4 files
    let mp4 = SearchSpec::new(
        FileType::Mp4,
        "mp4",
        &[0x00, 0x00, 0x00, 0x1c, 0x66, 0x74, 0x79, 0x70],
        None,
        600 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(mp4);

    // RIFF files (AVI/WAV)
    let riff = SearchSpec::new(
        FileType::Riff,
        "rif",
        b"RIFF",
        Some(b"INFO"),
        20 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(riff);

    // C++ source files
    let mut cpp = SearchSpec::new(
        FileType::Cpp,
        "cpp",
        b"#include",
        Some(b"char"),
        MEGABYTE,
        true,
        SearchType::Forward,
    );
    cpp.add_marker(b"int");
    specs.push(cpp);

    // WordPerfect files
    let wpd = SearchSpec::new(
        FileType::Wpd,
        "wpd",
        &[0xff, 0x57, 0x50, 0x43],
        None,
        MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(wpd);

    // GZIP files
    let gzip = SearchSpec::new(
        FileType::Gzip,
        "gz",
        &[0x1F, 0x8B],
        Some(&[0x00, 0x00, 0x00, 0x00]),
        100 * MEGABYTE,
        true,
        SearchType::Forward,
    );
    specs.push(gzip);

    specs
}

/// Get search specifications for specific file types
pub fn get_search_specs_for_types(types: &[String]) -> Vec<SearchSpec> {
    let all_specs = init_all_search_specs();
    
    if types.is_empty() || types.contains(&"all".to_string()) {
        return all_specs;
    }

    let mut result = Vec::new();
    for spec in all_specs {
        // Check if the requested type matches this spec (handle both "jpg" and "jpeg")
        for requested_type in types {
            if spec.suffix == *requested_type || 
               (spec.suffix == "jpg" && *requested_type == "jpeg") ||
               (spec.suffix == "jpeg" && *requested_type == "jpg") {
                result.push(spec.clone());
                break;
            }
        }
    }
    
    result
}

/// Parse file type string and return appropriate file types
pub fn parse_file_types(type_str: &str) -> Vec<String> {
    if type_str == "all" {
        return vec!["all".to_string()];
    }
    
    type_str.split(',').map(|s| s.trim().to_string()).collect()
}

/// Save search specifications to a TOML file
pub fn save_specs_to_toml<P: AsRef<Path>>(specs: &[SearchSpec], filename: P) -> Result<()> {
    let toml_specs: Vec<TomlSearchSpec> = specs.iter().map(|s| s.clone().into()).collect();
    let config = SearchSpecsConfig { specs: toml_specs };
    
    let toml_string = toml::to_string_pretty(&config)
        .context("Failed to serialize search specs to TOML")?;
    
    std::fs::write(filename, toml_string)
        .context("Failed to write TOML file")?;
    
    Ok(())
}

/// Load search specifications from a TOML file
pub fn load_specs_from_toml<P: AsRef<Path>>(filename: P) -> Result<Vec<SearchSpec>> {
    let toml_content = std::fs::read_to_string(&filename)
        .with_context(|| format!("Failed to read TOML file: {}", filename.as_ref().display()))?;
    
    let config: SearchSpecsConfig = toml::from_str(&toml_content)
        .context("Failed to parse TOML file")?;
    
    let specs: Vec<SearchSpec> = config.specs.into_iter().map(|ts| ts.into()).collect();
    
    Ok(specs)
}

/// Combine built-in and loaded specs based on command line arguments
pub fn get_combined_search_specs(
    types: &[String],
    disable_builtin: bool,
    config_file: Option<&str>,
) -> Result<Vec<SearchSpec>> {
    let mut all_specs = Vec::new();
    
    // Add built-in specs if not disabled
    if !disable_builtin {
        if types.is_empty() || types.contains(&"all".to_string()) {
            all_specs.extend(init_all_search_specs());
        } else {
            all_specs.extend(get_search_specs_for_types(types));
        }
    }
    
    // Add specs from config file if provided
    if let Some(config_path) = config_file {
        let loaded_specs = load_specs_from_toml(config_path)
            .with_context(|| format!("Failed to load specs from config file: {}", config_path))?;
        
        // If specific types are requested, filter loaded specs too
        if !types.is_empty() && !types.contains(&"all".to_string()) {
            for spec in loaded_specs {
                for requested_type in types {
                    if spec.suffix == *requested_type || 
                       (spec.suffix == "jpg" && *requested_type == "jpeg") ||
                       (spec.suffix == "jpeg" && *requested_type == "jpg") {
                        all_specs.push(spec.clone());
                        break;
                    }
                }
            }
        } else {
            all_specs.extend(loaded_specs);
        }
    }
    
    Ok(all_specs)
}