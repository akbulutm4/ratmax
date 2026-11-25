//! Embedded allowlist of stock W95 Max v0034 firmware hashes. No firmware image is bundled.

const W95MAX_MANIFEST_JSON: &str = r#"{
  "schema_version": 1,
  "model_id": 1400,
  "source_checkpoint": "clean-room W95 Max v0034 asset digest allowlist",
  "scope": "User-supplied stock W95 Max v0034 images and reconstructed local record buffers.",
  "images": [
    {
      "core": 1,
      "firmware_index": 1,
      "source": "FW/USB_M0/W95Max_P3332A_578_1_34.hexEncode",
      "source_bytes": 60912,
      "record_count": 1692,
      "source_sha256": "49e9697b2472736e397a5da340a15df231c66155fe0f7a4013fd6b1604765b25",
      "scratch_buffer_sha256": "1059e727f4eedef5a32397b8e7c1f7064056573d0e78f2a029e9967beed82032"
    },
    {
      "core": 2,
      "firmware_index": 2,
      "source": "FW/USB_M0/W95Max_P3332A_578_2_34.hexEncode",
      "source_bytes": 60912,
      "record_count": 1692,
      "source_sha256": "67b6817555b5696b06add216c27d9eec8f17a653d48e2a18375cdef5fb241b21",
      "scratch_buffer_sha256": "f5630fb1ccee3c513f1dc1373f8c5cc0a67bf04141c6463068ca2eb7ed9bceac"
    },
    {
      "core": 3,
      "firmware_index": 3,
      "source": "FW/USB_M0/W95Max_P3332A_578_3_34.hexEncode",
      "source_bytes": 60912,
      "record_count": 1692,
      "source_sha256": "6276e51d3fa0ab93af385cde5145ed590df601b39793767fbeab160258ee93a2",
      "scratch_buffer_sha256": "9f07b61d46057a027bc215af48c9247d0605cadf020c1f2916a1e49e1da3835f"
    },
    {
      "core": 4,
      "firmware_index": 0,
      "source": "FW/USB_M0/W95Max_P3332A_578_0_34.hexEncode",
      "source_bytes": 60912,
      "record_count": 1692,
      "source_sha256": "397bb9e997d73938a6416679cd8743f07a0bdfc9a580eabb2ecfd05dbe482827",
      "scratch_buffer_sha256": "8de6a8a1c6eccb70d7614a6126450f88a3d6276fb2b01039c14d3a3b21852593"
    }
  ]
}"#;

use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    firmware::{
        self, EncodedRange, IMAGE_LEN, LOCAL_BUFFER_LEN, LOCAL_STREAM_LEN, RECORD_COUNT,
        W95MAX_RANGES, W95MaxRecords,
    },
    model::{Core, FirmwareIndex, Model},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestData {
    schema_version: u32,
    model_id: Model,
    source_checkpoint: String,
    scope: String,
    images: Vec<Asset>,
}

/// Only the validated, embedded manifest can construct this allowlist.
#[derive(Debug)]
pub struct Manifest(ManifestData);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    core: Core,
    firmware_index: u8,
    source: String,
    source_bytes: usize,
    record_count: usize,
    source_sha256: String,
    scratch_buffer_sha256: String,
}

impl Manifest {
    pub fn embedded() -> Result<Self, Error> {
        let manifest = Self(
            serde_json::from_str(W95MAX_MANIFEST_JSON)
                .map_err(|error| Error::Manifest(error.to_string()))?,
        );
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.0.schema_version != 1 || self.0.images.len() != Core::ALL.len() {
            return Err(Error::Manifest(
                "expected schema 1 and exactly four images".into(),
            ));
        }
        for core in Core::ALL {
            let matching: Vec<_> = self
                .0
                .images
                .iter()
                .filter(|asset| asset.core == core)
                .collect();
            let [asset] = matching.as_slice() else {
                return Err(Error::Manifest(format!(
                    "expected exactly one image for {core}"
                )));
            };
            let index = core.firmware_index().get();
            let expected_source = format!("FW/USB_M0/W95Max_P3332A_578_{index}_34.hexEncode");
            if asset.firmware_index != index
                || asset.source != expected_source
                || asset.source_bytes != IMAGE_LEN
                || asset.record_count != RECORD_COUNT
                || !is_sha256(&asset.source_sha256)
                || !is_sha256(&asset.scratch_buffer_sha256)
            {
                return Err(Error::Manifest(format!("inconsistent metadata for {core}")));
            }
        }
        Ok(())
    }

    pub fn model(&self) -> Model {
        self.0.model_id
    }

    pub fn provenance(&self) -> &str {
        &self.0.source_checkpoint
    }

    pub fn scope(&self) -> &str {
        &self.0.scope
    }

    pub fn assets(&self) -> &[Asset] {
        &self.0.images
    }

    pub fn asset(&self, core: Core) -> &Asset {
        self.0
            .images
            .iter()
            .find(|asset| asset.core == core)
            .expect("validated four-core manifest")
    }

    pub fn inspect_bytes(&self, core: Core, bytes: &[u8]) -> Result<ValidatedImage, Error> {
        let asset = self.asset(core);
        let records = W95MaxRecords::parse(bytes)?;
        let source_sha256 = firmware::sha256(bytes);
        check_hash("source image", &asset.source_sha256, &source_sha256)?;
        let scratch_buffer_sha256 = records.local_buffer_sha256();
        check_hash(
            "local record-buffer stream",
            &asset.scratch_buffer_sha256,
            &scratch_buffer_sha256,
        )?;
        Ok(ValidatedImage {
            inspection: Inspection {
                model_id: self.0.model_id,
                core,
                firmware_index: core.firmware_index(),
                source: asset.source.clone(),
                source_bytes: bytes.len(),
                source_sha256,
                record_count: records.records().len(),
                scratch_buffer_bytes: LOCAL_STREAM_LEN,
                scratch_buffer_sha256,
                encoded_address_ranges: W95MAX_RANGES,
                local_buffer_length: LOCAL_BUFFER_LEN,
                device_feature_report_length: None,
            },
            records,
        })
    }

    pub fn inspect_file(&self, root: &Path, core: Core) -> Result<ValidatedImage, Error> {
        let path = root.join(self.asset(core).source());
        let bytes = read_regular_image(&path)?;
        self.inspect_bytes(core, &bytes)
    }
}

impl Asset {
    pub fn core(&self) -> Core {
        self.core
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

#[derive(Debug)]
pub struct ValidatedImage {
    inspection: Inspection,
    records: W95MaxRecords,
}

impl ValidatedImage {
    pub fn inspection(&self) -> &Inspection {
        &self.inspection
    }

    pub fn records(&self) -> &W95MaxRecords {
        &self.records
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub model_id: Model,
    pub core: Core,
    pub firmware_index: FirmwareIndex,
    pub source: String,
    pub source_bytes: usize,
    pub source_sha256: String,
    pub record_count: usize,
    pub scratch_buffer_bytes: usize,
    pub scratch_buffer_sha256: String,
    pub encoded_address_ranges: [EncodedRange; 2],
    pub local_buffer_length: usize,
    /// Deliberately null in offline output; 64 is not a measured device capability.
    pub device_feature_report_length: Option<usize>,
}

fn check_hash(context: &'static str, expected: &str, actual: &str) -> Result<(), Error> {
    if actual != expected {
        return Err(Error::Hash {
            context,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Only reads the fixed, known-size local image file. A bounded read also catches
/// growth/shrinkage between metadata and read without allocating an arbitrary size.
fn read_regular_image(path: &Path) -> Result<Vec<u8>, Error> {
    let io_error = |source| Error::File {
        path: path.to_owned(),
        source,
    };
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() {
        return Err(Error::NotRegularFile(path.to_owned()));
    }
    if metadata.len() != IMAGE_LEN as u64 {
        return Err(Error::Length {
            context: "local image file",
            expected: IMAGE_LEN,
            actual: metadata.len(),
        });
    }
    let mut bytes = Vec::with_capacity(IMAGE_LEN + 1);
    File::open(path)
        .map_err(io_error)?
        .take((IMAGE_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() != IMAGE_LEN {
        return Err(Error::Length {
            context: "local image file",
            expected: IMAGE_LEN,
            actual: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

/// Resolve only the two documented workspace locations. Installed binaries can
/// use --assets explicitly; no build-machine absolute path is baked in.
pub fn default_asset_root() -> Option<PathBuf> {
    [
        PathBuf::from("setup-analysis"),
        PathBuf::from("../setup-analysis"),
    ]
    .into_iter()
    .map(|path| path.join("extracted/program files/BloodyWorkShop8"))
    .find(|path| path.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_rejects_wrong_model_duplicate_core_and_path_substitution() {
        let original = W95MAX_MANIFEST_JSON;
        assert!(serde_json::from_str::<ManifestData>(&original.replace("1400", "1404")).is_err());
        for changed in [
            original.replacen("\"core\": 2", "\"core\": 1", 1),
            original.replacen("FW/USB_M0/", "../USB_M0/", 1),
            original.replacen("\"firmware_index\": 0", "\"firmware_index\": 4", 1),
        ] {
            assert!(
                Manifest(serde_json::from_str::<ManifestData>(&changed).unwrap())
                    .validate()
                    .is_err()
            );
        }
    }
}
