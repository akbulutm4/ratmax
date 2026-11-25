use ratmax::{
    model::Core,
    preview, profile,
    program::{self, Program},
    settings,
};
use std::path::Path;

fn project(name: &str) -> preview::Preview {
    preview::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(name),
    )
    .unwrap()
}

#[test]
fn named_programs_and_core_gating_rules_compile_cleanly() {
    use Program::*;
    for program in [
        DoubleClick,
        TripleClick,
        TripleFire,
        GunaDoubleHit,
        GunaTripleHit,
        GunaFourHit,
        PrecisionHold,
    ] {
        let compiled = program::compile(program, Core::Three).unwrap();
        assert!(!compiled.press.is_empty());
    }
    assert!(program::compile(GunaDoubleHit, Core::One).is_err());
    assert!(program::compile(GunaDoubleHit, Core::Four).is_err());
    assert!(program::compile(PrecisionHold, Core::Four).is_err());
    let selector_words: Vec<_> = (1..=7)
        .map(|slot| {
            program::compile(ShootSelect(slot), Core::Three)
                .unwrap()
                .press[0]
        })
        .collect();
    assert_eq!(
        selector_words,
        [0x2610, 0x2611, 0x2612, 0x2613, 0x2614, 0x2615, 0x2616]
    );
    assert!(program::compile(ShootSelect(8), Core::Three).is_err());
    for core in Core::ALL {
        assert_eq!(
            program::compile(Program::ShootSelect(2), core).is_ok(),
            matches!(core, Core::Two | Core::Three)
        );
    }
}

#[test]
fn custom_guna_and_isolated_program_examples_preview_without_hardware() {
    let report = project("core3-custom-shooting.json");
    assert!(!report.write_ready);
    assert_eq!(report.custom_shooting.unwrap().words.press.len(), 21);

    let report = project("r4-programs.json");
    assert!(!report.write_ready);
    let profile = report.programs.unwrap();
    let references: Vec<_> = profile
        .placements
        .iter()
        .map(|p| p.main_press_word)
        .collect();
    assert_eq!(references, [0xB000, 0xB001, 0xB002, 0xB000, 0x2628, 0x2611]);
    assert_eq!(profile.placements[2].nor_byte_address, Some(0x40044));
    assert_eq!(profile.placements[4].main_release_word, Some(0x2629));
    assert_eq!(
        profile.nor_checksum_contribution,
        profile::Checksums {
            sum: 0xFCE1,
            weighted: 0x5056
        }
    );
    assert_eq!(
        profile::checksums(&[0xA4A4, 0xA4A4, 0xFFFF, 0xFFFF, 3, 5], &[7, 11], &[13, 17]),
        profile::Checksums {
            sum: 56,
            weighted: 65
        }
    );
}

#[test]
fn cpi_asymmetric_cpi_and_report_rate_encodings_are_validated() {
    assert_eq!(settings::encode_cpi(1000).unwrap(), [0x40, 0x40, 0x16]);
    assert_eq!(settings::encode_cpi(1600).unwrap(), [0x40, 0x40, 0x23]);
    assert_eq!(settings::encode_cpi(2000).unwrap(), [0x40, 0x40, 0x2C]);
    assert!(settings::encode_cpi(12000).is_ok());
    assert!(settings::encode_cpi_xy(1600, 800).is_ok());
    assert_eq!(settings::encode_report_rate(2000).unwrap(), 0x11);
    assert!(settings::encode_cpi(0).is_err());
    assert!(settings::encode_cpi(12001).is_err());
    assert!(settings::encode_report_rate(333).is_err());
}
