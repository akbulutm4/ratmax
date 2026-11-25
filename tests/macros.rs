use ratmax::{
    macros::{self, Document, Sequence, Step},
    model::Core,
};
use std::path::Path;
fn program(lines: &[&str]) -> Sequence {
    Sequence {
        press: lines.iter().map(|s| Step::parse(s).unwrap()).collect(),
        release: vec![],
        repeat: 1,
    }
}
#[test]
fn shortcuts_repeats_delays_and_each_event_are_validated() {
    let mut p = program(&["tap ctrl+c"]);
    p.release = vec![Step::parse("tap ctrl+v").unwrap()];
    let c = macros::compile(&p).unwrap();
    assert_eq!(
        c.words.press,
        [0x2301, 0x2106, 0x2814, 0x2006, 0x2201, 0x262f]
    );
    assert_eq!(
        c.words.release.unwrap(),
        [0x2301, 0x2119, 0x2814, 0x2019, 0x2201, 0x262f]
    );
    assert_eq!(c.internal_bytes, 36);
    assert_eq!(c.extended_pages, 0);
    assert!(c.internal_installable);
    let c = macros::compile(&program(&["delay 2000", "move -64 63"])).unwrap();
    assert_eq!(c.words.press, [0x2be7, 0x2be7, 0x2802, 0x603f, 0x262f]);
    assert_eq!(c.duration_ms, 2000);
    let mut p = program(&["tap ctrl+c"]);
    p.repeat = 3;
    let c3 = macros::compile(&p).unwrap();
    assert!(c3.compact_tail_bytes > 40);
    assert_eq!(c3.extended_pages, 1);
    assert!(c3.internal_installable);
    // Over 3,019 words (> 6,056 bytes) still compiles for preview/save, but exceeds extended internal storage.
    let mut huge = Sequence {
        press: vec![Step::parse("tap ctrl+c 1").unwrap(); 40],
        release: vec![],
        repeat: 16,
    };
    let ch = macros::compile(&huge).unwrap();
    assert!(ch.words.press.len() > 3019);
    assert!(!ch.internal_installable);
    huge.repeat = 1;
    assert!(macros::compile(&huge).unwrap().internal_installable);
    for lines in [
        &["down a"][..],
        &["up a"][..],
        &["down ctrl", "down ctrl", "up ctrl"][..],
        &["mouse-down left"][..],
        &["tap ctrl+ctrl+c"][..],
        &["tap a+b"][..],
        &["delay 0"][..],
        &["move 64 0"][..],
    ] {
        assert!(macros::compile(&program(lines)).is_err(), "{lines:?}");
    }
    let c = macros::compile(&program(&["down ctrl", "tap ctrl+c", "up ctrl"])).unwrap();
    assert_eq!(
        c.words.press,
        [0x2301, 0x2106, 0x2814, 0x2006, 0x2201, 0x262f]
    );
    assert!(macros::compile(&program(&["tap hid:0x98"])).is_err());
    assert!(macros::compile(&program(&["tap hid:0xdf"])).is_err());
    let mut p = program(&["tap a"]);
    p.repeat = 0;
    assert!(macros::compile(&p).is_err());
}
#[test]
fn files_keep_incomplete_drafts_and_preview_compiles_complete_projects() {
    let dir = std::env::temp_dir().join(format!("ratmax-editor-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("macros.json");
    let mut doc = Document::empty(Core::Four);
    doc.macros.bindings[0].program = program(&["down a"]);
    doc.save(&path).unwrap();
    let loaded = Document::load(&path).unwrap();
    assert!(macros::preview(&loaded.macros).is_err());
    doc.macros.bindings[0].program = program(&["tap ctrl+c"]);
    doc.macros.bindings[1].program = program(&["tap ctrl+v"]);
    doc.save(&path).unwrap();
    let preview = ratmax::preview::load(&path).unwrap();
    assert!(!preview.write_ready);
    let mp = preview.macros.unwrap();
    assert_eq!(mp.bindings.len(), 2);
    assert_eq!(mp.simultaneous_device_programs, 7);
    assert!(mp.combined_internal_installable);
    assert_eq!(mp.combined_extended_pages, 1);
    let example = ratmax::preview::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/button-macros.json"),
    )
    .unwrap();
    let ex_m = example.macros.unwrap();
    assert_eq!(ex_m.bindings.len(), 3);
    assert!(ex_m.combined_internal_installable);
    assert_eq!(ex_m.combined_extended_pages, 1);
    doc.macros.bindings[1].button = doc.macros.bindings[0].button;
    assert!(doc.save(&path).is_err());
    assert_eq!(Document::load(&path).unwrap().macros.bindings.len(), 7);
    std::fs::remove_dir_all(dir).unwrap();
}
