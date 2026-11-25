//! Bounded offline lowering of the traced Core-3 GunA branch (0062B8B1).
//! This produces isolated instructions, never an installable profile.
use super::{END, LEFT_DOWN, LEFT_UP, ProgramWords, movement};
use crate::model::Core;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GunA {
    pub core: Core,
    pub bullets: Vec<Shot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shot {
    pub interval_ms: u16,
    /// Vendor GunA coordinates: the command builder negates Y.
    pub move_x: i8,
    pub move_y: i8,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    pub words: ProgramWords,
    pub shot_timing_ms: Vec<[u16; 2]>,
    pub write_ready: bool,
    pub limitations: [&'static str; 3],
}

pub fn preview(source: &GunA) -> Result<Preview, String> {
    if source.core != Core::Three || !(1..=5).contains(&source.bullets.len()) {
        return Err("GunA preview requires Core 3 and 1 to 5 bullets".into());
    }
    let mut press = Vec::new();
    let mut timing = Vec::new();
    for (index, shot) in source.bullets.iter().enumerate() {
        if !(1..=1019).contains(&shot.interval_ms)
            || !(-63..=63).contains(&shot.move_x)
            || !(-63..=63).contains(&shot.move_y)
        {
            return Err("GunA preview requires intervals 1..1019 ms and movement -63..63".into());
        }
        // 0062BC5F..0062BCBA: small intervals halve with a minimum of 1;
        // intervals >=40 use a 20-ms press and the remaining inter-shot gap.
        let [hold, gap] = if shot.interval_ms >= 40 {
            [20, shot.interval_ms - 20]
        } else {
            [1.max(shot.interval_ms / 2); 2]
        };
        let final_shot = index + 1 == source.bullets.len();
        timing.push([hold, if final_shot { 0 } else { gap }]);
        press.extend([LEFT_DOWN, 0x2608, 0x2800 + hold, LEFT_UP]);
        // 0062BD8B..0062BD9B skips the final gap AND movement.
        if !final_shot {
            press.extend([
                0x2608,
                0x2800 + gap,
                0x2609,
                movement(shot.move_x, -shot.move_y),
            ]);
        }
    }
    press.push(END);
    Ok(Preview {
        words: ProgramWords {
            press,
            release: None,
        },
        shot_timing_ms: timing,
        write_ready: false,
        limitations: [
            "Right-button pause and recoil recovery are excluded.",
            "Movement splitting outside -63..63 and other source types are excluded.",
            "No profile allocation, NOR preservation or device-write path is provided.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packaged_guna_assets_match_existing_compiler() {
        for (count, program) in [
            (2, super::super::Program::GunaDoubleHit),
            (3, super::super::Program::GunaTripleHit),
            (4, super::super::Program::GunaFourHit),
        ] {
            let source = GunA {
                core: Core::Three,
                bullets: (0..count)
                    .map(|_| Shot {
                        interval_ms: 100,
                        move_x: 0,
                        move_y: 0,
                    })
                    .collect(),
            };
            assert_eq!(
                preview(&source).unwrap().words.press,
                super::super::compile(program, Core::Three).unwrap().press
            );
        }
    }
    #[test]
    fn timing_threshold_y_inversion_and_final_shot_match_host_branches() {
        let source: GunA = serde_json::from_str(
            r#"{"core":3,"bullets":[
            {"interval_ms":39,"move_x":-2,"move_y":3},
            {"interval_ms":40,"move_x":63,"move_y":-63},
            {"interval_ms":1019,"move_x":1,"move_y":1}]}"#,
        )
        .unwrap();
        let result = preview(&source).unwrap();
        assert_eq!(result.shot_timing_ms, [[19, 19], [20, 20], [20, 0]]);
        assert_eq!(
            result.words.press,
            [
                0x2501, 0x2608, 0x2813, 0x2401, 0x2608, 0x2813, 0x2609, 0x7f7d, 0x2501, 0x2608,
                0x2814, 0x2401, 0x2608, 0x2814, 0x2609, 0x5fbf, 0x2501, 0x2608, 0x2814, 0x2401,
                0x262f
            ]
        );
        assert!(!result.write_ready);
    }
    #[test]
    fn rejects_untraced_inputs_and_does_not_saturate_delays() {
        let mut source = GunA {
            core: Core::Three,
            bullets: vec![
                Shot {
                    interval_ms: 1019,
                    move_x: 0,
                    move_y: 0,
                },
                Shot {
                    interval_ms: 1,
                    move_x: 0,
                    move_y: 0,
                },
            ],
        };
        assert_eq!(preview(&source).unwrap().words.press[5], 0x2be7);
        source.bullets[0].interval_ms = 1020;
        assert!(preview(&source).is_err());
        source.bullets[0].interval_ms = 1;
        source.bullets[0].move_x = -64;
        assert!(preview(&source).is_err());
        source.bullets[0].move_x = 0;
        source.core = Core::Two;
        assert!(preview(&source).is_err());
        assert!(serde_json::from_str::<GunA>(r#"{"core":3,"bullets":[],"recoil":true}"#).is_err());
    }
}
