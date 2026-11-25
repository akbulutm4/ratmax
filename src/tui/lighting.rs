//! Simplified visual Lighting tab with RGB swatches, live RAM preview,
//! and permanent internal-flash save (zero external-NOR writes).
use crate::{
    boot_roundtrip::Mode,
    lighting::{
        self, Breathing, Brightness, Effect, LED_COUNT, LightingStatus, PersistentLighting, Rgb,
    },
    workflow::{self, Workspace},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectKind {
    Normal,
    Solid,
    Gradient,
    Rainbow,
    PerLed,
}

impl EffectKind {
    const ALL: [Self; 5] = [
        Self::Normal,
        Self::Solid,
        Self::Gradient,
        Self::Rainbow,
        Self::PerLed,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Normal => "Stock (Default)",
            Self::Solid => "Solid Color",
            Self::Gradient => "Two-Color Gradient",
            Self::Rainbow => "Rainbow Spectrum",
            Self::PerLed => "Custom Per-LED (15 Zones)",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Brightness,
    Effect,
    Primary,
    Secondary,
    Breathing,
    LedZone,
    LedColor,
}

pub(super) enum Outcome {
    Handled,
    Pass,
    SavePermanent {
        leds: [Rgb; LED_COUNT],
        breathing: Breathing,
        brightness: Brightness,
    },
    RemovePermanent,
    LoadInstalled,
}

pub(super) struct Panel {
    workspace: Option<PathBuf>,
    model: bool,
    row: usize,
    brightness: Brightness,
    effect: EffectKind,
    primary: Rgb,
    secondary: Rgb,
    breathing: Breathing,
    selected_led: usize,
    leds: [Rgb; LED_COUNT],
    prompt: Option<(RowKind, String)>,
    status: Option<LightingStatus>,
    initialized: bool,
    message: Option<(String, bool)>,
}

impl Panel {
    pub(super) fn new(workspace: Option<PathBuf>, model: bool) -> Self {
        let primary = Rgb::new(0x00, 0xff, 0xff);
        let secondary = Rgb::new(0x88, 0x00, 0xff);
        Self {
            workspace,
            model,
            row: 0,
            brightness: Brightness::High100,
            effect: EffectKind::Solid,
            primary,
            secondary,
            breathing: Breathing::Off,
            selected_led: 0,
            leds: [primary; LED_COUNT],
            prompt: None,
            status: None,
            initialized: false,
            message: None,
        }
    }

    pub(super) fn ensure_loaded(&mut self, installed: Option<&PersistentLighting>) {
        if self.initialized || self.workspace.is_none() {
            return;
        }
        self.initialized = true;
        if let Some(cfg) = installed {
            self.breathing = cfg.breathing;
            self.leds = cfg.leds;
            if cfg.leds.iter().all(|c| *c == cfg.leds[0]) {
                self.effect = EffectKind::Solid;
                self.primary = cfg.leds[0];
            } else {
                self.effect = EffectKind::PerLed;
                self.primary = cfg.leds[0];
                self.secondary = cfg.leds[LED_COUNT - 1];
            }
            self.clamp_row();
        }
        self.do_read();
    }

    pub(super) fn modal_active(&self) -> bool {
        self.prompt.is_some()
    }

    pub(super) fn notify(&mut self, msg: impl Into<String>) {
        self.message = Some((msg.into(), false));
    }

    pub(super) fn load_installed(&mut self, cfg: &PersistentLighting) {
        self.breathing = cfg.breathing;
        self.leds = cfg.leds;
        if cfg.leds.iter().all(|c| *c == cfg.leds[0]) {
            self.effect = EffectKind::Solid;
            self.primary = cfg.leds[0];
        } else {
            self.effect = EffectKind::PerLed;
            self.primary = cfg.leds[0];
            self.secondary = cfg.leds[LED_COUNT - 1];
        }
        self.clamp_row();
        self.message = Some(("Loaded saved lighting from mouse.".into(), false));
    }

    fn visible_rows(&self) -> Vec<RowKind> {
        let mut rows = vec![RowKind::Brightness, RowKind::Effect];
        match self.effect {
            EffectKind::Normal => {}
            EffectKind::Solid => {
                rows.push(RowKind::Primary);
                rows.push(RowKind::Breathing);
            }
            EffectKind::Gradient => {
                rows.push(RowKind::Primary);
                rows.push(RowKind::Secondary);
                rows.push(RowKind::Breathing);
            }
            EffectKind::Rainbow => {
                rows.push(RowKind::Breathing);
            }
            EffectKind::PerLed => {
                rows.push(RowKind::LedZone);
                rows.push(RowKind::LedColor);
                rows.push(RowKind::Breathing);
            }
        }
        rows
    }

    fn clamp_row(&mut self) {
        let len = self.visible_rows().len();
        if self.row >= len {
            self.row = len.saturating_sub(1);
        }
    }

    fn current_effect(&self) -> Effect {
        match self.effect {
            EffectKind::Normal => Effect::Normal,
            EffectKind::Solid => Effect::Solid {
                color: self.primary,
            },
            EffectKind::Gradient => Effect::Gradient {
                start: self.primary,
                end: self.secondary,
            },
            EffectKind::Rainbow => Effect::Rainbow,
            EffectKind::PerLed => Effect::PerLed { leds: self.leds },
        }
    }

    fn load_workspace(&self) -> Result<Workspace, String> {
        let path = self.workspace.as_deref().ok_or_else(|| {
            "Configure workspace (~/.config/ratmax/workspace.json) to control lighting".to_string()
        })?;
        Workspace::load(path)
    }

    fn do_read(&mut self) {
        match self
            .load_workspace()
            .and_then(|ws| lighting::read_status(&ws, self.model))
        {
            Ok(st) => {
                if let Ok(b) = Brightness::from_level(st.brightness_level) {
                    self.brightness = b;
                }
                let b_label = Brightness::from_level(st.brightness_level)
                    .map_or("Unknown", Brightness::label);
                self.message = Some((format!("Current brightness: {b_label}"), false));
                self.status = Some(st);
            }
            Err(e) => self.message = Some((e, true)),
        }
    }

    fn do_preview(&mut self, stop_preview: bool) {
        let effect = if stop_preview {
            Effect::Normal
        } else {
            self.current_effect()
        };
        let brightness = if stop_preview {
            None
        } else {
            Some(self.brightness)
        };
        match self.load_workspace().and_then(|ws| {
            lighting::apply(&ws, brightness, Some(&effect), self.breathing, self.model)
        }) {
            Ok(rep) => {
                if let Some(st) = rep.status {
                    self.status = Some(st);
                }
                let msg = if stop_preview || !rep.live_preview {
                    "Live preview stopped — showing saved lighting.".into()
                } else {
                    "Live preview applied (press s to save permanently to mouse).".into()
                };
                self.message = Some((msg, false));
            }
            Err(e) => self.message = Some((e, true)),
        }
    }

    fn cycle_preset(current: Rgb, delta: i32) -> Rgb {
        let len = Rgb::PRESETS.len() as i32;
        let idx = Rgb::PRESETS
            .iter()
            .position(|(_, c)| *c == current)
            .map(|i| i as i32)
            .unwrap_or(0);
        Rgb::PRESETS[(idx + delta).rem_euclid(len) as usize].1
    }

    fn adjust(&mut self, delta: i32) {
        let Some(&kind) = self.visible_rows().get(self.row) else {
            return;
        };
        match kind {
            RowKind::Brightness => {
                let len = Brightness::ALL.len() as i32;
                self.brightness =
                    Brightness::ALL[(self.brightness as i32 + delta).rem_euclid(len) as usize];
            }
            RowKind::Effect => {
                let len = EffectKind::ALL.len() as i32;
                let idx = EffectKind::ALL
                    .iter()
                    .position(|e| *e == self.effect)
                    .unwrap_or(0) as i32;
                self.effect = EffectKind::ALL[(idx + delta).rem_euclid(len) as usize];
                self.clamp_row();
            }
            RowKind::Primary => self.primary = Self::cycle_preset(self.primary, delta),
            RowKind::Secondary => self.secondary = Self::cycle_preset(self.secondary, delta),
            RowKind::Breathing => {
                let len = Breathing::ALL.len() as i32;
                self.breathing =
                    Breathing::ALL[(self.breathing as i32 + delta).rem_euclid(len) as usize];
            }
            RowKind::LedZone => {
                self.selected_led =
                    (self.selected_led as i32 + delta).rem_euclid(LED_COUNT as i32) as usize;
            }
            RowKind::LedColor => {
                self.leds[self.selected_led] =
                    Self::cycle_preset(self.leds[self.selected_led], delta);
            }
        }
    }

    pub(super) fn handle(&mut self, key: KeyEvent, installed_mode: Option<Mode>) -> Outcome {
        let perm_disabled =
            installed_mode.is_some_and(|m| !workflow::permanent_lighting_supported(m));
        if let Some((target, mut text)) = self.prompt.take() {
            if key.code == KeyCode::Char('u') && key.modifiers.contains(KeyModifiers::CONTROL) {
                text.clear();
                self.prompt = Some((target, text));
                return Outcome::Handled;
            }
            match key.code {
                KeyCode::Esc => return Outcome::Handled,
                KeyCode::Backspace => {
                    text.pop();
                    self.prompt = Some((target, text));
                }
                KeyCode::Char(c) if (c.is_ascii_hexdigit() || c == '#') && text.len() < 7 => {
                    text.push(c);
                    self.prompt = Some((target, text));
                }
                KeyCode::Enter => match Rgb::parse_hex(&text) {
                    Ok(rgb) => {
                        match target {
                            RowKind::Primary => self.primary = rgb,
                            RowKind::Secondary => self.secondary = rgb,
                            RowKind::LedColor => self.leds[self.selected_led] = rgb,
                            _ => {}
                        }
                        self.message = None;
                    }
                    Err(e) => {
                        self.message = Some((e, true));
                        self.prompt = Some((target, text));
                    }
                },
                _ => self.prompt = Some((target, text)),
            }
            return Outcome::Handled;
        }

        let rows = self.visible_rows();
        match key.code {
            KeyCode::Up => {
                self.row = (self.row + rows.len() - 1) % rows.len();
                Outcome::Handled
            }
            KeyCode::Down => {
                self.row = (self.row + 1) % rows.len();
                Outcome::Handled
            }
            KeyCode::Left => {
                self.adjust(-1);
                Outcome::Handled
            }
            KeyCode::Right => {
                self.adjust(1);
                Outcome::Handled
            }
            KeyCode::Enter => {
                match rows.get(self.row) {
                    Some(RowKind::Primary) => {
                        self.prompt = Some((RowKind::Primary, self.primary.hex()));
                    }
                    Some(RowKind::Secondary) => {
                        self.prompt = Some((RowKind::Secondary, self.secondary.hex()));
                    }
                    Some(RowKind::LedColor) => {
                        self.prompt =
                            Some((RowKind::LedColor, self.leds[self.selected_led].hex()));
                    }
                    _ => self.do_preview(false),
                }
                Outcome::Handled
            }
            KeyCode::Char('p') | KeyCode::Char(' ') => {
                self.do_preview(false);
                Outcome::Handled
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                if perm_disabled {
                    self.message = Some((
                        "Permanent RGB save is disabled on Original Core 1 — flash Core 1–4 on Mouse tab (Live Preview [p] still works).".into(),
                        true,
                    ));
                    return Outcome::Handled;
                }
                match self.current_effect().render_leds() {
                    Some(leds) => Outcome::SavePermanent {
                        leds,
                        breathing: self.breathing,
                        brightness: self.brightness,
                    },
                    None => Outcome::RemovePermanent,
                }
            }
            KeyCode::Char('u') | KeyCode::Char('U') => {
                if perm_disabled {
                    self.message = Some((
                        "Permanent RGB is unavailable on Original Core 1 — flash Core 1–4 on Mouse tab.".into(),
                        true,
                    ));
                    return Outcome::Handled;
                }
                Outcome::RemovePermanent
            }
            KeyCode::Char('l') | KeyCode::Char('L') => {
                if perm_disabled {
                    self.message = Some((
                        "No permanent custom RGB on Original Core 1 — flash Core 1–4 on Mouse tab.".into(),
                        true,
                    ));
                    return Outcome::Handled;
                }
                Outcome::LoadInstalled
            }
            KeyCode::Char('r') => {
                self.do_read();
                Outcome::Handled
            }
            KeyCode::Char('x') => {
                self.do_preview(true);
                Outcome::Handled
            }
            _ => Outcome::Pass,
        }
    }

    pub(super) fn draw(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        installed: Option<&PersistentLighting>,
        installed_mode: Option<Mode>,
    ) {
        let perm_disabled =
            installed_mode.is_some_and(|m| !workflow::permanent_lighting_supported(m));
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(10), Constraint::Length(5)])
            .split(area);

        let rows = self.visible_rows();
        let mut lines: Vec<Line<'_>> = Vec::new();

        // Compact saved status banner
        let saved_span = if perm_disabled {
            Span::styled(
                "Permanent RGB disabled on Original Core 1 (switch to Core 1–4 on Mouse tab; Live Preview [p] still works)",
                Style::default().fg(Color::Yellow),
            )
        } else if let Some(perm) = installed {
            let desc = if perm.leds.iter().all(|c| *c == perm.leds[0]) {
                format!("Solid {} ({})", perm.leds[0].hex(), perm.breathing.label())
            } else {
                format!("Custom 15-LED ({})", perm.breathing.label())
            };
            Span::styled(
                format!("Saved on mouse: {desc}   (press l to load)"),
                Style::default().fg(Color::Green),
            )
        } else {
            Span::styled(
                "Saved on mouse: Stock lighting",
                Style::default().fg(Color::DarkGray),
            )
        };
        lines.push(Line::from(vec![Span::raw("  "), saved_span]));
        lines.push(Line::raw(""));

        for (i, kind) in rows.iter().enumerate() {
            let selected = i == self.row;
            let cursor = Span::styled(
                if selected { " ▶ " } else { "   " },
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
            let label_style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let val_style = if selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let mut spans = vec![cursor];
            match kind {
                RowKind::Brightness => {
                    spans.push(Span::styled(format!("{:<18}", "Brightness"), label_style));
                    spans.push(Span::styled(self.brightness.label(), val_style));
                }
                RowKind::Effect => {
                    spans.push(Span::styled(format!("{:<18}", "Effect"), label_style));
                    spans.push(Span::styled(self.effect.label(), val_style));
                }
                RowKind::Primary => {
                    let lbl = if self.effect == EffectKind::Gradient {
                        "Start Color"
                    } else {
                        "Color"
                    };
                    spans.push(Span::styled(format!("{lbl:<18}"), label_style));
                    spans.extend(color_swatch_spans(self.primary, val_style));
                }
                RowKind::Secondary => {
                    spans.push(Span::styled(format!("{:<18}", "End Color"), label_style));
                    spans.extend(color_swatch_spans(self.secondary, val_style));
                }
                RowKind::Breathing => {
                    spans.push(Span::styled(format!("{:<18}", "Breathing"), label_style));
                    spans.push(Span::styled(self.breathing.label(), val_style));
                }
                RowKind::LedZone => {
                    spans.push(Span::styled(format!("{:<18}", "LED Zone"), label_style));
                    spans.push(Span::styled(
                        format!("Zone {} / {LED_COUNT}", self.selected_led + 1),
                        val_style,
                    ));
                }
                RowKind::LedColor => {
                    spans.push(Span::styled(format!("{:<18}", "Zone Color"), label_style));
                    spans.extend(color_swatch_spans(self.leds[self.selected_led], val_style));
                }
            }
            lines.push(Line::from(spans));
        }

        if let Some((msg, is_err)) = &self.message {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!("  {msg}"),
                Style::default().fg(if *is_err { Color::Red } else { Color::Green }),
            ));
        }

        let top = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    " RGB Lighting ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )),
        );
        frame.render_widget(top, sections[0]);

        // Visual 15-LED RGB Strip Preview
        let mut strip_spans = vec![Span::raw("  ")];
        if let Some(rendered) = self.current_effect().render_leds() {
            for (idx, c) in rendered.iter().enumerate() {
                let marker = if self.effect == EffectKind::PerLed && idx == self.selected_led {
                    "▓▓"
                } else {
                    "██"
                };
                strip_spans.push(Span::styled(
                    marker,
                    Style::default().fg(Color::Rgb(c.r, c.g, c.b)),
                ));
                strip_spans.push(Span::raw(" "));
            }
        } else {
            strip_spans.push(Span::styled(
                "Mouse will use its built-in stock lighting.",
                Style::default().fg(Color::DarkGray),
            ));
        }
        let preview_box = Paragraph::new(vec![
            Line::from(strip_spans),
            Line::styled(
                if perm_disabled {
                    "  [p] Live Preview (instant)    [x] Stop Preview    (Permanent save requires Core 1–4)"
                } else {
                    "  [p] Live Preview (instant)    [s] Save Permanently to Mouse    [u] Restore Stock"
                },
                Style::default().fg(Color::DarkGray),
            ),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(" Preview ", Style::default().fg(Color::Cyan))),
        );
        frame.render_widget(preview_box, sections[1]);

        if let Some((_, text)) = &self.prompt {
            let mut plines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::raw("  Hex color (#RRGGBB): "),
                    Span::styled(
                        format!("{text}_"),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::raw(""),
                Line::styled(
                    "  [Enter] Accept    [Ctrl+U] Clear    [Esc] Cancel",
                    Style::default().fg(Color::DarkGray),
                ),
            ];
            if let Some((msg, true)) = &self.message {
                plines.push(Line::styled(
                    format!("  {msg}"),
                    Style::default().fg(Color::Red),
                ));
            }
            super::draw_popup_box(frame, area, "SET COLOR", Color::Cyan, plines);
        }
    }
}

fn color_swatch_spans(c: Rgb, val_style: Style) -> Vec<Span<'static>> {
    let label = match c.preset_name() {
        Some(name) => format!("{} ({name})", c.hex()),
        None => c.hex(),
    };
    vec![
        Span::styled("███", Style::default().fg(Color::Rgb(c.r, c.g, c.b))),
        Span::raw(" "),
        Span::styled(label, val_style),
    ]
}
