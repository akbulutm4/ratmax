//! Simplified, visual Macros tab with live key capture and clear separation
//! between TUI shortcuts and embedded mouse-macro keys.
use crate::{
    boot_roundtrip::Mode,
    macros::{self, Binding, Document, Mouse, Sequence, Step, Target},
    model::Core,
    workflow,
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

pub(super) enum Outcome {
    Handled,
    Pass,
    ApplySingle {
        button: Target,
        program: Sequence,
    },
    ApplyAll {
        bindings: Vec<crate::macros::storage::BindingEdit>,
    },
    Remove,
}

enum Modal {
    /// Captures a real keyboard press/chord directly for the mouse macro.
    RecordKey,
    /// Single-key picker for a mouse button click step.
    PickMouseClick,
    /// Numeric prompt for a delay in ms (1..=999).
    DelayInput(String),
    /// Power-user text prompt for typing a step (supports shorthand like `f13`, `esc`, `win+r`).
    TypeStep { editing: Option<usize>, text: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Buttons,
    Steps,
}

pub(super) struct Panel {
    document: Document,
    path: PathBuf,
    focus: Focus,
    target: usize,
    release: bool,
    row: usize,
    modal: Option<Modal>,
    message: Option<(String, bool)>, // (text, is_error)
}

impl Panel {
    pub(super) fn new(path: PathBuf, core: Core) -> Self {
        let mut p = Self {
            document: Document::empty(if matches!(core, Core::Three | Core::Four) {
                core
            } else {
                Core::Three
            }),
            path,
            focus: Focus::Buttons,
            target: 0,
            release: false,
            row: 0,
            modal: None,
            message: None,
        };
        if p.path.exists() {
            let _ = p.open(p.path.clone());
        }
        p
    }

    pub(super) fn open(&mut self, path: PathBuf) -> Result<(), String> {
        let doc = Document::load(&path)?;
        self.path = path;
        self.document = doc;
        self.fill_targets();
        self.target = 0;
        self.row = 0;
        Ok(())
    }

    pub(super) fn autosave_quiet(&mut self) {
        let _ = self.document.save(&self.path);
    }

    pub(super) fn notify_error(&mut self, msg: impl Into<String>) {
        self.message = Some((msg.into(), true));
    }

    pub(super) fn modal_active(&self) -> bool {
        self.modal.is_some()
    }

    fn fill_targets(&mut self) {
        for button in Target::ALL {
            if !self
                .document
                .macros
                .bindings
                .iter()
                .any(|b| b.button == button)
            {
                self.document.macros.bindings.push(Binding {
                    button,
                    name: button.name().into(),
                    program: Sequence::default(),
                });
            }
        }
    }

    fn binding_for(&self, button: Target) -> &Binding {
        self.document
            .macros
            .bindings
            .iter()
            .find(|b| b.button == button)
            .unwrap()
    }

    fn binding(&self) -> &Binding {
        self.binding_for(Target::ALL[self.target])
    }

    fn binding_mut(&mut self) -> &mut Binding {
        let target = Target::ALL[self.target];
        self.document
            .macros
            .bindings
            .iter_mut()
            .find(|b| b.button == target)
            .unwrap()
    }

    fn steps(&self) -> &Vec<Step> {
        if self.release {
            &self.binding().program.release
        } else {
            &self.binding().program.press
        }
    }

    fn steps_mut(&mut self) -> &mut Vec<Step> {
        let release = self.release;
        let p = &mut self.binding_mut().program;
        if release {
            &mut p.release
        } else {
            &mut p.press
        }
    }

    fn append_step(&mut self, step: Step) {
        if self.steps().len() >= 128 {
            self.notify_error("Maximum 128 steps reached.");
            return;
        }
        let idx = self.steps().len();
        self.steps_mut().push(step);
        self.row = idx;
        self.message = None;
    }

    fn build_apply_outcome(&mut self, installed_core: Option<Core>) -> Outcome {
        if let Some(c @ (Core::Three | Core::Four)) = installed_core {
            self.document.macros.core = c;
        }
        let non_empty: Vec<crate::macros::storage::BindingEdit> = self
            .document
            .macros
            .bindings
            .iter()
            .filter(|b| !b.program.press.is_empty() || !b.program.release.is_empty())
            .map(|b| crate::macros::storage::BindingEdit {
                button: b.button,
                program: b.program.clone(),
            })
            .collect();
        if non_empty.is_empty() {
            self.notify_error("Add at least one macro step first (press k, m, d, or t).");
            return Outcome::Handled;
        }
        if non_empty.len() == 1 {
            let item = non_empty.into_iter().next().unwrap();
            match macros::compile(&item.program) {
                Ok(c) if c.internal_installable => Outcome::ApplySingle {
                    button: item.button,
                    program: item.program,
                },
                Ok(_) => {
                    self.notify_error("Macro is too large for the mouse's internal memory.");
                    Outcome::Handled
                }
                Err(e) => {
                    self.notify_error(e);
                    Outcome::Handled
                }
            }
        } else {
            match macros::preview(&self.document.macros) {
                Ok(p) if p.combined_internal_installable => Outcome::ApplyAll {
                    bindings: non_empty,
                },
                Ok(_) => {
                    self.notify_error(
                        "Combined macros are too large for the mouse's internal memory.",
                    );
                    Outcome::Handled
                }
                Err(e) => {
                    self.notify_error(e);
                    Outcome::Handled
                }
            }
        }
    }

    pub(super) fn handle(&mut self, key: KeyEvent, installed_mode: Option<Mode>) -> Outcome {
        let installed_core = match installed_mode {
            Some(Mode::Normal) => Some(Core::One),
            Some(Mode::Target(c)) => Some(c),
            _ => None,
        };
        if let Some(mode) = installed_mode
            && !workflow::macros_supported(mode)
        {
            return match key.code {
                KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => Outcome::Handled,
                KeyCode::Char(
                    'k' | 'm' | 'd' | 't' | 'a' | 's' | 'S' | 'u' | 'U' | '[' | ']' | '+' | '='
                    | '-',
                )
                | KeyCode::Enter
                | KeyCode::Delete
                | KeyCode::Backspace => {
                    self.notify_error(disabled_macros_reason(mode));
                    Outcome::Handled
                }
                _ => Outcome::Pass,
            };
        }
        if let Some(modal) = self.modal.take() {
            match modal {
                Modal::RecordKey => {
                    if key.code == KeyCode::Esc {
                        return Outcome::Handled;
                    }
                    if let Some(step) = capture_key_event(key) {
                        self.append_step(step);
                    } else {
                        self.notify_error(
                            "Key not recognized by terminal — press t to type it (e.g. f13, esc, win+r).",
                        );
                    }
                    return Outcome::Handled;
                }
                Modal::PickMouseClick => {
                    let picked = match key.code {
                        KeyCode::Esc => return Outcome::Handled,
                        KeyCode::Char('1') => Some(Mouse::Left),
                        KeyCode::Char('2') => Some(Mouse::Right),
                        KeyCode::Char('3') => Some(Mouse::Middle),
                        KeyCode::Char('4') => Some(Mouse::Back),
                        KeyCode::Char('5') => Some(Mouse::Forward),
                        _ => {
                            self.modal = Some(Modal::PickMouseClick);
                            return Outcome::Handled;
                        }
                    };
                    if let Some(button) = picked {
                        self.append_step(Step::Click {
                            button,
                            hold_ms: 20,
                        });
                    }
                    return Outcome::Handled;
                }
                Modal::DelayInput(mut text) => {
                    match key.code {
                        KeyCode::Esc => return Outcome::Handled,
                        KeyCode::Backspace => {
                            text.pop();
                            self.modal = Some(Modal::DelayInput(text));
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() && text.len() < 3 => {
                            text.push(c);
                            self.modal = Some(Modal::DelayInput(text));
                        }
                        KeyCode::Enter => match text.parse::<u16>() {
                            Ok(ms) if (1..=999).contains(&ms) => {
                                self.append_step(Step::Delay { ms });
                            }
                            _ => {
                                self.notify_error("Delay must be between 1 and 999 ms.");
                                self.modal = Some(Modal::DelayInput(text));
                            }
                        },
                        _ => self.modal = Some(Modal::DelayInput(text)),
                    }
                    return Outcome::Handled;
                }
                Modal::TypeStep { editing, mut text } => {
                    if key.code == KeyCode::Char('u') && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        text.clear();
                        self.modal = Some(Modal::TypeStep { editing, text });
                        return Outcome::Handled;
                    }
                    match key.code {
                        KeyCode::Esc => return Outcome::Handled,
                        KeyCode::Backspace => {
                            text.pop();
                            self.modal = Some(Modal::TypeStep { editing, text });
                        }
                        KeyCode::Char(c) if !c.is_control() && text.len() < 80 => {
                            text.push(c);
                            self.modal = Some(Modal::TypeStep { editing, text });
                        }
                        KeyCode::Enter => match parse_friendly_step(&text) {
                            Ok(step) => {
                                if let Some(idx) = editing {
                                    if let Some(slot) = self.steps_mut().get_mut(idx) {
                                        *slot = step;
                                    }
                                    self.message = None;
                                } else {
                                    self.append_step(step);
                                }
                            }
                            Err(e) => {
                                self.notify_error(e);
                                self.modal = Some(Modal::TypeStep { editing, text });
                            }
                        },
                        _ => self.modal = Some(Modal::TypeStep { editing, text }),
                    }
                    return Outcome::Handled;
                }
            }
        }

        // Normal Macros tab TUI controls
        // ↑/↓ navigates Mouse Buttons (or Steps when focused on the Steps pane).
        // ←/→ toggles On Press / On Release.
        match key.code {
            KeyCode::Up => {
                match self.focus {
                    Focus::Buttons => {
                        self.target = (self.target + Target::ALL.len() - 1) % Target::ALL.len();
                        self.row = 0;
                        self.message = None;
                    }
                    Focus::Steps => {
                        self.row = self.row.saturating_sub(1);
                    }
                }
                Outcome::Handled
            }
            KeyCode::Down => {
                match self.focus {
                    Focus::Buttons => {
                        self.target = (self.target + 1) % Target::ALL.len();
                        self.row = 0;
                        self.message = None;
                    }
                    Focus::Steps => {
                        self.row = (self.row + 1).min(self.steps().len().saturating_sub(1));
                    }
                }
                Outcome::Handled
            }
            KeyCode::Left => {
                self.release = false;
                self.row = 0;
                if self.steps().is_empty() {
                    self.focus = Focus::Buttons;
                }
                Outcome::Handled
            }
            KeyCode::Right => {
                self.release = true;
                self.row = 0;
                if self.steps().is_empty() {
                    self.focus = Focus::Buttons;
                }
                Outcome::Handled
            }
            KeyCode::Esc if self.focus == Focus::Steps => {
                self.focus = Focus::Buttons;
                Outcome::Handled
            }
            KeyCode::Char('k') => {
                self.message = None;
                self.modal = Some(Modal::RecordKey);
                Outcome::Handled
            }
            KeyCode::Char('m') => {
                self.message = None;
                self.modal = Some(Modal::PickMouseClick);
                Outcome::Handled
            }
            KeyCode::Char('d') => {
                self.message = None;
                self.modal = Some(Modal::DelayInput("100".into()));
                Outcome::Handled
            }
            KeyCode::Char('t') | KeyCode::Char('a') => {
                self.message = None;
                self.modal = Some(Modal::TypeStep {
                    editing: None,
                    text: String::new(),
                });
                Outcome::Handled
            }
            KeyCode::Enter => {
                match self.focus {
                    Focus::Buttons => {
                        if !self.steps().is_empty() {
                            self.focus = Focus::Steps;
                            self.row = self.row.min(self.steps().len().saturating_sub(1));
                        } else {
                            self.modal = Some(Modal::RecordKey);
                        }
                    }
                    Focus::Steps => {
                        if let Some(step) = self.steps().get(self.row) {
                            self.modal = Some(Modal::TypeStep {
                                editing: Some(self.row),
                                text: step.to_string(),
                            });
                        } else {
                            self.focus = Focus::Buttons;
                        }
                    }
                }
                Outcome::Handled
            }
            KeyCode::Delete | KeyCode::Backspace => {
                if !self.steps().is_empty() {
                    let at = match self.focus {
                        Focus::Steps => self.row.min(self.steps().len() - 1),
                        Focus::Buttons => self.steps().len() - 1,
                    };
                    self.steps_mut().remove(at);
                    self.row = at.min(self.steps().len().saturating_sub(1));
                    if self.steps().is_empty() {
                        self.focus = Focus::Buttons;
                    }
                }
                Outcome::Handled
            }
            KeyCode::Char('[') => {
                let at = self.row;
                if at > 0 && at < self.steps().len() {
                    self.steps_mut().swap(at, at - 1);
                    self.row = at - 1;
                }
                Outcome::Handled
            }
            KeyCode::Char(']') => {
                let at = self.row;
                if at + 1 < self.steps().len() {
                    self.steps_mut().swap(at, at + 1);
                    self.row = at + 1;
                }
                Outcome::Handled
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                let r = &mut self.binding_mut().program.repeat;
                *r = (*r + 1).min(16);
                Outcome::Handled
            }
            KeyCode::Char('-') => {
                let r = &mut self.binding_mut().program.repeat;
                *r = (*r).saturating_sub(1).max(1);
                Outcome::Handled
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    self.autosave_quiet();
                    self.message = Some(("Saved macro draft.".into(), false));
                    Outcome::Handled
                } else {
                    self.build_apply_outcome(installed_core)
                }
            }
            KeyCode::Char('u') | KeyCode::Char('U') => Outcome::Remove,
            _ => Outcome::Pass,
        }
    }

    pub(super) fn draw(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        installed_mode: Option<Mode>,
        installed_buttons: &[Target],
    ) {
        let disabled_reason = installed_mode
            .filter(|m| !workflow::macros_supported(*m))
            .map(disabled_macros_reason);
        let cols = if area.width >= 76 {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(28), Constraint::Min(36)])
                .split(area)
        } else {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(10), Constraint::Min(8)])
                .split(area)
        };

        // Left pane: Mouse Buttons list
        let mut btn_lines: Vec<Line<'_>> = Vec::new();
        for (idx, button) in Target::ALL.iter().enumerate() {
            let selected = disabled_reason.is_none() && idx == self.target;
            let b = self.binding_for(*button);
            let total_steps = b.program.press.len() + b.program.release.len();
            let on_mouse = installed_buttons.contains(button);

            let mut spans = vec![
                Span::styled(
                    if selected { " ▶ " } else { "   " },
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<16}", short_button_name(*button)),
                    if disabled_reason.is_some() {
                        Style::default().fg(Color::DarkGray)
                    } else if selected {
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    },
                ),
            ];
            if on_mouse {
                spans.push(Span::styled("●", Style::default().fg(Color::Green)));
                spans.push(Span::raw(" "));
            } else {
                spans.push(Span::raw("  "));
            }
            if total_steps > 0 {
                spans.push(Span::styled(
                    format!("{total_steps}"),
                    Style::default().fg(if disabled_reason.is_some() {
                        Color::DarkGray
                    } else {
                        Color::Yellow
                    }),
                ));
            }
            btn_lines.push(Line::from(spans));
        }
        btn_lines.push(Line::raw(""));
        btn_lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("●", Style::default().fg(Color::Green)),
            Span::styled(" = Active on mouse", Style::default().fg(Color::DarkGray)),
        ]));
        if disabled_reason.is_some() {
            btn_lines.push(Line::raw(""));
            btn_lines.push(Line::styled(
                "  Disabled on this Core",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
            btn_lines.push(Line::styled(
                "  Requires Core 3 or Core 4",
                Style::default().fg(Color::DarkGray),
            ));
        }
        let left_border = if disabled_reason.is_some() {
            Color::DarkGray
        } else if self.focus == Focus::Buttons {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let left = Paragraph::new(btn_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(left_border))
                .title(Span::styled(
                    " Mouse Buttons (↑/↓) ",
                    Style::default()
                        .fg(if disabled_reason.is_some() {
                            Color::DarkGray
                        } else if self.focus == Focus::Buttons {
                            Color::Cyan
                        } else {
                            Color::Gray
                        })
                        .add_modifier(Modifier::BOLD),
                )),
        );
        frame.render_widget(left, cols[0]);

        if let Some(reason) = disabled_reason {
            let disabled_lines = vec![
                Line::raw(""),
                Line::styled(
                    "  Macros are disabled for the currently installed Core.",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::styled(format!("  {reason}"), Style::default().fg(Color::White)),
                Line::raw(""),
                Line::styled(
                    "  Supported Cores:",
                    Style::default()
                        .fg(Color::Gray)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::styled(
                    "    • Core 3: Shooting Mode + Custom Button Macros",
                    Style::default().fg(Color::Gray),
                ),
                Line::styled(
                    "    • Core 4: Full-Key Custom Button Macros (no Shooting / GunA)",
                    Style::default().fg(Color::Gray),
                ),
                Line::raw(""),
                Line::styled(
                    "  Press [1] to open the Mouse tab, change Active Core to Core 3 or Core 4, and press [s] to apply.",
                    Style::default().fg(Color::Cyan),
                ),
            ];
            let right = Paragraph::new(disabled_lines)
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray))
                        .title(Span::styled(
                            " Macros Disabled ",
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        )),
                );
            frame.render_widget(right, cols[1]);
            return;
        }

        // Right pane: Steps embedded in the selected mouse button
        let b = self.binding();
        let press_n = b.program.press.len();
        let rel_n = b.program.release.len();
        let mut right_lines: Vec<Line<'_>> = vec![
            Line::from(vec![
                Span::raw("  Trigger (←/→): "),
                Span::styled(
                    format!(" On Press ({press_n}) "),
                    if !self.release {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
                Span::raw("  "),
                Span::styled(
                    format!(" On Release ({rel_n}) "),
                    if self.release {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
                Span::raw("   "),
                Span::styled(
                    format!("Repeat: {}x (+/-)", b.program.repeat),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::raw(""),
        ];

        let steps = self.steps();
        if steps.is_empty() {
            right_lines.push(Line::styled(
                "  No steps yet for this button.",
                Style::default().fg(Color::DarkGray),
            ));
            right_lines.push(Line::raw(""));
            right_lines.push(Line::from(vec![
                Span::raw("  Press "),
                Span::styled(
                    " k ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" to record a keyboard key/combo, "),
                Span::styled(
                    " m ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" for a mouse click, or "),
                Span::styled(
                    " d ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" for a delay."),
            ]));
        } else {
            let max_visible = cols[1].height.saturating_sub(8).max(4) as usize;
            let start = self.row.saturating_sub(max_visible.saturating_sub(1));
            for (idx, step) in steps.iter().enumerate().skip(start).take(max_visible) {
                let selected = self.focus == Focus::Steps && idx == self.row;
                let (badge, badge_bg, badge_fg, desc) = format_step_pill(step);
                right_lines.push(Line::from(vec![
                    Span::styled(
                        if selected { " ▶ " } else { "   " },
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:>2}. ", idx + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!(" {badge} "),
                        Style::default()
                            .fg(badge_fg)
                            .bg(badge_bg)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        desc,
                        if selected {
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        },
                    ),
                ]));
            }
            right_lines.push(Line::raw(""));
            right_lines.push(Line::styled(
                if self.focus == Focus::Steps {
                    "  Steps focused: [↑↓] Select  [Enter] Edit  [[ / ]] Reorder  [Del] Delete  [Esc] Back to Buttons"
                } else {
                    "  Press [Enter] to select/edit individual steps, or [k/m/d/t] to add another step."
                },
                Style::default().fg(Color::DarkGray),
            ));
        }

        if let Some((msg, is_err)) = &self.message {
            right_lines.push(Line::raw(""));
            right_lines.push(Line::styled(
                format!("  {msg}"),
                Style::default().fg(if *is_err { Color::Red } else { Color::Green }),
            ));
        }

        let right_border = if self.focus == Focus::Steps {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let core_tag = match installed_mode {
            Some(Mode::Target(Core::Four)) => " (Core 4 · Full Key)",
            Some(Mode::Target(Core::Three)) => " (Core 3)",
            _ => "",
        };
        let right = Paragraph::new(right_lines)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(right_border))
                    .title(Span::styled(
                        format!(" Embedded Mouse Macro — {}{core_tag} ", b.button.name()),
                        Style::default()
                            .fg(if self.focus == Focus::Steps {
                                Color::Cyan
                            } else {
                                Color::White
                            })
                            .add_modifier(Modifier::BOLD),
                    )),
            );
        frame.render_widget(right, cols[1]);

        // Draw active input/recording modal cleanly centered on top!
        if let Some(modal) = &self.modal {
            match modal {
                Modal::RecordKey => {
                    super::draw_popup_box(
                        frame,
                        area,
                        "RECORDING MACRO KEY (goes into mouse)",
                        Color::Yellow,
                        vec![
                            Line::raw(""),
                            Line::styled(
                                "  Press ANY keyboard key or combo to embed in this mouse button:",
                                Style::default()
                                    .fg(Color::White)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Line::styled(
                                "  Examples: Ctrl+C, Alt+Tab, F1..F12, Space, Enter, Arrows, A..Z",
                                Style::default().fg(Color::Cyan),
                            ),
                            Line::raw(""),
                            Line::styled(
                                "  TUI shortcuts are PAUSED — your next keypress is recorded.",
                                Style::default().fg(Color::Yellow),
                            ),
                            Line::styled(
                                "  [Esc] Cancel   (Need Esc/Tab/F13..F24/Win? Cancel and press t)",
                                Style::default().fg(Color::DarkGray),
                            ),
                        ],
                    );
                }
                Modal::PickMouseClick => {
                    super::draw_popup_box(
                        frame,
                        area,
                        "ADD MOUSE CLICK TO MACRO",
                        Color::Green,
                        vec![
                            Line::raw(""),
                            Line::from(vec![
                                Span::raw("  "),
                                Span::styled(" [1] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                                Span::raw("Left    "),
                                Span::styled(" [2] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                                Span::raw("Right    "),
                                Span::styled(" [3] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                                Span::raw("Middle"),
                            ]),
                            Line::from(vec![
                                Span::raw("  "),
                                Span::styled(" [4] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                                Span::raw("Back    "),
                                Span::styled(" [5] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                                Span::raw("Forward"),
                            ]),
                            Line::raw(""),
                            Line::styled("  [Esc] Cancel", Style::default().fg(Color::DarkGray)),
                        ],
                    );
                }
                Modal::DelayInput(text) => {
                    let mut lines = vec![
                        Line::raw(""),
                        Line::from(vec![
                            Span::raw("  Wait time (1..999 ms): "),
                            Span::styled(
                                format!("{text}_"),
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ]),
                        Line::raw(""),
                        Line::styled(
                            "  [Enter] Add delay    [Esc] Cancel",
                            Style::default().fg(Color::DarkGray),
                        ),
                    ];
                    if let Some((msg, true)) = &self.message {
                        lines.push(Line::styled(format!("  {msg}"), Style::default().fg(Color::Red)));
                    }
                    super::draw_popup_box(frame, area, "ADD DELAY TO MACRO", Color::Cyan, lines);
                }
                Modal::TypeStep { editing, text } => {
                    let title = if editing.is_some() {
                        "EDIT MACRO STEP"
                    } else {
                        "TYPE CUSTOM MACRO STEP"
                    };
                    let mut lines = vec![
                        Line::raw(""),
                        Line::from(vec![
                            Span::raw("  Step: "),
                            Span::styled(
                                format!("{text}_"),
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ]),
                        Line::raw(""),
                        Line::styled(
                            "  Shorthand: f13, esc, tab, win+r, ctrl+shift+v",
                            Style::default().fg(Color::Gray),
                        ),
                        Line::styled(
                            "  Full:      tap ctrl+c 20 | down ctrl | up ctrl | click left | delay 100 | move 0 -12",
                            Style::default().fg(Color::DarkGray),
                        ),
                        Line::styled(
                            "  [Enter] Save    [Ctrl+U] Clear    [Esc] Cancel",
                            Style::default().fg(Color::DarkGray),
                        ),
                    ];
                    if let Some((msg, true)) = &self.message {
                        lines.push(Line::styled(format!("  {msg}"), Style::default().fg(Color::Red)));
                    }
                    super::draw_popup_box(frame, area, title, Color::Cyan, lines);
                }
            }
        }
    }
}

fn disabled_macros_reason(mode: Mode) -> String {
    match mode {
        Mode::Normal => {
            "Original Core 1 does not support custom macros. Switch to Core 3 or Core 4 on the Mouse tab."
                .into()
        }
        Mode::Target(c) => format!(
            "Core {} does not support custom macros. Switch to Core 3 or Core 4 on the Mouse tab.",
            c.number()
        ),
        Mode::Boot => "Macros are unavailable in bootloader mode.".into(),
    }
}

fn short_button_name(target: Target) -> &'static str {
    match target {
        Target::Back => "Back",
        Target::Forward => "Forward",
        Target::ExtraClick => "Extra Click",
        Target::Precision => "Precision",
        Target::AuxClick => "Aux Click",
        Target::AuxFront => "Aux Front",
        Target::AuxRear => "Aux Rear",
    }
}

fn format_key_display(key: &str) -> String {
    key.split('+')
        .map(|part| match part.to_ascii_lowercase().as_str() {
            "ctrl" | "lctrl" => "Ctrl".into(),
            "rctrl" => "RCtrl".into(),
            "shift" | "lshift" => "Shift".into(),
            "rshift" => "RShift".into(),
            "alt" | "lalt" => "Alt".into(),
            "ralt" => "RAlt".into(),
            "super" | "gui" | "win" | "lsuper" => "Win".into(),
            "esc" | "escape" => "Esc".into(),
            "enter" | "return" => "Enter".into(),
            "space" => "Space".into(),
            "tab" => "Tab".into(),
            "backspace" => "Backspace".into(),
            "delete" => "Delete".into(),
            "pageup" => "PgUp".into(),
            "pagedown" => "PgDn".into(),
            other if other.len() == 1 => other.to_ascii_uppercase(),
            other if other.starts_with('f') && other[1..].chars().all(|c| c.is_ascii_digit()) => {
                other.to_ascii_uppercase()
            }
            other => {
                let mut chs = other.chars();
                match chs.next() {
                    Some(c) => format!("{}{}", c.to_ascii_uppercase(), chs.as_str()),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

fn format_step_pill(step: &Step) -> (&'static str, Color, Color, String) {
    match step {
        Step::Tap { key, hold_ms } => (
            "KEY",
            Color::Cyan,
            Color::Black,
            format!("{}  ({hold_ms} ms)", format_key_display(key)),
        ),
        Step::KeyDown { key } => ("DOWN", Color::Blue, Color::White, format_key_display(key)),
        Step::KeyUp { key } => ("UP", Color::DarkGray, Color::White, format_key_display(key)),
        Step::Click { button, hold_ms } => (
            "MOUSE",
            Color::Green,
            Color::Black,
            format!("{button:?} Click  ({hold_ms} ms)"),
        ),
        Step::MouseDown { button } => (
            "M-DOWN",
            Color::Green,
            Color::Black,
            format!("{button:?} Button"),
        ),
        Step::MouseUp { button } => (
            "M-UP",
            Color::DarkGray,
            Color::White,
            format!("{button:?} Button"),
        ),
        Step::Delay { ms } => ("WAIT", Color::Yellow, Color::Black, format!("{ms} ms")),
        Step::Move { x, y } => (
            "MOVE",
            Color::Magenta,
            Color::White,
            format!("X {x:+}, Y {y:+}"),
        ),
    }
}

/// Accepts either full `Step::parse` syntax OR shorthand key/combo names like `f13`, `esc`, `ctrl+v`.
fn parse_friendly_step(raw: &str) -> Result<Step, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Enter a step (e.g. f13, ctrl+c, delay 100, click left)".into());
    }
    if let Ok(step) = Step::parse(trimmed) {
        return Ok(step);
    }
    if !trimmed.contains(char::is_whitespace) {
        let candidate = Step::Tap {
            key: trimmed.to_ascii_lowercase(),
            hold_ms: 20,
        };
        let test_seq = Sequence {
            press: vec![candidate.clone()],
            release: vec![],
            repeat: 1,
        };
        if macros::compile(&test_seq).is_ok() {
            return Ok(candidate);
        }
    }
    Step::parse(trimmed)
}

/// Converts a live terminal KeyEvent into an embedded mouse macro `Step::Tap`.
fn capture_key_event(key: KeyEvent) -> Option<Step> {
    let mut mods: Vec<&'static str> = Vec::new();
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        mods.push("ctrl");
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        mods.push("alt");
    }
    let mut implied_shift = false;
    let base: String = match key.code {
        KeyCode::Char(' ') => "space".into(),
        KeyCode::Char(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => c.to_string(),
        KeyCode::Char(c) if c.is_ascii_uppercase() => {
            implied_shift = true;
            c.to_ascii_lowercase().to_string()
        }
        KeyCode::Char(c) => {
            let (name, shifted) = match c {
                '-' => ("minus", false),
                '_' => ("minus", true),
                '=' => ("equal", false),
                '+' => ("equal", true),
                '[' => ("left-bracket", false),
                '{' => ("left-bracket", true),
                ']' => ("right-bracket", false),
                '}' => ("right-bracket", true),
                '\\' => ("backslash", false),
                '|' => ("backslash", true),
                ';' => ("semicolon", false),
                ':' => ("semicolon", true),
                '\'' => ("quote", false),
                '"' => ("quote", true),
                '`' => ("grave", false),
                '~' => ("grave", true),
                ',' => ("comma", false),
                '<' => ("comma", true),
                '.' => ("period", false),
                '>' => ("period", true),
                '/' => ("slash", false),
                '?' => ("slash", true),
                '!' => ("1", true),
                '@' => ("2", true),
                '#' => ("3", true),
                '$' => ("4", true),
                '%' => ("5", true),
                '^' => ("6", true),
                '&' => ("7", true),
                '*' => ("8", true),
                '(' => ("9", true),
                ')' => ("0", true),
                _ => return None,
            };
            implied_shift = shifted;
            name.into()
        }
        KeyCode::Enter => "enter".into(),
        KeyCode::Tab => "tab".into(),
        KeyCode::BackTab => {
            implied_shift = true;
            "tab".into()
        }
        KeyCode::Backspace => "backspace".into(),
        KeyCode::Delete => "delete".into(),
        KeyCode::Insert => "insert".into(),
        KeyCode::Home => "home".into(),
        KeyCode::End => "end".into(),
        KeyCode::PageUp => "pageup".into(),
        KeyCode::PageDown => "pagedown".into(),
        KeyCode::Up => "up".into(),
        KeyCode::Down => "down".into(),
        KeyCode::Left => "left".into(),
        KeyCode::Right => "right".into(),
        KeyCode::F(n @ 1..=24) => format!("f{n}"),
        _ => return None,
    };
    if implied_shift || key.modifiers.contains(KeyModifiers::SHIFT) {
        mods.push("shift");
    }
    let full = if mods.is_empty() {
        base
    } else {
        format!("{}+{base}", mods.join("+"))
    };
    Some(Step::Tap {
        key: full,
        hold_ms: 20,
    })
}
