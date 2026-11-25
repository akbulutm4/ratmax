//! Daily-driver 3-tab TUI for the Bloody W95 Max (Mouse, Macros, Lighting).

mod device;
mod lighting;
mod macros;
pub use device::WorkflowOptions;

use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
};

use crate::{boot_roundtrip::Mode, model::Core, workflow};

const TABS: [&str; 3] = ["1 Mouse", "2 Macros", "3 Lighting"];
const MOUSE_VIEW: usize = 0;
const MACROS_VIEW: usize = 1;
const LIGHTING_VIEW: usize = 2;

pub(super) fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let w = ((u32::from(area.width) * u32::from(percent_x)) / 100)
        .clamp(36, u32::from(area.width)) as u16;
    let h = height.min(area.height);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w, h)
}

pub(super) fn draw_popup_box(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    border_color: Color,
    lines: Vec<Line<'_>>,
) {
    let height = (lines.len() as u16 + 4).min(area.height.saturating_sub(2)).max(5);
    let popup = centered_rect(72, height, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }), inner);
}

pub struct App {
    view: usize,
    initial_core: Core,
    device: Option<device::Panel>,
    macros: macros::Panel,
    lighting: lighting::Panel,
}

impl App {
    pub fn new(initial: Core) -> Self {
        Self {
            view: MOUSE_VIEW,
            initial_core: initial,
            device: None,
            macros: macros::Panel::new(PathBuf::from("ratmax-macros.json"), initial),
            lighting: lighting::Panel::new(None, false),
        }
    }

    fn effective_mode(&self) -> Option<Mode> {
        match &self.device {
            Some(panel) => panel.installed_mode(),
            None => Some(Mode::Target(self.initial_core)),
        }
    }

    fn installed_core(&self) -> Option<Core> {
        self.device.as_ref().and_then(device::Panel::installed_core)
    }

    fn sync_lighting_if_needed(&mut self) {
        if self.view != LIGHTING_VIEW {
            return;
        }
        if self.device.as_ref().is_some_and(device::Panel::running) {
            return;
        }
        let installed = self
            .device
            .as_ref()
            .and_then(device::Panel::installed_lighting)
            .cloned();
        self.lighting.ensure_loaded(installed.as_ref());
    }

    fn modal_active(&self) -> bool {
        self.device.as_ref().is_some_and(device::Panel::modal_active)
            || (self.view == MACROS_VIEW && self.macros.modal_active())
            || (self.view == LIGHTING_VIEW && self.lighting.modal_active())
    }

    /// Returns false to exit once no device operation is in flight.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.kind == KeyEventKind::Release {
            return true;
        }
        // If a device review or live job modal is open, it owns all keys on every tab.
        if let Some(panel) = &mut self.device
            && panel.modal_active()
        {
            return panel.handle_modal(key);
        }

        // Let the active tab handle its own modals/inputs/keys first.
        match self.view {
            MOUSE_VIEW => {
                if let Some(panel) = &mut self.device
                    && panel.handle(key)
                {
                    return true;
                }
            }
            MACROS_VIEW => match self.macros.handle(key, self.effective_mode()) {
                macros::Outcome::Handled => return true,
                macros::Outcome::ApplySingle { button, program } => {
                    let core = self.installed_core();
                    let res = self
                        .device
                        .as_mut()
                        .ok_or_else(|| {
                            "Configure workspace (~/.config/ratmax/workspace.json) to save macros"
                                .to_string()
                        })
                        .and_then(|p| match core {
                            Some(c @ (Core::Three | Core::Four)) => p.review_macro(
                                c,
                                crate::macros::storage::Edit::Install { button, program },
                            ),
                            Some(other) => Err(format!(
                                "Macros require Core 3 or Core 4 (currently on Core {}). Switch Active Core on the Mouse tab first.",
                                other.number()
                            )),
                            None => Err("Mouse not detected yet. Press r on the Mouse tab to refresh.".into()),
                        });
                    if let Err(e) = res {
                        self.macros.notify_error(e);
                    } else {
                        self.macros.autosave_quiet();
                    }
                    return true;
                }
                macros::Outcome::ApplyAll { bindings } => {
                    let core = self.installed_core();
                    let res = self
                        .device
                        .as_mut()
                        .ok_or_else(|| {
                            "Configure workspace (~/.config/ratmax/workspace.json) to save macros"
                                .to_string()
                        })
                        .and_then(|p| match core {
                            Some(c @ (Core::Three | Core::Four)) => p.review_macro(
                                c,
                                crate::macros::storage::Edit::InstallAll { bindings },
                            ),
                            Some(other) => Err(format!(
                                "Macros require Core 3 or Core 4 (currently on Core {}). Switch Active Core on the Mouse tab first.",
                                other.number()
                            )),
                            None => Err("Mouse not detected yet. Press r on the Mouse tab to refresh.".into()),
                        });
                    if let Err(e) = res {
                        self.macros.notify_error(e);
                    } else {
                        self.macros.autosave_quiet();
                    }
                    return true;
                }
                macros::Outcome::Remove => {
                    let res = self
                        .device
                        .as_mut()
                        .ok_or_else(|| {
                            "Configure workspace (~/.config/ratmax/workspace.json) to clear macros"
                                .to_string()
                        })
                        .and_then(|p| p.review_macro_removal());
                    if let Err(e) = res {
                        self.macros.notify_error(e);
                    }
                    return true;
                }
                macros::Outcome::Pass => {}
            },
            LIGHTING_VIEW => match self.lighting.handle(key, self.effective_mode()) {
                lighting::Outcome::Handled => return true,
                lighting::Outcome::SavePermanent {
                    leds,
                    breathing,
                    brightness,
                } => {
                    let res = self
                        .device
                        .as_mut()
                        .ok_or_else(|| {
                            "Configure workspace (~/.config/ratmax/workspace.json) to save lighting"
                                .to_string()
                        })
                        .and_then(|p| {
                            p.review_lighting(crate::lighting::PersistentEdit::Install {
                                leds,
                                breathing,
                                brightness: Some(brightness),
                            })
                        });
                    if let Err(e) = res {
                        self.lighting.notify(e);
                    }
                    return true;
                }
                lighting::Outcome::RemovePermanent => {
                    let res = self
                        .device
                        .as_mut()
                        .ok_or_else(|| {
                            "Configure workspace (~/.config/ratmax/workspace.json) to restore lighting"
                                .to_string()
                        })
                        .and_then(|p| p.review_lighting(crate::lighting::PersistentEdit::Remove));
                    if let Err(e) = res {
                        self.lighting.notify(e);
                    }
                    return true;
                }
                lighting::Outcome::LoadInstalled => {
                    if let Some(cfg) = self
                        .device
                        .as_ref()
                        .and_then(|p| p.installed_lighting())
                        .cloned()
                    {
                        self.lighting.load_installed(&cfg);
                    } else {
                        self.lighting
                            .notify("No custom permanent lighting is saved on the mouse.");
                    }
                    return true;
                }
                lighting::Outcome::Pass => {}
            },
            _ => {}
        }

        // Global consistent navigation & exit keys (never fire inside modals).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Tab => {
                self.view = (self.view + 1) % TABS.len();
                self.sync_lighting_if_needed();
            }
            KeyCode::BackTab => {
                self.view = (self.view + TABS.len() - 1) % TABS.len();
                self.sync_lighting_if_needed();
            }
            KeyCode::Char('1') => self.view = MOUSE_VIEW,
            KeyCode::Char('2') => self.view = MACROS_VIEW,
            KeyCode::Char('3') => {
                self.view = LIGHTING_VIEW;
                self.sync_lighting_if_needed();
            }
            KeyCode::Char('r') => {
                if let Some(panel) = &mut self.device {
                    panel.trigger_refresh();
                }
            }
            _ => {}
        }
        true
    }

    pub fn draw(&self, frame: &mut Frame<'_>) {
        let area = frame.area();
        if area.width < 12 || area.height < 7 {
            return;
        }
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(4),
                Constraint::Length(3),
            ])
            .split(area);

        // Top bar: brand + connection badge on left, 3 tabs on right.
        let header_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(28), Constraint::Length(36)])
            .split(rows[0]);

        let (status_dot, status_text, status_color) = match &self.device {
            Some(p) => p.header_status(),
            None => ("○", "No workspace configured".to_string(), Color::DarkGray),
        };
        let header = Paragraph::new(Line::from(vec![
            Span::styled(
                " Ratmax ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(status_dot, Style::default().fg(status_color)),
            Span::raw(" "),
            Span::styled(status_text, Style::default().fg(Color::White)),
        ]))
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(header, header_cols[0]);

        let effective_mode = self.effective_mode();
        let macros_disabled =
            effective_mode.is_some_and(|m| !workflow::macros_supported(m));
        let perm_lighting_disabled =
            effective_mode.is_some_and(|m| !workflow::permanent_lighting_supported(m));

        let tab_titles: Vec<Line<'_>> = TABS
            .iter()
            .enumerate()
            .map(|(i, title)| {
                if i == MACROS_VIEW && macros_disabled {
                    Line::styled(*title, Style::default().fg(Color::DarkGray))
                } else {
                    Line::from(*title)
                }
            })
            .collect();
        let tabs = Tabs::new(tab_titles)
            .select(self.view)
            .divider(Span::styled(" │ ", Style::default().fg(Color::DarkGray)))
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        frame.render_widget(tabs, header_cols[1]);

        // Main tab body
        match self.view {
            MOUSE_VIEW => match &self.device {
                Some(panel) => panel.draw(frame, rows[1]),
                None => {
                    let msg = Paragraph::new(
                        "\n  No workspace found.\n\n  Set RATMAX_WORKSPACE or create ~/.config/ratmax/workspace.json.",
                    )
                    .block(Block::default().borders(Borders::ALL).title(" Mouse "));
                    frame.render_widget(msg, rows[1]);
                }
            },
            MACROS_VIEW => {
                let installed_buttons = self
                    .device
                    .as_ref()
                    .map(device::Panel::installed_macro_buttons)
                    .unwrap_or_default();
                self.macros
                    .draw(frame, rows[1], effective_mode, &installed_buttons);
            }
            LIGHTING_VIEW => {
                let installed = self
                    .device
                    .as_ref()
                    .and_then(device::Panel::installed_lighting);
                self.lighting
                    .draw(frame, rows[1], installed, effective_mode);
            }
            _ => {}
        }

        // Two-line TUI Controls Bar (visibly separate from embedded macro keys)
        let footer_lines = if self.modal_active() {
            vec![
                Line::from(vec![
                    Span::styled(
                        " MODAL ",
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "  Follow the dialog above · [Esc] Cancel",
                        Style::default().fg(Color::Gray),
                    ),
                ]),
                Line::raw(""),
            ]
        } else {
            let (line1, line2) = match self.view {
                MOUSE_VIEW => (
                    "  [1-3/Tab] Pages   [↑↓] Select   [←→] Change   [Shift+←→] Y DPI   [Enter] Edit   [Del] Revert",
                    "        [s] Apply   [r] Refresh   [B] Export Backup   [R] Factory Restore   [q] Quit",
                ),
                MACROS_VIEW if macros_disabled => (
                    "  [1-3/Tab] Pages   (Macros disabled on current Core — switch to Core 3 or Core 4 on Mouse tab)",
                    "        [1] Go to Mouse Tab   [r] Refresh   [q] Quit",
                ),
                MACROS_VIEW => (
                    "  [1-3/Tab] Pages   [↑↓] Button/Step   [←→] Press/Release   [Enter] Edit Steps   [Del] Delete",
                    "        [k] Record Key   [m] Mouse Click   [d] Delay   [t] Type Step   [s] Save   [u] Clear   [q] Quit",
                ),
                LIGHTING_VIEW if perm_lighting_disabled => (
                    "  [1-3/Tab] Pages   [↑↓] Select   [←→] Change   [Enter] Hex Color   [r] Refresh",
                    "        [p] Live Preview   [x] Stop Preview   (Permanent save requires Core 1–4)   [q] Quit",
                ),
                LIGHTING_VIEW => (
                    "  [1-3/Tab] Pages   [↑↓] Select   [←→] Change   [Enter] Hex Color   [r] Refresh",
                    "        [p] Live Preview   [s] Save Permanently   [l] Load Saved   [u] Stock   [x] Stop Preview   [q] Quit",
                ),
                _ => ("", ""),
            };
            vec![
                Line::from(vec![
                    Span::styled(
                        " TUI ",
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(line1, Style::default().fg(Color::Gray)),
                ]),
                Line::styled(line2, Style::default().fg(Color::Gray)),
            ]
        };
        let footer = Paragraph::new(footer_lines).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(footer, rows[2]);

        // Render device confirmation / progress modal OVER any tab!
        if let Some(panel) = &self.device {
            panel.draw_modal(frame, area);
        }
    }
}

pub fn run(
    initial: Core,
    project: Option<PathBuf>,
    workflow: Option<WorkflowOptions>,
) -> io::Result<()> {
    let mut app = App::new(initial);
    if let Some(options) = workflow {
        app.lighting = lighting::Panel::new(Some(options.workspace.clone()), options.model);
        let default_macros = options
            .workspace
            .parent()
            .unwrap_or(Path::new("."))
            .join("ratmax-macros.json");
        app.macros = macros::Panel::new(default_macros, initial);
        app.device = Some(device::Panel::new(options, initial));
        app.view = MOUSE_VIEW;
    }
    if let Some(project) = project
        && app.macros.open(project).is_ok()
    {
        app.view = MACROS_VIEW;
    }
    ratatui::run(|terminal| {
        if let Some(panel) = &mut app.device {
            panel.startup_read();
        }
        loop {
            if let Some(panel) = &mut app.device {
                panel.poll();
            }
            app.sync_lighting_if_needed();
            terminal.draw(|frame| app.draw(frame))?;
            if event::poll(Duration::from_millis(120))?
                && let Event::Key(key) = event::read()?
                && !app.handle_key(key)
            {
                break Ok(());
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn screen(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn three_tab_layout_switches_cleanly_and_renders_at_all_sizes() {
        let mut app = App::new(Core::Three);
        let home = screen(&app, 120, 30);
        assert!(home.contains("1 Mouse"));
        assert!(home.contains("2 Macros"));
        assert!(home.contains("3 Lighting"));
        assert!(!home.contains("Simulation"));
        assert!(!home.contains("Readiness"));

        for (w, h) in [(120, 30), (80, 24), (50, 18), (20, 8), (0, 0)] {
            let _ = screen(&app, w, h);
        }

        // Consistent 1/2/3 and Tab switching
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE)));
        assert_eq!(app.view, MACROS_VIEW);
        let mac_screen = screen(&app, 120, 30);
        assert!(mac_screen.contains("Record Key"));

        // Recording a key opens the unmistakable mouse-key capture modal and captures Ctrl+C!
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)));
        let cap_screen = screen(&app, 120, 30);
        assert!(cap_screen.contains("RECORDING MACRO KEY"));
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        let after = screen(&app, 120, 30);
        assert!(after.contains("Ctrl + C"));

        // Switch to Lighting tab
        assert!(app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE)));
        assert_eq!(app.view, LIGHTING_VIEW);
        assert!(screen(&app, 120, 30).contains("Brightness"));

        // Quit cleanly
        assert!(!app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    }

    #[test]
    fn core4_enables_macros_and_core1_or_core2_disables_macros() {
        // Core 4 supports Full-Key Macros!
        let mut c4 = App::new(Core::Four);
        assert!(c4.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE)));
        let s4 = screen(&c4, 120, 30);
        assert!(s4.contains("Core 4"));
        assert!(c4.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)));
        assert!(screen(&c4, 120, 30).contains("RECORDING MACRO KEY"));
        assert!(c4.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));

        // Core 1 and Core 2 disable Macros cleanly in the TUI!
        for core in [Core::One, Core::Two] {
            let mut app = App::new(core);
            assert!(app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE)));
            let text = screen(&app, 120, 30);
            assert!(text.contains("Macros are disabled"), "core {}: {text}", core.number());
            // Pressing 'k' does NOT open the recording modal when macros are disabled.
            assert!(app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)));
            assert!(!app.modal_active());
        }
    }
}
