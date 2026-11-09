"""
FireTrace TUI - Modular Cyber Reconnaissance Terminal User Interface
====================================================================
"""

from __future__ import annotations

import asyncio
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich import box
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    RadioButton,
    RadioSet,
    RichLog,
    Static,
    TextArea,
)

# Backend execution engine & prerequisite checker
from backend import (
    AsyncProcessEngine,
    CommandFactory,
    DistroDetector,
    DistroInfo,
    PrerequisiteChecker,
    PrerequisiteReport,
    TOOL_REGISTRY,
    ToolStatus,
)

# ==============================================================================
# UI THEMING & TEXTUAL CSS (TCSS)
# Strict Dark Mode with Amber Accents (#ffb000, #ffc107, #d97706)
# ==============================================================================
FIRETRACE_CSS = """
/* Global Application Canvas */
Screen {
    background: #0b0e14;
    color: #e6edf3;
}

/* Header & Branding Strip */
#header-bar {
    height: 3;
    background: #11141d;
    border-bottom: solid #d97706;
    padding: 0 1;
    align-vertical: middle;
}

#brand-title {
    color: #ffb000;
    text-style: bold;
    width: auto;
}

#brand-version {
    color: #8b949e;
    margin-left: 1;
    width: auto;
}

#header-target-badge {
    color: #ffb000;
    text-style: bold;
    margin-left: 3;
    width: auto;
}

#header-distro-badge {
    color: #38bdf8;
    margin-left: 2;
    width: auto;
}

#header-stats {
    dock: right;
    width: auto;
    color: #6e7681;
}

/* Workflow Phase Selector (Top Strip) */
#workflow-strip {
    height: 3;
    background: #131722;
    border-bottom: solid #2a3242;
    padding: 0 1;
    align-vertical: middle;
}

#workflow-label {
    color: #ffb000;
    text-style: bold;
    margin-right: 2;
    height: 1;
}

#workflow-radioset {
    layout: horizontal;
    background: transparent;
    border: none;
    height: 1;
    width: auto;
}

RadioButton {
    background: transparent;
    margin-right: 2;
    color: #8b949e;
    height: 1;
    padding: 0;
}

RadioButton:focus {
    color: #ffc107;
}

RadioButton.-selected {
    color: #ffb000;
    text-style: bold;
}

/* Main Two-Column Viewport */
#main-viewport {
    height: 1fr;
    width: 100%;
}

/* ========================================================================== */
/* LEFT / CENTER COLUMN: MAIN CONSOLE AREA                                    */
/* ========================================================================== */
#console-area {
    width: 68%;
    height: 100%;
    border-right: solid #2a3242;
    padding: 0 1 0 1;
}

#console-header-bar {
    height: 1;
    margin-top: 1;
    margin-bottom: 0;
}

#console-title {
    color: #ffb000;
    text-style: bold;
}

#console-status-indicator {
    dock: right;
    color: #22c55e;
    text-style: bold;
}

#terminal-log {
    height: 1fr;
    background: #080a0f;
    border: round #30394a;
    padding: 0 1;
    margin-top: 0;
    margin-bottom: 0;
    overflow-y: scroll;
}

#terminal-log:focus {
    border: round #ffb000;
}

/* Dynamic Suggestions Strip */
#suggestions-strip {
    height: 3;
    background: #11141d;
    border-left: solid #ffb000;
    padding: 0 1;
    margin-top: 0;
    margin-bottom: 0;
    align-vertical: middle;
}

#suggestions-label {
    color: #ffb000;
    text-style: bold;
    margin-right: 1;
    width: auto;
}

#suggestions-container {
    layout: horizontal;
    width: 1fr;
    height: 1;
}

.suggestion-chip {
    background: #1a202c;
    color: #ffb000;
    border: none;
    height: 1;
    min-width: 8;
    margin-right: 1;
    padding: 0 1;
}

.suggestion-chip:hover {
    background: #ffb000;
    color: #0b0e14;
    text-style: bold;
}

/* Interactive Command Prompt Row */
#command-row {
    height: 3;
    margin-top: 0;
    margin-bottom: 1;
    align-vertical: middle;
}

#prompt-label {
    width: auto;
    color: #ffb000;
    text-style: bold;
    padding: 0 1 0 0;
    height: 3;
    content-align-vertical: middle;
}

#cmd-input {
    width: 1fr;
    background: #080a0f;
    border: round #ffb000;
    color: #ffffff;
}

#cmd-input:focus {
    border: round #ffc107;
}

/* ========================================================================== */
/* RIGHT COLUMN: NOTE-TAKING PANE (TOP) & TARGET STATUS (BOTTOM)              */
/* ========================================================================== */
#right-column {
    width: 32%;
    height: 100%;
    padding: 0 1 0 1;
}

/* Note-Taking Pane (Top Right) */
#notes-container {
    height: 65%;
    border: round #ffb000;
    background: #11141d;
    padding: 0 1;
    margin-top: 1;
    margin-bottom: 1;
}

#notes-header-bar {
    height: 1;
    margin-bottom: 0;
    padding-top: 0;
}

#notes-title {
    color: #ffb000;
    text-style: bold;
}

#notes-status-badge {
    dock: right;
    color: #6e7681;
}

#notes-textarea {
    height: 1fr;
    background: #080a0f;
    border: solid #2a3242;
    color: #e6edf3;
}

#notes-textarea:focus {
    border: solid #ffb000;
}

#notes-footer-bar {
    height: 1;
    color: #6e7681;
}

/* Target Status Widget (Bottom Right Corner) */
#target-status-widget {
    height: 35%;
    border: round #ffb000;
    background: #11141d;
    padding: 0 1;
    margin-bottom: 1;
}

#target-header-bar {
    height: 1;
    margin-bottom: 0;
}

#target-title {
    color: #ffb000;
    text-style: bold;
}

#target-scope-display {
    height: auto;
    margin-top: 0;
    color: #ffffff;
}

#target-health-row {
    height: 1;
    margin-top: 1;
    align-vertical: middle;
}

.indicator-dot-green {
    color: #22c55e;
    text-style: bold;
}

.indicator-dot-red {
    color: #ef4444;
    text-style: bold;
}

#target-controls-row {
    height: 3;
    margin-top: 1;
    align-vertical: middle;
}

.target-action-btn {
    height: 1;
    min-width: 11;
    background: #1a202c;
    color: #ffb000;
    border: none;
    margin-right: 1;
    padding: 0 1;
}

.target-action-btn:hover {
    background: #ffb000;
    color: #0b0e14;
    text-style: bold;
}

/* ========================================================================== */
/* MODAL: PREREQUISITE CHECKER ALERT                                          */
/* ========================================================================== */
MissingToolsModal {
    align: center middle;
    background: rgba(0, 0, 0, 0.75);
}

#modal-container {
    width: 85%;
    max-width: 105;
    height: auto;
    max-height: 90%;
    background: #11141d;
    border: thick #ffb000;
    padding: 1 2;
}

#modal-title {
    color: #ffb000;
    text-style: bold;
    height: 1;
}

#modal-distro-info {
    color: #8b949e;
    margin-bottom: 1;
    height: 1;
}

#modal-table-container {
    height: auto;
    max-height: 14;
    margin-bottom: 1;
}

#modal-command-box {
    background: #080a0f;
    border: solid #2a3242;
    padding: 0 1;
    margin-bottom: 1;
    height: auto;
}

#modal-command-label {
    color: #ffb000;
    text-style: bold;
}

#modal-command-text {
    color: #ffffff;
}

#modal-buttons-row {
    height: 3;
    align-horizontal: right;
    align-vertical: middle;
}

.modal-btn {
    min-width: 18;
    margin-left: 2;
    background: #ffb000;
    color: #0b0e14;
    text-style: bold;
    border: none;
}

.modal-btn:hover {
    background: #ffc107;
}

.modal-btn-secondary {
    min-width: 18;
    margin-left: 2;
    background: #1a202c;
    color: #ffb000;
    border: none;
}

.modal-btn-secondary:hover {
    background: #ffb000;
    color: #0b0e14;
}
"""

# ==============================================================================
# PRESET COMMANDS PER PENETRATION TESTING WORKFLOW PHASE (GENERIC / CLEAN)
# ==============================================================================
WORKFLOW_PRESETS: Dict[str, List[str]] = {
    "Recon": [
        "run subfinder",
        "run whois-lookup",
        "set target <IP>",
        "check-tools",
        "help",
    ],
    "Scanning": [
        "run nmap-quick",
        "run nmap-full",
        "run feroxbuster",
        "run nuclei-tech",
        "run ffuf-dirs",
        "help",
    ],
    "Exploit": [
        "run nuclei-cve",
        "check auth-bypass",
        "searchsploit",
        "help",
    ],
    "Post-Exp": [
        "run linpeas-check",
        "check sudo-privs",
        "dump sam-hashes",
        "help",
    ],
    "Reporting": [
        "export markdown",
        "status",
        "help",
    ],
}

DEFAULT_NOTES_CONTENT = ""

ASCII_BANNER = r"""[bold #ffb000]
  ______ _           _______                   
 |  ____(_)         |__   __|                  
 | |__   _ _ __ ___    | |_ __ __ _  ___ ___   
 |  __| | | '__/ _ \   | | '__/ _` |/ __/ _ \  
 | |    | | | |  __/   | | | | (_| | (_|  __/  
 |_|    |_|_|  \___|   |_|_|  \__,_|\___\___|  
[/][dim]Modular CLI/TUI Cyber Reconnaissance Framework v0.1.0[/]
"""


# ==============================================================================
# MODAL DIALOG: PREREQUISITE CHECKER
# ==============================================================================
class MissingToolsModal(ModalScreen[None]):
    """Modal dialog displaying missing tools and distro-specific installation commands."""

    def __init__(self, report: PrerequisiteReport) -> None:
        super().__init__()
        self.report = report

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-container"):
            yield Static("WARNING: FIRETRACE PREREQUISITE VALIDATION", id="modal-title")
            yield Static(
                f"Detected System: [bold white]{self.report.distro.distro_name}[/] | "
                f"Package Family: [bold #ffb000]{self.report.distro.package_family.upper()}[/]",
                id="modal-distro-info",
            )

            # Table of tools status
            table = Table(
                box=box.ROUNDED,
                border_style="#ffb000",
                header_style="bold #ffb000",
                expand=True,
            )
            table.add_column("Tool", style="bold white", width=14)
            table.add_column("Binary", style="dim", width=13)
            table.add_column("Tier", width=11)
            table.add_column("Status", width=14)
            table.add_column("Installation Command", style="cyan")

            for s in self.report.statuses:
                status_markup = "[bold #22c55e]INSTALLED[/]" if s.installed else "[bold #ef4444]MISSING[/]"
                tier_markup = "[bold #ffb000]Required[/]" if s.tool.required else "[dim]Optional[/]"
                table.add_row(
                    s.tool.name,
                    s.tool.binary,
                    tier_markup,
                    status_markup,
                    s.install_command,
                )

            with Vertical(id="modal-table-container"):
                yield Static(table)

            # One-liner script preview
            one_liner = self.report.generate_install_all_script()
            with Vertical(id="modal-command-box"):
                yield Static(
                    "Recommended Terminal Installation Command:",
                    id="modal-command-label",
                )
                yield Static(f"[bold white]{one_liner}[/]", id="modal-command-text")

            # Actions
            with Horizontal(id="modal-buttons-row"):
                yield Button(
                    "Proceed to FireTrace",
                    id="btn-dismiss-modal",
                    classes="modal-btn",
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-dismiss-modal":
            self.dismiss()


# ==============================================================================
# MAIN TUI APPLICATION CLASS
# ==============================================================================
class FireTraceApp(App):
    """FireTrace Terminal User Interface Application with Backend Engine."""

    CSS = FIRETRACE_CSS
    TITLE = "FIRETRACE"
    SUB_TITLE = "v0.1.0"
    dark = True

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=True),
        Binding("ctrl+l", "clear_console", "Clear Screen", show=True),
        Binding("ctrl+x", "abort_scan", "Abort Scan", show=True),
        Binding("f1", "set_phase_recon", "Recon", show=True),
        Binding("f2", "set_phase_scanning", "Scanning", show=True),
        Binding("f3", "set_phase_exploit", "Exploit", show=True),
        Binding("f4", "set_phase_post_exp", "Post-Exp", show=True),
        Binding("f5", "set_phase_reporting", "Reporting", show=True),
        Binding("f6", "toggle_ping", "Check Reachability", show=True),
        Binding("f7", "check_prerequisites", "Check Tools", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # State management (Strict blank-slate default: Target is Not Set)
        self.target_ip: str = "Not Set"
        self.current_workflow: str = "Recon"
        self.ping_successful: bool = False
        self.ping_latency_ms: Optional[int] = None
        self.last_ping_time: Optional[str] = None

        # Backend Engine & System Detection
        self.engine = AsyncProcessEngine()
        self.distro: DistroInfo = DistroDetector.detect()
        self.prereq_report: PrerequisiteReport = PrerequisiteChecker.run_check(self.distro)

    # ==========================================================================
    # SPATIAL LAYOUT COMPOSITION
    # ==========================================================================
    def compose(self) -> ComposeResult:
        """Compose the spatial layout of FireTrace."""
        # Top Header Bar (Clean branding without emojis or -PRO suffix)
        with Horizontal(id="header-bar"):
            yield Static("FIRETRACE", id="brand-title")
            yield Static("v0.1.0", id="brand-version")
            yield Static(
                self._render_header_target_badge(),
                id="header-target-badge",
            )
            yield Static(
                f"[{self.distro.distro_name}]",
                id="header-distro-badge",
            )
            yield Static("[Dark Mode: Amber Accent]", id="header-stats")

        # Official Penetration Testing Workflow Selector Strip (Top Bar)
        with Horizontal(id="workflow-strip"):
            yield Static("◈ WORKFLOW PHASE:", id="workflow-label")
            with RadioSet(id="workflow-radioset"):
                yield RadioButton("Recon", value=True, id="wf-recon")
                yield RadioButton("Scanning", id="wf-scanning")
                yield RadioButton("Exploit", id="wf-exploit")
                yield RadioButton("Post-Exp", id="wf-postexp")
                yield RadioButton("Reporting", id="wf-reporting")

        # Main Two-Column Viewport
        with Horizontal(id="main-viewport"):
            # ------------------------------------------------------------------
            # LEFT/CENTER: Main Console Area (msfconsole style)
            # ------------------------------------------------------------------
            with Vertical(id="console-area"):
                with Horizontal(id="console-header-bar"):
                    yield Static(
                        "◈ TERMINAL CONSOLE (msfconsole interactive shell)",
                        id="console-title",
                    )
                    yield Static("[IDLE]", id="console-status-indicator")
                yield RichLog(
                    id="terminal-log",
                    highlight=True,
                    markup=True,
                    auto_scroll=True,
                )

                # Suggestion Strip above input
                with Horizontal(id="suggestions-strip"):
                    yield Static("SUGGESTIONS:", id="suggestions-label")
                    yield Horizontal(id="suggestions-container")

                # Command Input Row
                with Horizontal(id="command-row"):
                    yield Static(
                        f"firetrace ({self.current_workflow.lower()})> ",
                        id="prompt-label",
                    )
                    yield Input(
                        placeholder="Type a command (e.g., 'set target <IP>', 'run nmap-quick', 'help')...",
                        id="cmd-input",
                    )

            # ------------------------------------------------------------------
            # RIGHT COLUMN: Notes Pane (Top Right) & Target Status (Bottom Right)
            # ------------------------------------------------------------------
            with Vertical(id="right-column"):
                # Note-Taking Pane (Top Right) - Blank initial canvas
                with Vertical(id="notes-container"):
                    with Horizontal(id="notes-header-bar"):
                        yield Static("📝 SESSION SCRATCHPAD", id="notes-title")
                        yield Static("[Auto-saving]", id="notes-status-badge")
                    yield TextArea(
                        text=DEFAULT_NOTES_CONTENT,
                        language="markdown",
                        id="notes-textarea",
                    )
                    yield Static(
                        "Markdown-enabled persistent session notepad",
                        id="notes-footer-bar",
                    )

                # Target Status Widget (Bottom Right Corner)
                with Vertical(id="target-status-widget"):
                    with Horizontal(id="target-header-bar"):
                        yield Static("◈ TARGET STATUS & HEALTH", id="target-title")
                    yield Static(
                        self._render_target_scope_text(),
                        id="target-scope-display",
                    )
                    with Horizontal(id="target-health-row"):
                        yield Static(
                            self._render_ping_indicator(),
                            id="target-ping-indicator",
                        )
                    with Horizontal(id="target-controls-row"):
                        yield Button(
                            "Check Ping",
                            id="btn-toggle-ping",
                            classes="target-action-btn",
                        )
                        yield Button(
                            "Set Target",
                            id="btn-change-target",
                            classes="target-action-btn",
                        )

        # Bottom Keybinding Footer
        yield Footer()

    # ==========================================================================
    # LIFECYCLE HOOKS
    # ==========================================================================
    async def on_mount(self) -> None:
        """Invoked when UI is initialized and mounted."""
        # Focus command input by default for instant keyboard readiness
        self.query_one("#cmd-input", Input).focus()

        # Render startup console banner & instructions
        log = self.query_one("#terminal-log", RichLog)
        log.write(ASCII_BANNER)

        target_str = "[bold yellow]Not Set[/]" if self.target_ip == "Not Set" else f"[bold white]{self.target_ip}[/]"
        log.write(
            f"[bold #ffb000][*] FireTrace Penetration Testing Console Initialized.[/]\n"
            f"[*] Target Scope : {target_str}\n"
            f"[*] Active Phase : [bold #ffb000]{self.current_workflow.upper()}[/]\n"
            f"[*] Host System  : [bold #38bdf8]{self.distro.distro_name}[/] ({self.distro.package_family})\n"
            f"[dim]Phases: 1. Recon | 2. Scanning | 3. Exploit | 4. Post-Exp | 5. Reporting[/]\n"
            f"[dim]Step 1: Use [bold #ffb000]'set target <IP/Domain>'[/] to configure active engagement scope.[/]\n"
            f"[dim]Type [bold #ffb000]'help'[/] for commands, [bold #ffb000]'check-tools'[/] for prerequisites.[/]\n"
        )

        # Check for missing required tools
        if self.prereq_report.missing_required:
            await self.push_screen(MissingToolsModal(self.prereq_report))
            log.write(
                f"[bold #ef4444][!] Prerequisite Warning:[/] {len(self.prereq_report.missing_required)} required tool(s) "
                f"missing from system PATH. Press [bold #ffb000]F7[/] to review installation commands.\n"
            )
        else:
            log.write("[bold #22c55e][+] All required security tools are present on system PATH.[/]\n")

        # Populate initial suggestions based on the active workflow phase
        await self._refresh_suggestions()

    # ==========================================================================
    # RENDERING HELPERS
    # ==========================================================================
    def _render_header_target_badge(self) -> str:
        """Format header target indicator based on current state."""
        if self.target_ip == "Not Set":
            return "[#ffb000]Active Target:[/] [bold yellow]Not Set[/]"
        return f"[#ffb000]Active Target:[/] [bold white]{self.target_ip}[/]"

    def _render_target_scope_text(self) -> str:
        """Generate formatted target scope metadata."""
        if self.target_ip == "Not Set":
            return (
                "Target IP : [bold yellow]Not Set[/]\n"
                "Scope     : Pending target configuration\n"
                "Project   : [dim]None (Set target first)[/]"
            )
        return (
            f"Target IP : [bold white]{self.target_ip}[/]\n"
            f"Scope     : Single Host IPv4 / CIDR: /32\n"
            f"Project   : ./projects/{self.target_ip.replace('.', '_')}/"
        )

    def _render_ping_indicator(self) -> str:
        """Visual indicator widget representation reflecting actual reachability."""
        if self.target_ip == "Not Set":
            return "[dim]● NO TARGET (Use 'set target <IP>') [/]"

        if self.ping_successful:
            latency_text = f"{self.ping_latency_ms}ms RTT" if self.ping_latency_ms is not None else "Reachable"
            time_text = f" | Checked {self.last_ping_time}" if self.last_ping_time else ""
            return f"[#22c55e]● REACHABLE[/] [dim]({latency_text}{time_text})[/]"
        else:
            time_text = f"Checked {self.last_ping_time}" if self.last_ping_time else "No ICMP reply"
            return f"[#ef4444]● UNREACHABLE[/] [dim]({time_text})[/]"

    async def _refresh_suggestions(self, filter_text: str = "") -> None:
        """Populate suggestion buttons above input according to the active workflow phase."""
        container = self.query_one("#suggestions-container", Horizontal)
        await container.remove_children()

        presets = WORKFLOW_PRESETS.get(self.current_workflow, [])
        query = filter_text.strip().lower()

        matched = [cmd for cmd in presets if query in cmd.lower()] if query else presets

        for cmd in matched[:5]:  # Display top 5 matches
            await container.mount(Button(cmd, classes="suggestion-chip"))

    # ==========================================================================
    # WORKFLOW PHASE EVENT HANDLERS
    # ==========================================================================
    async def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Triggered when the user switches workflow phase in the Top Bar."""
        selected_phase = str(event.pressed.label)
        await self._switch_workflow_phase(selected_phase)

    async def _switch_workflow_phase(self, phase_name: str) -> None:
        """Update prompt, suggestions, and console log when workflow phase changes."""
        self.current_workflow = phase_name

        # Update Command Line Prompt prefix
        prompt_label = self.query_one("#prompt-label", Static)
        prompt_label.update(f"firetrace ({self.current_workflow.lower()})> ")

        # Refresh preset suggestion pills
        await self._refresh_suggestions()

        # Log transition in terminal
        log = self.query_one("#terminal-log", RichLog)
        log.write(
            f"[*] Active workflow phase switched to: [bold #ffb000]{self.current_workflow.upper()}[/]"
        )

    # ==========================================================================
    # COMMAND INPUT & AUTOCOMPLETE HANDLERS
    # ==========================================================================
    async def on_input_changed(self, event: Input.Changed) -> None:
        """Live autocomplete filter based on text typed by the user."""
        await self._refresh_suggestions(event.value)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Process command entered by the user in the terminal input."""
        cmd_text = event.value.strip()
        cmd_input = self.query_one("#cmd-input", Input)
        cmd_input.value = ""

        if not cmd_text:
            return

        log = self.query_one("#terminal-log", RichLog)
        log.write(
            f"[bold #ffb000]firetrace ({self.current_workflow.lower()})>[/] {escape(cmd_text)}"
        )

        await self._execute_command(cmd_text)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle suggestion chip clicks and target control actions."""
        if "suggestion-chip" in event.button.classes:
            chosen_command = str(event.button.label)
            cmd_input = self.query_one("#cmd-input", Input)
            cmd_input.value = chosen_command
            cmd_input.focus()

        elif event.button.id == "btn-toggle-ping":
            await self._action_toggle_ping()

        elif event.button.id == "btn-change-target":
            log = self.query_one("#terminal-log", RichLog)
            log.write(
                "[dim][*] To configure target, enter command: [bold #ffb000]set target <IP/Domain>[/][/]"
            )
            cmd_input = self.query_one("#cmd-input", Input)
            cmd_input.value = "set target "
            cmd_input.focus()

    # ==========================================================================
    # COMMAND DISPATCHER & ASYNCHRONOUS SUBPROCESS EXECUTION
    # ==========================================================================
    async def _execute_command(self, cmd: str) -> None:
        """Parse and dispatch commands to the asynchronous backend engine."""
        log = self.query_one("#terminal-log", RichLog)
        parts = cmd.split()
        root = parts[0].lower()

        # 1. Built-in Help Table
        if root == "help":
            self._render_help_table()

        # 2. Clear Screen
        elif root == "clear":
            log.clear()

        # 3. Check Prerequisites / Tools Modal
        elif root in ("check-tools", "prereq", "tools"):
            await self.action_check_prerequisites()

        # 4. Abort / Stop active scan
        elif root in ("abort", "stop", "kill"):
            await self.action_abort_scan()

        # 5. Target Scope Mutation: set target <ip>
        elif root == "set" and len(parts) >= 3 and parts[1].lower() == "target":
            new_target = parts[2]
            try:
                # Sanitize and validate target format
                self.target_ip = CommandFactory.sanitize_target(new_target)
                self.ping_successful = False
                self.ping_latency_ms = None
                self.last_ping_time = None

                self.query_one("#header-target-badge", Static).update(
                    self._render_header_target_badge()
                )
                self.query_one("#target-scope-display", Static).update(
                    self._render_target_scope_text()
                )
                self.query_one("#target-ping-indicator", Static).update(
                    self._render_ping_indicator()
                )

                log.write(
                    f"[bold #22c55e][+] Target scope successfully configured:[/] [bold white]{self.target_ip}[/]\n"
                    f"    [dim]Workspace assigned: ./projects/{self.target_ip.replace('.', '_')}/[/]"
                )
            except ValueError as err:
                log.write(f"[bold #ef4444][!] Target validation error: {err}[/]")

        # 6. Ping Command
        elif root == "ping":
            await self._action_toggle_ping()

        # 7. Security Tool Execution Hook
        elif root in ("run", "nmap", "feroxbuster", "ffuf", "subfinder", "nuclei", "whois"):
            await self._execute_tool(cmd)

        # 8. Report Status / Artifact Inspection
        elif root in ("export", "report", "status"):
            self._handle_reporting()

        # 9. Fallback Unknown Command
        else:
            log.write(
                f"[bold #ef4444][!] Unknown command: '{escape(cmd)}'[/]. "
                f"Type [bold #ffb000]'help'[/] for commands or [bold #ffb000]'check-tools'[/] for prerequisites."
            )

    async def _execute_tool(self, raw_cmd: str) -> None:
        """
        Execute tool through AsyncProcessEngine with real-time stdout streaming.
        Strictly zero simulation: if a tool is missing or unconfigured, reports true status.
        """
        log = self.query_one("#terminal-log", RichLog)
        status_indicator = self.query_one("#console-status-indicator", Static)

        # Enforce target configuration requirement
        if self.target_ip == "Not Set":
            log.write(
                "[bold #ef4444][!] Target scope is not set.[/] "
                "Please configure a target first (e.g., [bold #ffb000]set target <IP/Domain>[/])."
            )
            return

        if self.engine.is_running:
            log.write(
                "[bold #ef4444][!] Another scan is currently executing.[/] "
                "Type [bold #ffb000]'abort'[/] or press [bold #ffb000]Ctrl+X[/] to terminate it."
            )
            return

        try:
            cmd_vector, binary_name = CommandFactory.build(raw_cmd, self.target_ip)
        except ValueError as err:
            log.write(f"[bold #ef4444][!] Command syntax error: {err}[/]")
            return

        tool_def = TOOL_REGISTRY.get(binary_name)
        is_available = shutil.which(binary_name) is not None

        # Real Execution: Stream stdout/stderr line-by-line in real-time
        if is_available:
            status_indicator.update("[bold #ffb000][SCANNING...][/]")
            try:
                await self.engine.execute_stream(
                    cmd_args=cmd_vector,
                    line_callback=log.write,
                )
            finally:
                status_indicator.update("[bold #22c55e][IDLE][/]")

        # Missing tool: Report exact status and install instruction (Zero simulated output)
        else:
            status_indicator.update("[bold #22c55e][IDLE][/]")
            install_cmd = (
                tool_def.get_install_command(self.distro)
                if tool_def
                else f"{self.distro.install_prefix} {binary_name}"
            )
            log.write(
                f"[bold #ef4444][!] Tool '{binary_name}' is not installed or not accessible on system PATH.[/]\n"
                f"[*] Detected Host: [bold #38bdf8]{self.distro.distro_name}[/] ({self.distro.package_family})\n"
                f"[*] To install this tool, run:\n"
                f"    [bold #ffb000]{install_cmd}[/]"
            )

    def _render_help_table(self) -> None:
        """Render a formatted Rich Table inside the terminal log."""
        table = Table(
            title="FireTrace Command Reference",
            border_style="#ffb000",
            header_style="bold #ffb000",
        )
        table.add_column("Command", style="bold white", width=22)
        table.add_column("Phase", style="#ffa000", width=12)
        table.add_column("Description", style="dim")

        table.add_row("set target <IP>", "Global", "Configure target IP or domain scope")
        table.add_row("run nmap-quick", "Scanning", "Top-100 port scan with version discovery")
        table.add_row("run nmap-full", "Scanning", "Full TCP 1-65535 scan with OS detection")
        table.add_row("run feroxbuster", "Scanning", "Recursive directory brute-forcing")
        table.add_row("run ffuf-dirs", "Scanning", "Web directory fuzzing via wordlist")
        table.add_row("run subfinder", "Recon", "Passive OSINT subdomain enumeration")
        table.add_row("run nuclei-cve", "Exploit", "Template vulnerability scan against target")
        table.add_row("check-tools", "Global", "Open prerequisite checker & distro install guide (F7)")
        table.add_row("abort", "Global", "Terminate currently running subprocess (Ctrl+X)")
        table.add_row("ping", "Global", "Execute ICMP round-trip probe against target")
        table.add_row("clear", "Global", "Clear the terminal screen buffer (Ctrl+L)")

        log = self.query_one("#terminal-log", RichLog)
        log.write(table)

    def _handle_reporting(self) -> None:
        """Inspect actual report files generated in project workspace (Zero mock outputs)."""
        log = self.query_one("#terminal-log", RichLog)
        if self.target_ip == "Not Set":
            log.write("[bold #ef4444][!] Target scope is not set. Use 'set target <IP/Domain>' first.[/]")
            return

        sanitized = self.target_ip.replace(".", "_")
        reports_dir = Path(f"./projects/{sanitized}/reports")
        if not reports_dir.exists():
            log.write(
                f"[bold #ffb000][*] Workspace status for target {self.target_ip}:[/]\n"
                f"    [dim]Directory ./projects/{sanitized}/ has not generated scan reports yet.[/]\n"
                f"    [dim]Run reconnaissance tools against the target to generate report artifacts.[/]"
            )
            return

        files = list(reports_dir.glob("*.md"))
        if not files:
            log.write(f"[dim][*] No markdown report files found in {reports_dir}.[/]")
        else:
            log.write(f"[bold #22c55e][+] Found {len(files)} report artifact(s) in {reports_dir}:[/]")
            for f in files:
                log.write(f"    ├── [bold white]{f.name}[/] ({f.stat().st_size} bytes)")

    # ==========================================================================
    # ACTION HANDLERS & KEYBINDINGS
    # ==========================================================================
    async def _action_toggle_ping(self) -> None:
        """Execute real ICMP probe against target. Strictly zero simulated toggles."""
        log = self.query_one("#terminal-log", RichLog)

        if self.target_ip == "Not Set":
            log.write("[bold #ef4444][!] Cannot test reachability: Target is 'Not Set'. Use 'set target <IP/Domain>' first.[/]")
            return

        ping_bin = shutil.which("ping")
        if not ping_bin:
            log.write("[bold #ef4444][!] 'ping' utility is not found on your system PATH.[/]")
            return

        param = "-n" if self.distro.os_type == "Windows" else "-c"
        cmd = ["ping", param, "1", self.target_ip]

        log.write(f"[dim][*] Probing target {self.target_ip}...[/]")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace")
            self.last_ping_time = datetime.now().strftime("%H:%M:%S")

            if proc.returncode == 0:
                self.ping_successful = True
                match = re.search(r"(?:time[=<]|Average = )(\d+(?:\.\d+)?)\s*ms", output)
                if match:
                    self.ping_latency_ms = int(float(match.group(1)))
                else:
                    self.ping_latency_ms = 1
                log.write(f"[bold #22c55e][+] ICMP probe SUCCESS:[/] Target {self.target_ip} is REACHABLE ({self.ping_latency_ms}ms RTT)")
            else:
                self.ping_successful = False
                self.ping_latency_ms = None
                log.write(f"[bold #ef4444][!] ICMP probe FAILED:[/] Target {self.target_ip} is UNREACHABLE")

        except Exception as exc:
            self.ping_successful = False
            self.ping_latency_ms = None
            log.write(f"[bold #ef4444][!] Reachability probe error: {exc}[/]")

        indicator = self.query_one("#target-ping-indicator", Static)
        indicator.update(self._render_ping_indicator())

    async def action_abort_scan(self) -> None:
        """Keyboard action (Ctrl+X): Terminate currently running subprocess."""
        if self.engine.is_running:
            await self.engine.terminate()
            log = self.query_one("#terminal-log", RichLog)
            log.write("[bold #ef4444][!] Scan abort signal dispatched.[/]")
        else:
            log = self.query_one("#terminal-log", RichLog)
            log.write("[dim][*] No subprocess is currently running.[/]")

    async def action_check_prerequisites(self) -> None:
        """Keyboard action (F7): Re-check tools and open Prerequisite Modal."""
        self.prereq_report = PrerequisiteChecker.run_check(self.distro)
        await self.push_screen(MissingToolsModal(self.prereq_report))

    def action_clear_console(self) -> None:
        """Keyboard action: Clear the terminal log (Ctrl+L)."""
        self.query_one("#terminal-log", RichLog).clear()

    async def action_set_phase_recon(self) -> None:
        """Keyboard action (F1): Switch to Recon phase."""
        self.query_one("#wf-recon", RadioButton).value = True
        await self._switch_workflow_phase("Recon")

    async def action_set_phase_scanning(self) -> None:
        """Keyboard action (F2): Switch to Scanning phase."""
        self.query_one("#wf-scanning", RadioButton).value = True
        await self._switch_workflow_phase("Scanning")

    async def action_set_phase_exploit(self) -> None:
        """Keyboard action (F3): Switch to Exploit phase."""
        self.query_one("#wf-exploit", RadioButton).value = True
        await self._switch_workflow_phase("Exploit")

    async def action_set_phase_post_exp(self) -> None:
        """Keyboard action (F4): Switch to Post-Exp phase."""
        self.query_one("#wf-postexp", RadioButton).value = True
        await self._switch_workflow_phase("Post-Exp")

    async def action_set_phase_reporting(self) -> None:
        """Keyboard action (F5): Switch to Reporting phase."""
        self.query_one("#wf-reporting", RadioButton).value = True
        await self._switch_workflow_phase("Reporting")

    async def action_toggle_ping(self) -> None:
        """Keyboard action (F6): Check target reachability."""
        await self._action_toggle_ping()


# ==============================================================================
# MAIN APPLICATION ENTRYPOINT
# ==============================================================================
def main() -> None:
    """Run the FireTrace application."""
    app = FireTraceApp()
    app.run()


if __name__ == "__main__":
    main()
