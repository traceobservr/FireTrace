"""
FireTrace Backend Execution Engine & Prerequisite Checker
=========================================================
Module: backend.py
Features:
  1. DistroDetector: Identifies Linux distributions via /etc/os-release (Debian/Kali/Arch/Fedora/Alpine/etc.)
  2. PrerequisiteChecker: Validates required security binaries on PATH via shutil.which()
  3. ToolDefinition & TOOL_REGISTRY: Modular definitions and command vector builders for security tools
  4. AsyncProcessEngine: Non-blocking asynchronous subprocess runner with real-time stdout/stderr streaming
"""

from __future__ import annotations

import asyncio
import os
import platform
import re
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncGenerator, Callable, Dict, List, Optional, Tuple


# ==============================================================================
# 1. CROSS-DISTRO OS & PACKAGE MANAGER DETECTION
# ==============================================================================
@dataclass
class DistroInfo:
    """System distribution metadata and package manager strategy."""
    os_type: str                   # Linux, Windows, Darwin
    distro_name: str               # e.g., "Kali GNU/Linux", "Ubuntu", "Arch Linux", "Fedora"
    distro_id: str                 # e.g., "kali", "ubuntu", "arch", "fedora"
    package_family: str            # "apt", "pacman", "dnf", "apk", "brew", "windows", "generic"
    install_prefix: str            # e.g., "sudo apt install -y"


class DistroDetector:
    """Inspects host system to determine distribution and package manager."""

    @classmethod
    def detect(cls) -> DistroInfo:
        sys_type = platform.system()

        if sys_type == "Windows":
            return DistroInfo(
                os_type="Windows",
                distro_name="Windows (Host Dev Environment)",
                distro_id="windows",
                package_family="windows",
                install_prefix="winget install --id",
            )
        elif sys_type == "Darwin":
            return DistroInfo(
                os_type="Darwin",
                distro_name="macOS",
                distro_id="darwin",
                package_family="brew",
                install_prefix="brew install",
            )
        elif sys_type == "Linux":
            return cls._detect_linux()
        else:
            return DistroInfo(
                os_type=sys_type,
                distro_name=f"Generic Unix ({sys_type})",
                distro_id="generic",
                package_family="generic",
                install_prefix="install",
            )

    @staticmethod
    def _detect_linux() -> DistroInfo:
        """Parse /etc/os-release to identify Linux distribution."""
        os_release_paths = [Path("/etc/os-release"), Path("/usr/lib/os-release")]
        data: Dict[str, str] = {}

        for p in os_release_paths:
            if p.exists():
                try:
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip().strip('"').strip("'")
                    break
                except Exception:
                    pass

        distro_id = data.get("ID", "").lower()
        id_like = data.get("ID_LIKE", "").lower()
        pretty_name = data.get("PRETTY_NAME", data.get("NAME", "Linux"))

        # 1. Debian / Ubuntu / Kali / Parrot
        if any(d in distro_id or d in id_like for d in ("kali", "parrot", "debian", "ubuntu", "mint", "pop")):
            return DistroInfo(
                os_type="Linux",
                distro_name=pretty_name,
                distro_id=distro_id or "debian",
                package_family="apt",
                install_prefix="sudo apt update && sudo apt install -y",
            )
        # 2. Arch / Manjaro / BlackArch / EndeavourOS
        elif any(d in distro_id or d in id_like for d in ("arch", "manjaro", "blackarch", "endeavouros")):
            return DistroInfo(
                os_type="Linux",
                distro_name=pretty_name,
                distro_id=distro_id or "arch",
                package_family="pacman",
                install_prefix="sudo pacman -S --noconfirm",
            )
        # 3. Fedora / RHEL / CentOS / AlmaLinux / Rocky
        elif any(d in distro_id or d in id_like for d in ("fedora", "rhel", "centos", "almalinux", "rocky")):
            return DistroInfo(
                os_type="Linux",
                distro_name=pretty_name,
                distro_id=distro_id or "fedora",
                package_family="dnf",
                install_prefix="sudo dnf install -y",
            )
        # 4. Alpine Linux
        elif "alpine" in distro_id or "alpine" in id_like:
            return DistroInfo(
                os_type="Linux",
                distro_name=pretty_name,
                distro_id="alpine",
                package_family="apk",
                install_prefix="sudo apk add",
            )
        # 5. Fallback Generic Linux
        return DistroInfo(
            os_type="Linux",
            distro_name=pretty_name,
            distro_id=distro_id or "linux",
            package_family="generic",
            install_prefix="sudo apt install -y",
        )


# ==============================================================================
# 2. TOOL DEFINITIONS & REGISTRY
# ==============================================================================
@dataclass
class ToolDefinition:
    """Metadata, package mapping, and command builder for a security tool."""
    name: str
    binary: str
    category: str
    description: str
    required: bool
    packages: Dict[str, str] = field(default_factory=dict)
    fallback_install: str = ""

    def get_install_command(self, distro: DistroInfo) -> str:
        """Derive the precise installation command for the detected OS."""
        family = distro.package_family
        if family in self.packages:
            pkg = self.packages[family]
            if pkg.startswith("go install") or pkg.startswith("curl") or pkg.startswith("cargo"):
                return pkg
            return f"{distro.install_prefix} {pkg}"
        if self.fallback_install:
            return self.fallback_install
        return f"{distro.install_prefix} {self.binary}"

    def is_installed(self) -> bool:
        """Check if binary is accessible via PATH."""
        return shutil.which(self.binary) is not None

    def resolved_path(self) -> Optional[str]:
        """Return the absolute path of the binary if found."""
        return shutil.which(self.binary)


# Registry of core CLI security tools
TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    "nmap": ToolDefinition(
        name="Nmap",
        binary="nmap",
        category="Scanning",
        description="Network exploration tool and security / port scanner",
        required=True,
        packages={
            "apt": "nmap",
            "pacman": "nmap",
            "dnf": "nmap",
            "apk": "nmap",
            "brew": "nmap",
            "windows": "Insecure.Nmap",
        },
        fallback_install="sudo apt install -y nmap",
    ),
    "feroxbuster": ToolDefinition(
        name="Feroxbuster",
        binary="feroxbuster",
        category="Scanning",
        description="Fast, recursive web content and directory discovery in Rust",
        required=True,
        packages={
            "apt": "feroxbuster",
            "pacman": "feroxbuster",
            "brew": "feroxbuster",
            "windows": "cargo install feroxbuster",
        },
        fallback_install="curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash",
    ),
    "ffuf": ToolDefinition(
        name="ffuf",
        binary="ffuf",
        category="Scanning",
        description="Fast web fuzzer written in Go for paths and parameters",
        required=True,
        packages={
            "apt": "ffuf",
            "pacman": "ffuf",
            "dnf": "golang-github-ffuf-ffuf",
            "brew": "ffuf",
            "windows": "go install github.com/ffuf/ffuf/v2@latest",
        },
        fallback_install="go install github.com/ffuf/ffuf/v2@latest",
    ),
    "subfinder": ToolDefinition(
        name="Subfinder",
        binary="subfinder",
        category="Recon",
        description="Fast passive subdomain enumeration tool using public OSINT",
        required=False,
        packages={
            "apt": "subfinder",
            "pacman": "subfinder",
            "brew": "subfinder",
            "generic": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        fallback_install="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "nuclei": ToolDefinition(
        name="Nuclei",
        binary="nuclei",
        category="Exploit",
        description="Fast and customizable vulnerability scanner based on simple YAML DSL",
        required=False,
        packages={
            "apt": "nuclei",
            "pacman": "nuclei",
            "brew": "nuclei",
            "generic": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        fallback_install="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    "whois": ToolDefinition(
        name="Whois",
        binary="whois",
        category="Recon",
        description="Client for the WHOIS protocol to query domain registrar records",
        required=False,
        packages={
            "apt": "whois",
            "pacman": "whois",
            "dnf": "whois",
            "apk": "whois",
            "brew": "whois",
        },
        fallback_install="sudo apt install -y whois",
    ),
}

# ==============================================================================
# HOW TO ADD NEW TOOLS:
# ------------------------------------------------------------------------------
# 1. Add an entry to TOOL_REGISTRY with the tool name, binary name, category,
#    and package manager mapping.
# 2. Add safe command builders in `CommandFactory.build()` below.
# 3. The PrerequisiteChecker and AsyncProcessEngine will automatically handle
#    path resolution, missing alerts, and streaming execution!
# ==============================================================================


# ==============================================================================
# 3. PREREQUISITE CHECKER ENGINE
# ==============================================================================
@dataclass
class ToolStatus:
    """Status check result for a single tool."""
    tool: ToolDefinition
    installed: bool
    path: Optional[str]
    install_command: str


@dataclass
class PrerequisiteReport:
    """Comprehensive environment prerequisite report."""
    distro: DistroInfo
    statuses: List[ToolStatus]
    all_required_present: bool
    missing_required: List[ToolStatus]
    missing_optional: List[ToolStatus]

    def generate_install_all_script(self) -> str:
        """Create a single one-liner command to install all missing tools."""
        missing = self.missing_required + self.missing_optional
        if not missing:
            return "# All tools are already installed on PATH!"

        # Combine standard package manager commands where possible
        pkgs = []
        custom_cmds = []
        for s in missing:
            cmd = s.install_command
            if cmd.startswith(self.distro.install_prefix):
                pkg_name = cmd[len(self.distro.install_prefix):].strip()
                pkgs.append(pkg_name)
            else:
                custom_cmds.append(cmd)

        commands = []
        if pkgs:
            commands.append(f"{self.distro.install_prefix} {' '.join(pkgs)}")
        commands.extend(custom_cmds)

        return " && ".join(commands)


class PrerequisiteChecker:
    """Validates tool readiness across the host system."""

    @classmethod
    def run_check(cls, distro: Optional[DistroInfo] = None) -> PrerequisiteReport:
        distro = distro or DistroDetector.detect()
        statuses: List[ToolStatus] = []
        missing_req: List[ToolStatus] = []
        missing_opt: List[ToolStatus] = []

        for tool in TOOL_REGISTRY.values():
            installed = tool.is_installed()
            path = tool.resolved_path()
            install_cmd = tool.get_install_command(distro)

            status = ToolStatus(
                tool=tool,
                installed=installed,
                path=path,
                install_command=install_cmd,
            )
            statuses.append(status)

            if not installed:
                if tool.required:
                    missing_req.append(status)
                else:
                    missing_opt.append(status)

        return PrerequisiteReport(
            distro=distro,
            statuses=statuses,
            all_required_present=len(missing_req) == 0,
            missing_required=missing_req,
            missing_optional=missing_opt,
        )


# ==============================================================================
# 4. SECURE COMMAND VECTOR BUILDER
# ==============================================================================
class CommandFactory:
    """
    Constructs discrete argument vectors (List[str]) for tools.
    Strictly avoids shell string interpolation to prevent injection vulnerabilities.
    """

    IP_OR_HOST_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|"  # FQDN
        r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|"                                  # IPv4 or CIDR
        r"^[a-fA-F0-9:]+$"                                                          # IPv6
    )

    @classmethod
    def sanitize_target(cls, target: Optional[str]) -> str:
        """Validate target format against injection characters and uninitialized state."""
        if not target or target.strip() in ("Not Set", "None", ""):
            raise ValueError("Target scope is not set. Please set a target first (e.g., 'set target <IP/Domain>').")
        clean = target.strip()
        # Disallow dangerous shell metacharacters
        if any(c in clean for c in (";", "&", "|", "`", "$", "(", ")", "{", "}", "\n", "\r", "<", ">")):
            raise ValueError(f"Invalid characters detected in target scope: '{target}'")
        return clean

    @classmethod
    def build(cls, raw_command: str, target: str) -> Tuple[List[str], str]:
        """
        Build safe command vector and identify binary name.
        Returns: (command_vector, binary_name)
        """
        clean_target = cls.sanitize_target(target)
        parts = shlex.split(raw_command)
        if not parts:
            raise ValueError("Empty command string provided.")

        action = parts[0].lower()

        # Handle 'run <tool>' or direct '<tool>'
        if action == "run" and len(parts) >= 2:
            sub = parts[1].lower()
            remaining_args = parts[2:]
        else:
            sub = action
            remaining_args = parts[1:]

        # Map predefined shorthand actions to argument vectors
        if sub in ("nmap-quick", "nmap"):
            return ["nmap", "-sV", "-T4", "--top-ports", "100", clean_target, *remaining_args], "nmap"

        elif sub == "nmap-full":
            return ["nmap", "-sV", "-p-", "-T4", clean_target, *remaining_args], "nmap"

        elif sub in ("feroxbuster", "ferox-depth"):
            url = f"http://{clean_target}/" if not clean_target.startswith("http") else clean_target
            return ["feroxbuster", "-u", url, "-k", "-e", *remaining_args], "feroxbuster"

        elif sub in ("ffuf-dirs", "ffuf"):
            url = f"http://{clean_target}/FUZZ" if not clean_target.startswith("http") else f"{clean_target}/FUZZ"
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not Path(wordlist).exists():
                wordlist = "/usr/share/wordlists/dirb/common.txt"
            return ["ffuf", "-u", url, "-w", wordlist, *remaining_args], "ffuf"

        elif sub == "ffuf-params":
            url = f"http://{clean_target}/?FUZZ=test"
            wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
            return ["ffuf", "-u", url, "-w", wordlist, *remaining_args], "ffuf"

        elif sub == "subfinder":
            return ["subfinder", "-d", clean_target, *remaining_args], "subfinder"

        elif sub in ("nuclei-cve", "nuclei"):
            url = f"http://{clean_target}/" if not clean_target.startswith("http") else clean_target
            return ["nuclei", "-u", url, "-tags", "cve", *remaining_args], "nuclei"

        elif sub == "nuclei-tech":
            url = f"http://{clean_target}/" if not clean_target.startswith("http") else clean_target
            return ["nuclei", "-u", url, "-tags", "tech", *remaining_args], "nuclei"

        elif sub == "whois-lookup":
            return ["whois", clean_target, *remaining_args], "whois"

        elif sub == "ping":
            param = "-n" if platform.system() == "Windows" else "-c"
            return ["ping", param, "3", clean_target], "ping"

        # Direct binary execution fallback with target appended if not present
        args = [sub, *remaining_args]
        if clean_target not in args:
            args.append(clean_target)
        return args, sub


# ==============================================================================
# 5. ASYNCHRONOUS SUBPROCESS EXECUTION ENGINE
# ==============================================================================
class AsyncProcessEngine:
    """
    Non-blocking subprocess runner. Streams stdout and stderr in real-time
    without blocking Textual UI responsiveness.
    """

    def __init__(self) -> None:
        self.active_process: Optional[asyncio.subprocess.Process] = None
        self.is_running: bool = False
        self._cancel_requested: bool = False

    async def execute_stream(
        self,
        cmd_args: List[str],
        line_callback: Callable[[str], None],
        cwd: Optional[Path] = None,
    ) -> int:
        """
        Execute command asynchronously and stream output line-by-line to the callback.
        Returns: Process exit code.
        """
        self.is_running = True
        self._cancel_requested = False

        try:
            line_callback(f"[bold #ffb000][*] Spawning subprocess:[/] [dim]{' '.join(shlex.quote(c) for c in cmd_args)}[/]")

            # Spawn process without shell=True for injection safety
            self.active_process = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(cwd) if cwd else None,
            )

            # Stream stdout/stderr in real-time
            assert self.active_process.stdout is not None
            while True:
                line_bytes = await self.active_process.stdout.readline()
                if not line_bytes:
                    break

                line_str = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
                if line_str:
                    line_callback(line_str)

            exit_code = await self.active_process.wait()

            if self._cancel_requested:
                line_callback("[bold #ef4444][!] Process terminated by user intervention.[/]")
                return -1

            if exit_code == 0:
                line_callback(f"[bold #22c55e][+] Process completed successfully (exit code 0).[/]")
            else:
                line_callback(f"[bold #ef4444][!] Process exited with non-zero status code: {exit_code}[/]")

            return exit_code

        except asyncio.CancelledError:
            await self.terminate()
            line_callback("[bold #ef4444][!] Asynchronous execution cancelled.[/]")
            return -1
        except Exception as exc:
            line_callback(f"[bold #ef4444][!] Subprocess execution error: {exc}[/]")
            return 1
        finally:
            self.is_running = False
            self.active_process = None

    async def terminate(self) -> None:
        """Safely terminate the currently active process."""
        self._cancel_requested = True
        if self.active_process and self.active_process.returncode is None:
            try:
                self.active_process.terminate()
                await asyncio.sleep(0.2)
                if self.active_process.returncode is None:
                    self.active_process.kill()
            except ProcessLookupError:
                pass
