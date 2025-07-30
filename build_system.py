# SConstruct - Main build system configuration
# Flipper Zero Firmware Next - Professional Build System

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

# Add tools directory to Python path
sys.path.insert(0, os.path.join(os.getcwd(), "scripts", "fbt_tools"))

# Import custom build tools
try:
    from fbt_tools import (
        GetFwBuildEnv,
        fw_build_meta,
        assemble_manifest,
        prepare_sdk,
    )
except ImportError as e:
    print(f"Error importing build tools: {e}")
    print("Please run './fbt update' to initialize the build system")
    Exit(1)

# Build configuration
FIRMWARE_ORIGINS = {
    "dev": "Development",
    "rc": "Release Candidate", 
    "release": "Release",
}

DEFAULT_HW_TARGET = 7  # Flipper Zero hardware target

# Command line variables
vars = Variables("site_scons/commandline.scons", ARGUMENTS)
vars.AddVariables(
    # Build configuration
    BoolVariable(
        "DEBUG",
        help="Build with debug information",
        default=True,
    ),
    BoolVariable(
        "COMPACT", 
        help="Build compact firmware (optimized for size)",
        default=False,
    ),
    BoolVariable(
        "VERBOSE",
        help="Verbose build output", 
        default=False,
    ),
    
    # Hardware target
    EnumVariable(
        "TARGET_HW",
        help="Hardware target",
        default=str(DEFAULT_HW_TARGET),
        allowed_values=["7", "18"],
    ),
    
    # Security options
    BoolVariable(
        "ENABLE_SECURITY",
        help="Enable security features",
        default=True,
    ),
    BoolVariable(
        "SECURE_BOOT",
        help="Enable secure boot",
        default=True,
    ),
    
    # Testing options
    BoolVariable(
        "ENABLE_TESTING",
        help="Enable testing framework",
        default=False,
    ),
    
    # Application configuration
    PathVariable(
        "APPSRC",
        help="Application source directory",
        default="",
        validator=PathVariable.PathAccept,
    ),
    
    # Firmware options
    ("DIST_SUFFIX", "Firmware distribution suffix", ""),
    ("FIRMWARE_ORIGIN", "Firmware origin", "dev"),
    ("COPRO_OB_DATA", "Coprocessor option bytes data", ""),
    
    # Advanced options
    BoolVariable(
        "FORCE",
        help="Force operation", 
        default=False,
    ),
    BoolVariable(
        "FBT_NO_SYNC",
        help="Don't sync git submodules",
        default=False,
    ),
)

# Create build environment
firmware_env = GetFwBuildEnv(vars)

# Help text
Help(vars.GenerateHelpText(firmware_env))

# Validate configuration
def validate_build_config(env):
    """Validate build configuration and show warnings for incompatible options."""
    
    if env["COMPACT"] and env["DEBUG"]:
        print("⚠️  Warning: COMPACT and DEBUG are both enabled")
        print("   This may result in larger firmware size than expected")
    
    if env["ENABLE_SECURITY"] and env["DEBUG"]:
        print("ℹ️  Info: Security features enabled in debug build")
        print("   Some security checks may be relaxed for debugging")
    
    # Check target hardware
    target_hw = int(env["TARGET_HW"])
    if target_hw not in [7, 18]:
        print(f"❌ Error: Unsupported hardware target: {target_hw}")
        Exit(1)

validate_build_config(firmware_env)

# Build metadata
build_meta = fw_build_meta.get_metadata(
    firmware_env,
    build_type="firmware",
    custom_vars=vars.keys(),
)

# Export build environment for sub-builds
Export("firmware_env", "build_meta")

# Set up build directories
firmware_env.VariantDir("build/firmware", "firmware", duplicate=False)
firmware_env.VariantDir("build/core", "core", duplicate=False)
firmware_env.VariantDir("build/lib", "lib", duplicate=False)

# Include platform-specific build scripts
platform_scons = f"firmware/targets/f{firmware_env['TARGET_HW']}/SConscript"
if os.path.exists(platform_scons):
    firmware_env.SConscript(platform_scons)
else:
    print(f"❌ Error: Platform build script not found: {platform_scons}")
    Exit(1)

# Core firmware build
core_libs = firmware_env.SConscript(
    "core/SConscript",
    variant_dir="build/core",
    duplicate=False,
)

# External libraries
external_libs = firmware_env.SConscript(
    "lib/SConscript", 
    variant_dir="build/lib",
    duplicate=False,
)

# Applications
app_artifacts = firmware_env.SConscript(
    "applications/SConscript",
    variant_dir="build/applications",
    duplicate=False,
)

# Testing framework
if firmware_env["ENABLE_TESTING"]:
    test_artifacts = firmware_env.SConscript(
        "tests/SConscript",
        variant_dir="build/tests", 
        duplicate=False,
    )

# Security framework
if firmware_env["ENABLE_SECURITY"]:
    security_artifacts = firmware_env.SConscript(
        "security/SConscript",
        variant_dir="build/security",
        duplicate=False,
    )

# Default targets
Default([
    firmware_env["FW_BIN"],
    firmware_env["FW_HEX"], 
    firmware_env["FW_ELF"],
])

---

#!/usr/bin/env python3
"""
fbt - Flipper Build Tool
Professional build system for Flipper Zero Firmware Next

This script provides a unified interface for building, flashing, testing,
and managing the Flipper Zero firmware with enterprise-grade features.
"""

import os
import sys
import argparse
import subprocess
import shutil
import json
import time
import signal
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Ensure we're running with Python 3.8+
if sys.version_info < (3, 8):
    print("❌ Error: Python 3.8 or higher is required")
    sys.exit(1)

# Project configuration
PROJECT_ROOT = Path(__file__).parent.absolute()
BUILD_DIR = PROJECT_ROOT / "build"
DIST_DIR = PROJECT_ROOT / "dist"
TOOLCHAIN_DIR = PROJECT_ROOT / "toolchain"

# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color

@dataclass
class BuildConfig:
    """Build configuration container."""
    target_hw: str = "7"
    debug: bool = True
    compact: bool = False
    verbose: bool = False
    enable_security: bool = True
    secure_boot: bool = True
    enable_testing: bool = False
    dist_suffix: str = ""
    firmware_origin: str = "dev"
    force: bool = False
    jobs: int = 0  # 0 means auto-detect

class FBT:
    """Main Flipper Build Tool class."""
    
    def __init__(self):
        self.config = BuildConfig()
        self.start_time = time.time()
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _signal_handler(self, sig, frame):
        """Handle interrupt signals."""
        print(f"\n{Colors.YELLOW}⚠️  Build interrupted by user{Colors.NC}")
        sys.exit(130)
    
    def _print_header(self, message: str):
        """Print a formatted header."""
        print(f"\n{Colors.PURPLE}{'='*50}{Colors.NC}")
        print(f"{Colors.PURPLE}{message.center(50)}{Colors.NC}")
        print(f"{Colors.PURPLE}{'='*50}{Colors.NC}\n")
    
    def _print_success(self, message: str):
        """Print a success message."""
        print(f"{Colors.GREEN}✅ {message}{Colors.NC}")
    
    def _print_error(self, message: str):
        """Print an error message."""
        print(f"{Colors.RED}❌ {message}{Colors.NC}")
    
    def _print_warning(self, message: str):
        """Print a warning message."""
        print(f"{Colors.YELLOW}⚠️  {message}{Colors.NC}")
    
    def _print_info(self, message: str):
        """Print an info message."""
        print(f"{Colors.BLUE}ℹ️  {message}{Colors.NC}")
    
    def _run_command(self, cmd: List[str], **kwargs) -> Tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        if self.config.verbose:
            print(f"{Colors.CYAN}Running: {' '.join(cmd)}{Colors.NC}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                **kwargs
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError:
            return 1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return 1, "", str(e)
    
    def _check_prerequisites(self) -> bool:
        """Check if all prerequisites are met."""
        self._print_header("Checking Prerequisites")
        
        prerequisites = [
            ("python3", "Python 3.8+"),
            ("git", "Git version control"),
            ("arm-none-eabi-gcc", "ARM GCC toolchain"),
        ]
        
        missing = []
        for cmd, desc in prerequisites:
            returncode, _, _ = self._run_command(["which", cmd])
            if returncode == 0:
                self._print_success(f"{desc} found")
            else:
                self._print_error(f"{desc} not found")
                missing.append(desc)
        
        if missing:
            self._print_error("Missing prerequisites:")
            for item in missing:
                print(f"  - {item}")
            print(f"\n{Colors.YELLOW}Run './scripts/setup.sh' to install missing dependencies{Colors.NC}")
            return False
        
        return True
    
    def _update_submodules(self) -> bool:
        """Update git submodules."""
        if os.environ.get("FBT_NO_SYNC") == "1":
            self._print_info("Skipping submodule sync (FBT_NO_SYNC=1)")
            return True
        
        self._print_info("Updating git submodules...")
        
        commands = [
            ["git", "submodule", "update", "--init", "--recursive"],
            ["git", "submodule", "sync", "--recursive"],
        ]
        
        for cmd in commands:
            returncode, stdout, stderr = self._run_command(cmd)
            if returncode != 0:
                self._print_error(f"Submodule update failed: {stderr}")
                return False
        
        self._print_success("Submodules updated")
        return True
    
    def _build_scons_command(self, targets: List[str]) -> List[str]:
        """Build the SCons command with current configuration."""
        cmd = ["python3", "-m", "SCons"]
        
        # Add configuration options
        cmd.extend([
            f"TARGET_HW={self.config.target_hw}",
            f"DEBUG={1 if self.config.debug else 0}",
            f"COMPACT={1 if self.config.compact else 0}",
            f"VERBOSE={1 if self.config.verbose else 0}",
            f"ENABLE_SECURITY={1 if self.config.enable_security else 0}",
            f"SECURE_BOOT={1 if self.config.secure_boot else 0}",
            f"ENABLE_TESTING={1 if self.config.enable_testing else 0}",
            f"FORCE={1 if self.config.force else 0}",
        ])
        
        if self.config.dist_suffix:
            cmd.append(f"DIST_SUFFIX={self.config.dist_suffix}")
        
        if self.config.firmware_origin:
            cmd.append(f"FIRMWARE_ORIGIN={self.config.firmware_origin}")
        
        # Add job control
        if self.config.jobs > 0:
            cmd.extend(["-j", str(self.config.jobs)])
        
        # Add targets
        cmd.extend(targets)
        
        return cmd
    
    def build(self, targets: Optional[List[str]] = None) -> bool:
        """Build firmware with specified targets."""
        if not self._check_prerequisites():
            return False
        
        if not self._update_submodules():
            return False
        
        self._print_header("Building Firmware")
        
        # Default targets
        if not targets:
            targets = ["firmware_all"]
        
        # Show build configuration
        self._print_info("Build Configuration:")
        print(f"  Target Hardware: f{self.config.target_hw}")
        print(f"  Debug Mode: {self.config.debug}")
        print(f"  Compact Build: {self.config.compact}")
        print(f"  Security Features: {self.config.enable_security}")
        print(f"  Secure Boot: {self.config.secure_boot}")
        print(f"  Testing Framework: {self.config.enable_testing}")
        
        if self.config.dist_suffix:
            print(f"  Distribution Suffix: {self.config.dist_suffix}")
        
        # Build command
        cmd = self._build_scons_command(targets)
        
        # Run build
        self._print_info(f"Building targets: {', '.join(targets)}")
        returncode, stdout, stderr = self._run_command(cmd, cwd=PROJECT_ROOT)
        
        if returncode == 0:
            elapsed = time.time() - self.start_time
            self._print_success(f"Build completed in {elapsed:.1f}s")
            
            # Show build artifacts
            self._print_info("Build artifacts:")
            build_latest = BUILD_DIR / "latest"
            if build_latest.exists():
                for artifact in build_latest.glob("*.{bin,hex,elf}"):
                    size = artifact.stat().st_size
                    print(f"  {artifact.name}: {size:,} bytes")
            
            return True
        else:
            self._print_error("Build failed")
            if stderr:
                print(f"{Colors.RED}{stderr}{Colors.NC}")
            return False
    
    def flash(self, method: str = "swd") -> bool:
        """Flash firmware to device."""
        self._print_header(f"Flashing Firmware ({method.upper()})")
        
        flash_targets = {
            "swd": "flash",
            "usb": "flash_usb", 
            "usb_full": "flash_usb_full",
            "jlink": "jflash",
        }
        
        if method not in flash_targets:
            self._print_error(f"Unknown flash method: {method}")
            return False
        
        target = flash_targets[method]
        cmd = self._build_scons_command([target])
        
        returncode, stdout, stderr = self._run_command(cmd, cwd=PROJECT_ROOT)
        
        if returncode == 0:
            self._print_success(f"Firmware flashed successfully via {method.upper()}")
            return True
        else:
            self._print_error(f"Flash failed: {stderr}")
            return False
    
    def test(self, test_type: str = "all") -> bool:
        """Run tests."""
        self._print_header(f"Running Tests ({test_type})")
        
        test_targets = {
            "all": ["test_unit", "test_integration"],
            "unit": ["test_unit"],
            "integration": ["test_integration"],
            "security": ["test_security"],
            "hardware": ["test_hardware"],
            "coverage": ["test_coverage"],
        }
        
        if test_type not in test_targets:
            self._print_error(f"Unknown test type: {test_type}")
            return False
        
        # Enable testing in configuration
        self.config.enable_testing = True
        
        targets = test_targets[test_type]
        cmd = self._build_scons_command(targets)
        
        returncode, stdout, stderr = self._run_command(cmd, cwd=PROJECT_ROOT)
        
        if returncode == 0:
            self._print_success("Tests passed")
            return True
        else:
            self._print_error(f"Tests failed: {stderr}")
            return False
    
    def lint(self) -> bool:
        """Run code quality checks."""
        self._print_header("Running Code Quality Checks")
        
        cmd = self._build_scons_command(["lint"])
        returncode, stdout, stderr = self._run_command(cmd, cwd=PROJECT_ROOT)
        
        if returncode == 0:
            self._print_success("Code quality checks passed")
            return True
        else:
            self._print_error(f"Code quality checks failed: {stderr}")
            return False
    
    def clean(self) -> bool:
        """Clean build artifacts."""
        self._print_header("Cleaning Build Artifacts")
        
        # Remove build and dist directories
        for directory in [BUILD_DIR, DIST_DIR]:
            if directory.exists():
                self._print_info(f"Removing {directory}")
                shutil.rmtree(directory)
        
        # SCons clean
        cmd = self._build_scons_command(["-c"])
        returncode, stdout, stderr = self._run_command(cmd, cwd=PROJECT_ROOT)
        
        self._print_success("Build artifacts cleaned")
        return True
    
    def update(self) -> bool:
        """Update build system and dependencies."""
        self._print_header("Updating Build System")
        
        # Update submodules
        if not self._update_submodules():
            return False
        
        # Update Python dependencies
        self._print_info("Updating Python dependencies...")
        venv_python = PROJECT_ROOT / "venv" / "bin" / "python"
        
        if venv_python.exists():
            cmd = [str(venv_python), "-m", "pip", "install", "--upgrade", "-r", "requirements-dev.txt"]
            returncode, stdout, stderr = self._run_command(cmd)
            
            if returncode == 0:
                self._print_success("Python dependencies updated")
            else:
                self._print_warning("Failed to update Python dependencies")
        
        self._print_success("Build system updated")
        return True

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Flipper Build Tool - Professional firmware build system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./fbt                           # Build debug firmware
  ./fbt COMPACT=1 DEBUG=0         # Build release firmware
  ./fbt flash                     # Flash via SWD
  ./fbt flash_usb                 # Flash via USB
  ./fbt test                      # Run all tests
  ./fbt test unit                 # Run unit tests only
  ./fbt lint                      # Run code quality checks
  ./fbt clean                     # Clean build artifacts
  ./fbt update                    # Update build system

For more information, visit:
https://github.com/your-username/flipper-zero-firmware-next
        """
    )
    
    # Build configuration
    parser.add_argument("--target-hw", "-t", default="7", choices=["7", "18"],
                       help="Hardware target (default: 7)")
    parser.add_argument("--debug", action="store_true", default=True,
                       help="Build with debug information (default)")
    parser.add_argument("--release", action="store_true",
                       help="Build release version (optimized)")
    parser.add_argument("--compact", action="store_true",
                       help="Build compact firmware (size optimized)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    parser.add_argument("--jobs", "-j", type=int, default=0,
                       help="Number of parallel jobs (0=auto)")
    parser.add_argument("--force", action="store_true",
                       help="Force operation")
    
    # Security options
    parser.add_argument("--no-security", action="store_true",
                       help="Disable security features")
    parser.add_argument("--no-secure-boot", action="store_true", 
                       help="Disable secure boot")
    
    # Commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Build command
    build_parser = subparsers.add_parser("build", help="Build firmware")
    build_parser.add_argument("targets", nargs="*", help="Build targets")
    
    # Flash commands
    flash_parser = subparsers.add_parser("flash", help="Flash firmware via SWD")
    flash_usb_parser = subparsers.add_parser("flash_usb", help="Flash firmware via USB")
    flash_full_parser = subparsers.add_parser("flash_usb_full", help="Flash firmware and resources via USB")
    
    # Test commands
    test_parser = subparsers.add_parser("test", help="Run tests")
    test_parser.add_argument("type", nargs="?", default="all",
                           choices=["all", "unit", "integration", "security", "hardware", "coverage"],
                           help="Test type to run")
    
    # Utility commands
    subparsers.add_parser("lint", help="Run code quality checks")
    subparsers.add_parser("clean", help="Clean build artifacts")
    subparsers.add_parser("update", help="Update build system")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create FBT instance
    fbt = FBT()
    
    # Configure build
    fbt.config.target_hw = args.target_hw
    fbt.config.debug = not args.release and args.debug
    fbt.config.compact = args.compact
    fbt.config.verbose = args.verbose
    fbt.config.force = args.force
    fbt.config.jobs = args.jobs
    fbt.config.enable_security = not args.no_security
    fbt.config.secure_boot = not args.no_secure_boot
    
    # Handle legacy command line arguments
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-") and not hasattr(args, "command"):
        # Legacy mode: ./fbt [scons args]
        cmd = fbt._build_scons_command(sys.argv[1:])
        returncode, stdout, stderr = fbt._run_command(cmd, cwd=PROJECT_ROOT)
        sys.exit(returncode)
    
    # Execute command
    success = True
    
    if args.command == "build" or not args.command:
        success = fbt.build(getattr(args, "targets", None))
    elif args.command == "flash":
        success = fbt.flash("swd")
    elif args.command == "flash_usb":
        success = fbt.flash("usb")
    elif args.command == "flash_usb_full":
        success = fbt.flash("usb_full")
    elif args.command == "test":
        success = fbt.test(args.type)
    elif args.command == "lint":
        success = fbt.lint()
    elif args.command == "clean":
        success = fbt.clean()
    elif args.command == "update":
        success = fbt.update()
    else:
        parser.print_help()
        sys.exit(1)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()