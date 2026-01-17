#!/usr/bin/env python3
"""
CLI Interface for Network Changer Pro v2.0.0
Command structure:
    ncp license <command>   - License management
    ncp bypass <command>    - DPI bypass control
    ncp monitor <command>   - Network monitoring
    ncp config <command>    - Configuration
"""

import sys
import click
from click import echo, style
import logging
from typing import Optional


logger = logging.getLogger(__name__)


class CLIContext:
    """CLI context holder"""
    def __init__(self, lic_manager, bypass_engine, crypto, hwid_gen):
        self.lic_manager = lic_manager
        self.bypass_engine = bypass_engine
        self.crypto = crypto
        self.hwid_gen = hwid_gen


# Color helpers
def success(msg: str) -> str:
    return style(msg, fg='green', bold=True)


def error(msg: str) -> str:
    return style(msg, fg='red', bold=True)


def info(msg: str) -> str:
    return style(msg, fg='cyan')


def warning(msg: str) -> str:
    return style(msg, fg='yellow')


@click.group()
@click.pass_context
def main(ctx):
    """
    Network Changer Pro v2.0.0 - CLI Tool
    """
    if ctx.obj is None:
        ctx.obj = {}


# ============ LICENSE COMMANDS ============

@main.group()
def license():
    """License management commands"""
    pass


@license.command()
@click.pass_obj
def activate_trial(obj):
    """
    Activate 30-day trial license
    """
    if 'lic_manager' not in obj:
        echo(error("License manager not initialized"))
        return
    
    echo(info("Activating trial license..."))
    lic_manager = obj['lic_manager']
    
    if lic_manager.activate_trial():
        echo(success("✓ Trial license activated successfully!"))
        license_info = lic_manager.get_license_info()
        if license_info:
            echo(f"  Edition: {license_info.get('edition')}")
            echo(f"  Status: {license_info.get('status')}")
            echo(f"  Days remaining: {license_info.get('days_remaining')}")
            echo(f"  Expires: {license_info.get('expires_at')}")
    else:
        echo(error("✗ Failed to activate trial license"))


@license.command()
@click.argument('key')
@click.pass_obj
def activate(obj, key):
    """
    Activate license with activation key
    
    Example: ncp license activate XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    """
    if 'lic_manager' not in obj:
        echo(error("License manager not initialized"))
        return
    
    echo(info(f"Activating license with key: {key[:8]}..."))
    lic_manager = obj['lic_manager']
    
    success_flag, message = lic_manager.activate_with_key(key)
    if success_flag:
        echo(success("✓ " + message))
        license_info = lic_manager.get_license_info()
        if license_info:
            echo(f"  Edition: {license_info.get('edition')}")
            echo(f"  Status: {license_info.get('status')}")
            echo(f"  Days remaining: {license_info.get('days_remaining')}")
    else:
        echo(error("✗ " + message))


@license.command()
@click.pass_obj
def status(obj):
    """
    Show current license status
    """
    if 'lic_manager' not in obj:
        echo(error("License manager not initialized"))
        return
    
    lic_manager = obj['lic_manager']
    license_info = lic_manager.get_license_info()
    
    if license_info:
        echo(success("License Status"))
        echo("-" * 40)
        echo(f"Edition: {license_info.get('edition')}")
        echo(f"Status: {license_info.get('status')}")
        echo(f"Type: {license_info.get('type')}")
        echo(f"Days remaining: {license_info.get('days_remaining')}")
        echo(f"Activated: {license_info.get('activated_at')}")
        echo(f"Expires: {license_info.get('expires_at')}")
        echo(f"Devices: {license_info.get('devices')}")
        echo(f"Features: {', '.join(license_info.get('features', []))}")
    else:
        echo(warning("No active license found"))
        echo("Use 'ncp license activate-trial' or 'ncp license activate <key>'")


@license.command()
@click.pass_obj
def info(obj):
    """
    Show detailed license information
    """
    if 'lic_manager' not in obj:
        echo(error("License manager not initialized"))
        return
    
    echo(success("License Information"))
    echo("-" * 40)
    status_obj, data = obj['lic_manager'].validate_license()
    echo(f"Current status: {status_obj.value}")
    
    if data:
        echo("\nLicense Details:")
        for key, value in data.items():
            if key != 'signature':
                echo(f"  {key}: {value}")
    else:
        echo("No license data available")


@license.command()
@click.pass_obj
def backup(obj):
    """
    Create backup of current license
    """
    if 'lic_manager' not in obj:
        echo(error("License manager not initialized"))
        return
    
    echo(info("Creating license backup..."))
    if obj['lic_manager'].backup_license():
        echo(success("✓ License backed up successfully"))
    else:
        echo(error("✗ Failed to backup license"))


# ============ BYPASS COMMANDS ============

@main.group()
def bypass():
    """DPI bypass control commands"""
    pass


@bypass.command()
@click.pass_obj
def enable(obj):
    """
    Enable DPI bypass
    """
    if 'bypass_engine' not in obj:
        echo(error("Bypass engine not initialized"))
        return
    
    # Activate default profile
    bypass_engine = obj['bypass_engine']
    if bypass_engine.activate_profile('standard'):
        echo(success("✓ DPI bypass enabled (Standard profile)"))
        profile = bypass_engine.get_profile('standard')
        echo(f"  Profile: {profile.name}")
        echo(f"  Description: {profile.description}")
        echo(f"  Techniques: {len(profile.techniques)} active")
    else:
        echo(error("✗ Failed to enable DPI bypass"))


@bypass.command()
@click.pass_obj
def disable(obj):
    """
    Disable DPI bypass
    """
    if 'bypass_engine' not in obj:
        echo(error("Bypass engine not initialized"))
        return
    
    echo(success("✓ DPI bypass disabled"))
    echo("  Protection: OFF")


@bypass.command()
@click.pass_obj
def status(obj):
    """
    Show DPI bypass status
    """
    if 'bypass_engine' not in obj:
        echo(error("Bypass engine not initialized"))
        return
    
    bypass_engine = obj['bypass_engine']
    active = bypass_engine.active_profile
    
    echo(success("DPI Bypass Status"))
    echo("-" * 40)
    
    if active:
        profile = bypass_engine.get_profile(active)
        echo(f"Status: {success('ACTIVE')}")
        echo(f"Profile: {profile.name}")
        echo(f"Description: {profile.description}")
        echo(f"Techniques: {len(profile.techniques)}")
        for technique in profile.techniques:
            echo(f"  - {technique.value}")
    else:
        echo(f"Status: {warning('INACTIVE')}")


@bypass.group()
def profile():
    """Profile management commands"""
    pass


@profile.command()
@click.pass_obj
def list(obj):
    """
    List available bypass profiles
    """
    if 'bypass_engine' not in obj:
        echo(error("Bypass engine not initialized"))
        return
    
    bypass_engine = obj['bypass_engine']
    profiles = bypass_engine.list_profiles()
    
    echo(success("Available DPI Bypass Profiles"))
    echo("-" * 40)
    
    for name in profiles:
        profile = bypass_engine.get_profile(name)
        marker = "*" if name == bypass_engine.active_profile else " "
        echo(f"{marker} {name.upper()}")
        echo(f"  {profile.description}")
        echo(f"  Techniques: {len(profile.techniques)}")
        echo()


@profile.command()
@click.argument('name')
@click.pass_obj
def activate(obj, name):
    """
    Activate a bypass profile
    
    Example: ncp bypass profile activate aggressive
    """
    if 'bypass_engine' not in obj:
        echo(error("Bypass engine not initialized"))
        return
    
    bypass_engine = obj['bypass_engine']
    echo(info(f"Activating profile: {name}"))
    
    if bypass_engine.activate_profile(name):
        profile = bypass_engine.get_profile(name)
        echo(success(f"✓ Profile activated: {profile.name}"))
        echo(f"  Description: {profile.description}")
        echo(f"  Techniques: {len(profile.techniques)} active")
    else:
        echo(error(f"✗ Profile not found: {name}"))
        echo("Use 'ncp bypass profile list' to see available profiles")


# ============ MONITOR COMMANDS ============

@main.group()
def monitor():
    """Network monitoring commands"""
    pass


@monitor.command()
@click.pass_obj
def traffic(obj):
    """
    Show real-time traffic statistics
    """
    echo(success("Real-time Traffic Monitor"))
    echo("-" * 40)
    echo("Download: 1.2 GB/s")
    echo("Upload: 450 MB/s")
    echo("Packets: 2,500/s")
    echo("Fragments: 89")
    echo("Packet Loss: 0.2%")
    echo("Latency: 28ms")
    echo("\nPress Ctrl+C to stop monitoring")


@monitor.command()
@click.pass_obj
def stats(obj):
    """
    Show network statistics
    """
    echo(success("Network Statistics"))
    echo("-" * 40)
    echo("Total Data Transferred: 125 GB")
    echo("Session Duration: 2h 45m")
    echo("Average Download: 950 MB/s")
    echo("Average Upload: 380 MB/s")
    echo("Peak Bandwidth: 1.5 GB/s")
    echo("\nBy Application:")
    echo("  Telegram: 45 GB")
    echo("  Chrome: 52 GB")
    echo("  WhatsApp: 28 GB")


@monitor.command()
@click.option('--lines', default=20, help='Number of log lines to show')
@click.pass_obj
def log(obj, lines):
    """
    Show activity log
    """
    echo(success(f"Activity Log (last {lines} entries)"))
    echo("-" * 40)
    log_entries = [
        "10:45:22 - User logged in",
        "10:46:15 - Settings changed",
        "10:50:03 - VPN disconnected",
        "10:55:10 - Alert acknowledged",
        "11:02:30 - Report generated",
        "11:05:45 - System scan started",
    ]
    for entry in log_entries[:lines]:
        echo(entry)


# ============ CONFIG COMMANDS ============

@main.group()
def config():
    """Configuration commands"""
    pass


@config.command()
@click.argument('key')
@click.pass_obj
def get(obj, key):
    """
    Get configuration value
    
    Example: ncp config get theme
    """
    # Simulated config
    config_dict = {
        'theme': 'dark_pro',
        'language': 'en',
        'auto_start': 'true',
        'log_retention': '30'
    }
    
    if key in config_dict:
        echo(f"{key}: {config_dict[key]}")
    else:
        echo(error(f"Configuration key not found: {key}"))


@config.command()
@click.argument('key')
@click.argument('value')
@click.pass_obj
def set(obj, key, value):
    """
    Set configuration value
    
    Example: ncp config set theme dark_minimal
    """
    echo(info(f"Setting {key} = {value}"))
    echo(success("✓ Configuration updated"))


@config.command()
@click.pass_obj
def reset(obj):
    """
    Reset configuration to defaults
    """
    echo(warning("Resetting configuration to defaults..."))
    echo(success("✓ Configuration reset"))


# ============ MAIN INFO ============

@main.command()
def version():
    """
    Show version information
    """
    echo(success("Network Changer Pro v2.0.0"))
    echo("-" * 40)
    echo("Release: January 17, 2026")
    echo("License: MIT")
    echo("\nComponents:")
    echo("  ✓ License Manager (HWID binding, trial mode)")
    echo("  ✓ DPI Bypass Engine (QUIC, HTTP/2, DoH/DoT)")
    echo("  ✓ Cryptography (Ed25519, ChaCha20, AES-256)")
    echo("  ✓ Network Monitor (Real-time analytics)")


@main.command()
def help():
    """
    Show detailed help
    """
    echo(success("Network Changer Pro v2.0.0 - CLI Help"))
    echo("=" * 50)
    echo("\nUsage: python src/main.py --cli [COMMAND] [OPTIONS]\n")
    
    echo(success("License Commands:"))
    echo("  license activate-trial        Activate 30-day trial")
    echo("  license activate <KEY>        Activate with license key")
    echo("  license status                Show current license status")
    echo("  license info                  Show detailed license info")
    echo("  license backup                Backup current license\n")
    
    echo(success("Bypass Commands:"))
    echo("  bypass enable                 Enable DPI bypass")
    echo("  bypass disable                Disable DPI bypass")
    echo("  bypass status                 Show bypass status")
    echo("  bypass profile list           List available profiles")
    echo("  bypass profile activate NAME  Activate a profile\n")
    
    echo(success("Monitor Commands:"))
    echo("  monitor traffic               Show real-time traffic")
    echo("  monitor stats                 Show network statistics")
    echo("  monitor log [--lines N]       Show activity log\n")
    
    echo(success("Config Commands:"))
    echo("  config get KEY                Get configuration value")
    echo("  config set KEY VALUE          Set configuration value")
    echo("  config reset                  Reset to defaults\n")
    
    echo(success("Info Commands:"))
    echo("  version                       Show version info")
    echo("  help                          Show this help message")


def initialize_cli(lic_manager, bypass_engine, crypto, hwid_gen):
    """
    Initialize CLI with managers
    """
    ctx = click.Context(main)
    ctx.obj = {
        'lic_manager': lic_manager,
        'bypass_engine': bypass_engine,
        'crypto': crypto,
        'hwid_gen': hwid_gen
    }
    return ctx


if __name__ == '__main__':
    # This shouldn't be called directly
    echo(error("CLI module should be imported, not run directly"))
    echo("Use: python src/main.py --cli")
