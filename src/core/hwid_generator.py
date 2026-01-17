"""
Hardware ID Generator for Network Changer Pro v2.0.0
Generates unique HWID from:
- MAC Address (48-bit)
- CPU Processor ID (variable)
- OS UUID (128-bit)
- Installation Date (timestamp)
- Disk Serial (variable)
"""

import hashlib
import uuid
import platform
import socket
import subprocess
import json
import os
from typing import Dict, Optional, Tuple
from datetime import datetime
import logging

try:
    import psutil
except ImportError:
    psutil = None


logger = logging.getLogger(__name__)


class HWIDGenerator:
    """
    Hardware ID generator for license binding
    Generates 96-bit (12-byte) unique identifier from system components
    """
    
    def __init__(self):
        """Initialize HWID generator"""
        self.system = platform.system()
    
    # ============ MAC Address ============
    
    def get_mac_address(self) -> Optional[str]:
        """
        Get primary network interface MAC address
        
        Returns:
            MAC address string (format: XX:XX:XX:XX:XX:XX)
        """
        try:
            mac = uuid.getnode()
            if mac != uuid.DUMMY_NODE_ID:
                mac_str = ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))
                return mac_str.upper()
        except Exception as e:
            logger.warning(f"Failed to get MAC address: {e}")
        
        return None
    
    def get_mac_address_list(self) -> list:
        """
        Get list of all MAC addresses
        
        Returns:
            List of MAC addresses
        """
        mac_list = []
        try:
            if psutil:
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == 18:  # AF_LINK (MAC address)
                            mac_list.append(addr.address.upper())
        except Exception as e:
            logger.warning(f"Failed to get MAC address list: {e}")
        
        return mac_list
    
    # ============ CPU Processor ID ============
    
    def get_cpu_id(self) -> Optional[str]:
        """
        Get CPU processor ID
        
        Returns:
            CPU model name (e.g., "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz")
        """
        try:
            if psutil:
                # Get CPU model from /proc/cpuinfo on Linux
                if self.system == "Linux":
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if line.startswith('model name'):
                                return line.split(':', 1)[1].strip()
                
                # Fallback to psutil
                return platform.processor()
        except Exception as e:
            logger.warning(f"Failed to get CPU ID: {e}")
        
        return platform.processor() or "Unknown"
    
    def get_cpu_count(self) -> int:
        """
        Get number of CPU cores
        
        Returns:
            Number of physical CPU cores
        """
        try:
            if psutil:
                return psutil.cpu_count(logical=False) or 1
        except Exception:
            pass
        
        return os.cpu_count() or 1
    
    # ============ OS UUID ============
    
    def get_os_uuid(self) -> str:
        """
        Get OS-specific unique identifier
        
        Windows: Machine GUID from registry (HKLM\Software\Microsoft\Cryptography)
        Linux: /etc/machine-id
        macOS: Hardware UUID from IOPlatformUUID
        
        Returns:
            OS UUID string
        """
        try:
            if self.system == "Windows":
                return self._get_windows_machine_guid()
            elif self.system == "Linux":
                return self._get_linux_machine_id()
            elif self.system == "Darwin":
                return self._get_macos_hardware_uuid()
        except Exception as e:
            logger.warning(f"Failed to get OS UUID: {e}")
        
        # Fallback to Python's UUID
        return str(uuid.getnode())
    
    @staticmethod
    def _get_windows_machine_guid() -> str:
        """
        Get Windows Machine GUID from registry
        
        Returns:
            Machine GUID
        """
        try:
            import winreg
            reg_path = r"Software\Microsoft\Cryptography"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                return machine_guid
        except Exception as e:
            logger.warning(f"Failed to read Windows GUID from registry: {e}")
            return str(uuid.uuid4())
    
    @staticmethod
    def _get_linux_machine_id() -> str:
        """
        Get Linux machine ID
        
        Returns:
            Machine ID from /etc/machine-id
        """
        try:
            with open('/etc/machine-id', 'r') as f:
                return f.read().strip()
        except Exception as e:
            logger.warning(f"Failed to read Linux machine ID: {e}")
            return str(uuid.uuid4())
    
    @staticmethod
    def _get_macos_hardware_uuid() -> str:
        """
        Get macOS Hardware UUID
        
        Returns:
            Hardware UUID
        """
        try:
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.split('\n'):
                if 'IOPlatformUUID' in line:
                    return line.split('"')[1]
        except Exception as e:
            logger.warning(f"Failed to read macOS UUID: {e}")
        
        return str(uuid.uuid4())
    
    # ============ Installation Date ============
    
    def get_installation_date(self) -> str:
        """
        Get OS installation date
        
        Returns:
            ISO format date string (e.g., "2024-01-17")
        """
        try:
            if self.system == "Windows":
                # Get from registry
                import winreg
                reg_path = r"Software\Microsoft\Windows NT\CurrentVersion"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    install_date, _ = winreg.QueryValueEx(key, "InstallDate")
                    return datetime.fromtimestamp(int(install_date)).date().isoformat()
            
            elif self.system == "Linux":
                # Get from /etc creation or /proc/sys/kernel/random/boot_id first access
                try:
                    stat = os.stat('/')
                    return datetime.fromtimestamp(stat.st_ctime).date().isoformat()
                except:
                    pass
            
            elif self.system == "Darwin":
                # Get from filesystem creation
                stat = os.stat('/')
                return datetime.fromtimestamp(stat.st_ctime).date().isoformat()
        except Exception as e:
            logger.warning(f"Failed to get installation date: {e}")
        
        # Fallback to current date
        return datetime.now().date().isoformat()
    
    # ============ Disk Serial ============
    
    def get_disk_serial(self) -> Optional[str]:
        """
        Get primary disk serial number
        
        Returns:
            Disk serial number
        """
        try:
            if self.system == "Windows":
                return self._get_windows_disk_serial()
            elif self.system == "Linux":
                return self._get_linux_disk_serial()
            elif self.system == "Darwin":
                return self._get_macos_disk_serial()
        except Exception as e:
            logger.warning(f"Failed to get disk serial: {e}")
        
        return None
    
    @staticmethod
    def _get_windows_disk_serial() -> Optional[str]:
        """
        Get Windows disk serial
        """
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "serialnumber"],
                capture_output=True,
                text=True
            )
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                return lines[1].strip()
        except Exception:
            pass
        return None
    
    @staticmethod
    def _get_linux_disk_serial() -> Optional[str]:
        """
        Get Linux disk serial
        """
        try:
            result = subprocess.run(
                ["lsblk", "-o", "SERIAL", "-n"],
                capture_output=True,
                text=True
            )
            lines = result.stdout.strip().split('\n')
            if lines:
                return lines[0].strip()
        except Exception:
            pass
        return None
    
    @staticmethod
    def _get_macos_disk_serial() -> Optional[str]:
        """
        Get macOS disk serial
        """
        try:
            result = subprocess.run(
                ["system_profiler", "SPStorageDataType"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.split('\n'):
                if 'Serial Number' in line:
                    return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return None
    
    # ============ HWID Generation ============
    
    def generate_hwid(self, include_timestamp: bool = True) -> str:
        """
        Generate Hardware ID by combining system identifiers
        
        Args:
            include_timestamp: Include current timestamp in HWID
            
        Returns:
            96-bit (24 hex char) HWID
        """
        components = []
        
        # MAC Address (primary identifier)
        mac = self.get_mac_address()
        if mac:
            components.append(mac.replace(':', ''))
        
        # CPU Model
        cpu_id = self.get_cpu_id()
        if cpu_id:
            components.append(cpu_id)
        
        # OS UUID
        os_uuid = self.get_os_uuid()
        if os_uuid:
            components.append(os_uuid)
        
        # Installation Date
        inst_date = self.get_installation_date()
        if inst_date:
            components.append(inst_date)
        
        # Disk Serial (if available)
        disk_serial = self.get_disk_serial()
        if disk_serial:
            components.append(disk_serial)
        
        # Combine all components
        combined = '|'.join(str(c) for c in components)
        
        # Generate SHA256 hash
        hwid_hash = hashlib.sha256(combined.encode()).digest()
        
        # Return first 96 bits (12 bytes) as hex
        return hwid_hash[:12].hex().upper()
    
    def get_hwid_components(self) -> Dict[str, str]:
        """
        Get all HWID components
        
        Returns:
            Dictionary with component details
        """
        return {
            'mac_address': self.get_mac_address() or 'N/A',
            'mac_addresses': self.get_mac_address_list(),
            'cpu_id': self.get_cpu_id() or 'N/A',
            'cpu_count': self.get_cpu_count(),
            'os_uuid': self.get_os_uuid() or 'N/A',
            'installation_date': self.get_installation_date() or 'N/A',
            'disk_serial': self.get_disk_serial() or 'N/A',
            'system': self.system,
            'python_uuid': str(uuid.getnode()),
            'generated_at': datetime.now().isoformat()
        }
    
    def save_hwid_info(self, filepath: str) -> None:
        """
        Save HWID information to JSON file
        
        Args:
            filepath: Path to save HWID info
        """
        info = self.get_hwid_components()
        info['hwid'] = self.generate_hwid()
        
        with open(filepath, 'w') as f:
            json.dump(info, f, indent=2, default=str)
        
        logger.info(f"HWID info saved to {filepath}")


# Export main class
__all__ = ['HWIDGenerator']
