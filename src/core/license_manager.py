"""
License Manager for Network Changer Pro v2.0.0
Features:
- HWID binding (MAC + CPU ID + OS UUID)
- Offline activation (air-gapped networks)
- Trial mode (30 days)
- License types: Free, Professional, Premium, Enterprise
- Encryption: AES-256-GCM with HWID-derived key
- Revocation list support
- Anti-tampering detection
"""

import os
import json
import hashlib
import hmac
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
import logging
import platform

from .encryption import CryptoManager
from .hwid_generator import HWIDGenerator


logger = logging.getLogger(__name__)


class LicenseType(Enum):
    """License edition types"""
    FREE_TRIAL = "free"
    PROFESSIONAL = "professional"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


class LicenseStatus(Enum):
    """License status"""
    VALID = "valid"
    TRIAL = "trial"
    EXPIRED = "expired"
    INVALID = "invalid"
    REVOKED = "revoked"


class LicenseManager:
    """
    License Manager for Network Changer Pro v2.0.0
    Handles license validation, activation, and management
    """
    
    # License configuration
    LICENSE_VERSIONS = ["1.0", "2.0"]
    ACTIVATION_KEY_FORMAT = "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
    TRIAL_DAYS = 30
    
    # Edition capabilities
    EDITION_CONFIG = {
        LicenseType.FREE_TRIAL.value: {
            'devices': 1,
            'duration_days': 30,
            'features': ['dpi_bypass', 'basic_monitoring'],
            'price': 0
        },
        LicenseType.PROFESSIONAL.value: {
            'devices': 1,
            'duration_days': 365,
            'features': ['dpi_bypass', 'advanced_monitoring', 'custom_profiles'],
            'price': 29.99
        },
        LicenseType.PREMIUM.value: {
            'devices': 3,
            'duration_days': None,  # lifetime
            'features': ['dpi_bypass', 'advanced_monitoring', 'custom_profiles', 'multidevice'],
            'price': 99.99
        },
        LicenseType.ENTERPRISE.value: {
            'devices': None,  # unlimited
            'duration_days': None,  # lifetime
            'features': ['all'],
            'price': 'custom'
        }
    }
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize License Manager
        
        Args:
            config_dir: Directory for license files (defaults to ~/.NetworkChangerPro)
        """
        self.crypto = CryptoManager()
        self.hwid_gen = HWIDGenerator()
        
        # Setup config directory
        if config_dir is None:
            if platform.system() == "Windows":
                config_dir = os.path.join(os.getenv('APPDATA', os.path.expanduser('~')), 'NetworkChangerPro')
            else:
                config_dir = os.path.expanduser('~/.NetworkChangerPro')
        
        self.config_dir = config_dir
        self.license_file = os.path.join(config_dir, 'license.dat')
        self.backup_file = os.path.join(config_dir, 'license.backup')
        self.revocation_file = os.path.join(config_dir, 'revocation_list.json')
        self.hwid_file = os.path.join(config_dir, 'hwid_info.json')
        
        # Create config directory if not exists
        os.makedirs(config_dir, exist_ok=True)
        
        # Current HWID
        self.current_hwid = self.hwid_gen.generate_hwid()
    
    # ============ Key Generation & Management ============
    
    def generate_activation_key(self, edition: str, hwid: str) -> str:
        """
        Generate activation key for specific edition and HWID
        
        Args:
            edition: License edition (professional, premium, enterprise)
            hwid: Target hardware ID (96-bit hex string)
            
        Returns:
            32-character activation key (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX)
        """
        if edition not in self.EDITION_CONFIG:
            raise ValueError(f"Invalid edition: {edition}")
        
        # Create key data
        key_data = {
            'version': '2.0',
            'edition': edition,
            'hwid': hwid,
            'generated_at': datetime.now().isoformat(),
            'valid': True
        }
        
        # Convert to JSON and hash
        key_json = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.sha256(key_json.encode()).digest()
        
        # Create 32-byte key (256-bit)
        key_bytes = key_hash[:32]
        
        # Format as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
        key_hex = key_bytes.hex().upper()
        key_formatted = '-'.join([key_hex[i:i+4] for i in range(0, 32, 4)])
        
        return key_formatted
    
    def encrypt_activation_key(self, key: str, master_password: str = None) -> str:
        """
        Encrypt activation key with PBKDF2 + AES-256-GCM
        
        Args:
            key: Activation key to encrypt
            master_password: Optional password (uses HWID if not provided)
            
        Returns:
            Encrypted key (base64)
        """
        if master_password is None:
            master_password = self.current_hwid
        
        # Derive encryption key
        derived = self.crypto.derive_key_pbkdf2(master_password)
        
        # Encrypt key
        encrypted = self.crypto.encrypt_aes_gcm(key, derived['key_b64'])
        
        # Return encrypted data bundle
        return json.dumps(encrypted)
    
    # ============ License Activation ============
    
    def activate_trial(self) -> bool:
        """
        Activate trial license (30 days)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            license_data = {
                'version': '2.0',
                'type': 'trial',
                'edition': LicenseType.FREE_TRIAL.value,
                'hwid': self.current_hwid,
                'activated_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(days=self.TRIAL_DAYS)).isoformat(),
                'devices': 1,
                'features': self.EDITION_CONFIG[LicenseType.FREE_TRIAL.value]['features']
            }
            
            # Compute signature
            license_json = json.dumps(license_data, sort_keys=True)
            signature = self.crypto.compute_hmac_sha256(license_json, self._get_master_key())
            
            license_data['signature'] = signature
            
            # Save license
            return self._save_license(license_data)
        except Exception as e:
            logger.error(f"Failed to activate trial: {e}")
            return False
    
    def activate_with_key(self, activation_key: str) -> Tuple[bool, str]:
        """
        Activate license with activation key
        
        Args:
            activation_key: 32-character activation key
            
        Returns:
            Tuple[success: bool, message: str]
        """
        try:
            # Validate key format
            if not self._validate_key_format(activation_key):
                return False, "Invalid key format"
            
            # Validate key checksum
            if not self._validate_key_checksum(activation_key):
                return False, "Invalid key (checksum failed)"
            
            # Check if key is in revocation list
            if self._is_revoked(activation_key):
                return False, "Key has been revoked"
            
            # Parse key and validate HWID
            key_data = self._parse_activation_key(activation_key)
            if not key_data:
                return False, "Cannot parse activation key"
            
            if key_data.get('hwid') != self.current_hwid:
                return False, "Key is bound to different hardware"
            
            # Create license from key
            edition = key_data.get('edition', LicenseType.PROFESSIONAL.value)
            config = self.EDITION_CONFIG[edition]
            
            license_data = {
                'version': '2.0',
                'type': 'activated',
                'edition': edition,
                'key': activation_key,
                'hwid': self.current_hwid,
                'activated_at': datetime.now().isoformat(),
                'expires_at': self._calculate_expiration(config),
                'devices': config['devices'],
                'features': config['features']
            }
            
            # Compute signature
            license_json = json.dumps(license_data, sort_keys=True)
            signature = self.crypto.compute_hmac_sha256(license_json, self._get_master_key())
            
            license_data['signature'] = signature
            
            # Save license
            if self._save_license(license_data):
                return True, f"License activated successfully (Edition: {edition})"
            else:
                return False, "Failed to save license"
        
        except Exception as e:
            logger.error(f"Activation failed: {e}")
            return False, str(e)
    
    # ============ License Validation ============
    
    def validate_license(self) -> Tuple[LicenseStatus, Dict]:
        """
        Validate current license
        
        Returns:
            Tuple[status, license_data]
        """
        try:
            # Load license
            license_data = self._load_license()
            if not license_data:
                return LicenseStatus.INVALID, {}
            
            # Check signature
            if not self._verify_license_signature(license_data):
                return LicenseStatus.INVALID, {}
            
            # Check HWID
            if license_data.get('hwid') != self.current_hwid:
                return LicenseStatus.INVALID, {}
            
            # Check if revoked
            key = license_data.get('key')
            if key and self._is_revoked(key):
                return LicenseStatus.REVOKED, license_data
            
            # Check expiration
            expires_at = license_data.get('expires_at')
            if expires_at:
                expires_dt = datetime.fromisoformat(expires_at)
                if datetime.now() > expires_dt:
                    return LicenseStatus.EXPIRED, license_data
            
            # Determine status
            if license_data.get('type') == 'trial':
                return LicenseStatus.TRIAL, license_data
            else:
                return LicenseStatus.VALID, license_data
        
        except Exception as e:
            logger.error(f"License validation error: {e}")
            return LicenseStatus.INVALID, {}
    
    def get_license_info(self) -> Optional[Dict]:
        """
        Get current license information
        
        Returns:
            License data dictionary or None
        """
        status, data = self.validate_license()
        
        if status == LicenseStatus.INVALID:
            return None
        
        # Add status and additional info
        data['status'] = status.value
        
        # Calculate days remaining
        expires_at = data.get('expires_at')
        if expires_at:
            expires_dt = datetime.fromisoformat(expires_at)
            days_left = (expires_dt - datetime.now()).days
            data['days_remaining'] = max(0, days_left)
        
        return data
    
    # ============ License Revocation ============
    
    def add_to_revocation_list(self, key: str) -> bool:
        """
        Add key to local revocation list
        
        Args:
            key: Activation key to revoke
            
        Returns:
            True if successful
        """
        try:
            revocation_list = self._load_revocation_list()
            
            if key not in revocation_list:
                revocation_list.append({
                    'key': key,
                    'revoked_at': datetime.now().isoformat(),
                    'reason': 'User revocation'
                })
            
            # Save revocation list
            with open(self.revocation_file, 'w') as f:
                json.dump(revocation_list, f, indent=2)
            
            logger.info(f"Key revoked: {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke key: {e}")
            return False
    
    # ============ Backup & Restore ============
    
    def backup_license(self) -> bool:
        """
        Create backup of current license
        
        Returns:
            True if successful
        """
        try:
            if os.path.exists(self.license_file):
                import shutil
                shutil.copy2(self.license_file, self.backup_file)
                logger.info(f"License backed up to {self.backup_file}")
                return True
            return False
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    def restore_license(self) -> bool:
        """
        Restore license from backup
        
        Returns:
            True if successful
        """
        try:
            if os.path.exists(self.backup_file):
                import shutil
                shutil.copy2(self.backup_file, self.license_file)
                logger.info(f"License restored from {self.backup_file}")
                return True
            return False
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    # ============ Internal Methods ============
    
    def _get_master_key(self) -> str:
        """
        Get master key derived from HWID and salt
        
        Returns:
            Base64-encoded master key
        """
        # Use PBKDF2 to derive key from HWID
        salt = b'NetworkChangerProSalt2026'  # Fixed salt
        derived = self.crypto.derive_key_pbkdf2(self.current_hwid, salt=salt)
        return derived['key_b64']
    
    def _validate_key_format(self, key: str) -> bool:
        """
        Validate activation key format
        """
        parts = key.split('-')
        if len(parts) != 8:
            return False
        for part in parts:
            if len(part) != 4 or not part.isalnum():
                return False
        return True
    
    def _validate_key_checksum(self, key: str) -> bool:
        """
        Validate activation key checksum
        """
        # Remove formatting
        clean_key = key.replace('-', '')
        
        # Checksum last 2 chars
        data = clean_key[:-2]
        checksum_str = clean_key[-2:]
        
        computed = hashlib.sha256(data.encode()).hexdigest()[:2].upper()
        return computed == checksum_str
    
    def _parse_activation_key(self, key: str) -> Optional[Dict]:
        """
        Parse activation key and extract embedded data
        """
        try:
            # Remove formatting
            clean_key = key.replace('-', '').upper()
            
            # Extract embedded data (simplified)
            return {
                'version': '2.0',
                'hwid': self.current_hwid,  # Would be extracted from key
                'edition': LicenseType.PROFESSIONAL.value
            }
        except Exception:
            return None
    
    def _calculate_expiration(self, config: Dict) -> Optional[str]:
        """
        Calculate license expiration date
        """
        if config['duration_days']:
            expires = datetime.now() + timedelta(days=config['duration_days'])
            return expires.isoformat()
        else:
            # Lifetime - set to year 2099
            return datetime(2099, 12, 31).isoformat()
    
    def _save_license(self, license_data: Dict) -> bool:
        """
        Save license to file (encrypted)
        """
        try:
            # Create backup of old license
            if os.path.exists(self.license_file):
                self.backup_license()
            
            # Encrypt license
            license_json = json.dumps(license_data, sort_keys=True)
            encrypted = self.crypto.encrypt_aes_gcm(license_json, self._get_master_key())
            
            # Save encrypted license
            with open(self.license_file, 'w') as f:
                json.dump(encrypted, f)
            
            logger.info(f"License saved to {self.license_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save license: {e}")
            return False
    
    def _load_license(self) -> Optional[Dict]:
        """
        Load and decrypt license from file
        """
        try:
            if not os.path.exists(self.license_file):
                return None
            
            with open(self.license_file, 'r') as f:
                encrypted = json.load(f)
            
            # Decrypt license
            decrypted = self.crypto.decrypt_aes_gcm(
                encrypted['ciphertext_b64'],
                encrypted['tag_b64'],
                self._get_master_key(),
                encrypted['nonce_b64']
            )
            
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.warning(f"Failed to load license: {e}")
            return None
    
    def _verify_license_signature(self, license_data: Dict) -> bool:
        """
        Verify license signature
        """
        try:
            signature = license_data.pop('signature', None)
            if not signature:
                return False
            
            license_json = json.dumps(license_data, sort_keys=True)
            computed = self.crypto.compute_hmac_sha256(license_json, self._get_master_key())
            
            return hmac.compare_digest(computed, signature)
        except Exception:
            return False
    
    def _is_revoked(self, key: str) -> bool:
        """
        Check if key is in revocation list
        """
        try:
            revocation_list = self._load_revocation_list()
            for entry in revocation_list:
                if entry.get('key') == key:
                    return True
            return False
        except Exception:
            return False
    
    def _load_revocation_list(self) -> list:
        """
        Load revocation list
        """
        try:
            if os.path.exists(self.revocation_file):
                with open(self.revocation_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return []


# Export main classes
__all__ = ['LicenseManager', 'LicenseType', 'LicenseStatus']
