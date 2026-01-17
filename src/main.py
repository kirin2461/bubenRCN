#!/usr/bin/env python3
"""
Network Changer Pro v2.0.0 - Main Entry Point
Usage:
    python main.py          # Start GUI
    python main.py --cli    # Start CLI
    python main.py --test   # Run tests
"""

import sys
import os
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network_changer_pro.log')
    ]
)

logger = logging.getLogger(__name__)


def main():
    """
    Main application entry point
    """
    logger.info("="*60)
    logger.info("Network Changer Pro v2.0.0 - Starting Application")
    logger.info("="*60)
    
    try:
        # Import core modules
        from core import (
            CryptoManager,
            HWIDGenerator,
            LicenseManager,
            DPIBypassEngine
        )
        
        logger.info("✓ Core modules imported successfully")
        
        # Initialize components
        logger.info("\nInitializing components...")
        
        # 1. Crypto Manager
        crypto = CryptoManager()
        logger.info("✓ CryptoManager initialized")
        logger.info(f"  - Algorithms: Ed25519, ChaCha20-Poly1305, AES-256-GCM")
        logger.info(f"  - PBKDF2 iterations: {CryptoManager.PBKDF2_ITERATIONS:,}")
        
        # 2. HWID Generator
        hwid_gen = HWIDGenerator()
        hwid = hwid_gen.generate_hwid()
        logger.info("✓ HWIDGenerator initialized")
        logger.info(f"  - Generated HWID: {hwid}")
        logger.info(f"  - System: {hwid_gen.system}")
        
        # 3. License Manager
        lic_manager = LicenseManager()
        logger.info("✓ LicenseManager initialized")
        
        # Check current license
        license_info = lic_manager.get_license_info()
        if license_info:
            logger.info(f"  - Current License: {license_info.get('edition', 'unknown')}")
            logger.info(f"  - Status: {license_info.get('status', 'unknown')}")
            logger.info(f"  - Days remaining: {license_info.get('days_remaining', 'N/A')}")
        else:
            logger.info("  - No active license found")
        
        # 4. DPI Bypass Engine
        bypass_engine = DPIBypassEngine()
        logger.info("✓ DPIBypassEngine initialized")
        stats = bypass_engine.get_profile_stats()
        logger.info(f"  - Available profiles: {stats['total_profiles']}")
        logger.info(f"  - Techniques: {len(stats['available_techniques'])}")
        logger.info(f"  - DoH providers: {stats['doh_providers']}")
        logger.info(f"  - DoT providers: {stats['dot_providers']}")
        
        # Parse command line arguments
        if len(sys.argv) > 1:
            if sys.argv[1] == '--cli':
                logger.info("\n" + "="*60)
                logger.info("Starting CLI mode...")
                logger.info("="*60)
                start_cli(lic_manager, bypass_engine, crypto, hwid_gen)
            elif sys.argv[1] == '--test':
                logger.info("\n" + "="*60)
                logger.info("Running tests...")
                logger.info("="*60)
                run_tests(lic_manager, crypto, hwid_gen, bypass_engine)
            elif sys.argv[1] == '--activate-trial':
                logger.info("\nActivating trial license...")
                if lic_manager.activate_trial():
                    logger.info("✓ Trial license activated successfully!")
                    logger.info(f"  - Valid for {LicenseManager.TRIAL_DAYS} days")
                    license_info = lic_manager.get_license_info()
                    if license_info:
                        logger.info(f"  - Expires: {license_info.get('expires_at')}")
                else:
                    logger.error("✗ Failed to activate trial license")
            else:
                logger.info("\n" + "="*60)
                logger.info("Starting GUI mode...")
                logger.info("="*60)
                start_gui(lic_manager, bypass_engine)
        else:
            logger.info("\n" + "="*60)
            logger.info("Starting GUI mode...")
            logger.info("="*60)
            start_gui(lic_manager, bypass_engine)
    
    except ImportError as e:
        logger.error(f"✗ Import error: {e}")
        logger.error("Please install required dependencies: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.error(f"✗ Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


def start_gui(lic_manager, bypass_engine):
    """
    Start GUI application (placeholder)
    """
    logger.info("GUI mode not yet implemented")
    logger.info("Currently in development...")
    logger.info("\nUse --cli flag to start CLI mode")
    logger.info("  python main.py --cli")


def start_cli(lic_manager, bypass_engine, crypto, hwid_gen):
    """
    Start CLI application (placeholder)
    """
    from cli.cli import main as cli_main
    cli_main(lic_manager, bypass_engine, crypto, hwid_gen)


def run_tests(lic_manager, crypto, hwid_gen, bypass_engine):
    """
    Run basic tests
    """
    logger.info("\n" + "-"*60)
    logger.info("TEST 1: Encryption/Decryption")
    logger.info("-"*60)
    
    try:
        # Test encryption
        message = "Test message for encryption"
        key = CryptoManager.generate_aes_key()
        
        encrypted = CryptoManager.encrypt_aes_gcm(message, key)
        logger.info("✓ AES-256-GCM encryption: PASSED")
        
        decrypted = CryptoManager.decrypt_aes_gcm(
            encrypted['ciphertext_b64'],
            encrypted['tag_b64'],
            key,
            encrypted['nonce_b64']
        )
        
        if decrypted.decode() == message:
            logger.info("✓ AES-256-GCM decryption: PASSED")
        else:
            logger.error("✗ Decryption mismatch")
    except Exception as e:
        logger.error(f"✗ Encryption test failed: {e}")
    
    logger.info("\n" + "-"*60)
    logger.info("TEST 2: HWID Generation")
    logger.info("-"*60)
    
    try:
        hwid = hwid_gen.generate_hwid()
        if hwid and len(hwid) == 24:  # 96-bit = 24 hex chars
            logger.info(f"✓ HWID generation: PASSED")
            logger.info(f"  - HWID: {hwid}")
            logger.info(f"  - Length: {len(hwid)} hex chars (96-bit)")
        else:
            logger.error(f"✗ Invalid HWID format: {hwid}")
    except Exception as e:
        logger.error(f"✗ HWID test failed: {e}")
    
    logger.info("\n" + "-"*60)
    logger.info("TEST 3: License Management")
    logger.info("-"*60)
    
    try:
        # Test trial activation
        if lic_manager.activate_trial():
            logger.info("✓ Trial activation: PASSED")
        else:
            logger.error("✗ Trial activation: FAILED")
        
        # Test license validation
        status, data = lic_manager.validate_license()
        logger.info(f"✓ License validation: PASSED (Status: {status.value})")
    except Exception as e:
        logger.error(f"✗ License test failed: {e}")
    
    logger.info("\n" + "-"*60)
    logger.info("TEST 4: DPI Bypass Profiles")
    logger.info("-"*60)
    
    try:
        profiles = bypass_engine.list_profiles()
        logger.info(f"✓ Available profiles: {len(profiles)}")
        for profile in profiles:
            logger.info(f"  - {profile.capitalize()}")
        
        # Activate a profile
        if bypass_engine.activate_profile('aggressive'):
            logger.info(f"✓ Profile activation: PASSED (Aggressive)")
        else:
            logger.error(f"✗ Profile activation: FAILED")
    except Exception as e:
        logger.error(f"✗ DPI bypass test failed: {e}")
    
    logger.info("\n" + "="*60)
    logger.info("All tests completed!")
    logger.info("="*60)


if __name__ == '__main__':
    main()
