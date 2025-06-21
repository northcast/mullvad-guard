#!/usr/bin/env python3
"""
Mullvad Device Manager

Monitors and manages Mullvad VPN devices, automatically removing unauthorized
devices while maintaining a whitelist of approved devices.
"""

import subprocess
import os
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional


class MullvadManager:
    """Manages Mullvad VPN device monitoring and cleanup."""
    
    def __init__(self, token_file: str = "token", whitelist_file: str = "whitelist", 
                 log_file: str = "logs", check_interval: int = 60):
        self.token_file = Path(token_file)
        self.whitelist_file = Path(whitelist_file)
        self.log_file = Path(log_file)
        self.check_interval = check_interval
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _run_command(self, cmd: List[str], capture_output: bool = True, 
                    suppress_output: bool = False) -> subprocess.CompletedProcess:
        """Run a subprocess command with error handling."""
        try:
            kwargs = {
                'capture_output': capture_output,
                'text': True,
                'check': True
            }
            
            if suppress_output:
                kwargs['stdout'] = subprocess.DEVNULL
                kwargs['stderr'] = subprocess.DEVNULL
                
            return subprocess.run(cmd, **kwargs)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(cmd)} - {e}")
            raise
        except FileNotFoundError:
            self.logger.error(f"Command not found: {cmd[0]}")
            raise
            
    def _get_account_info(self) -> Optional[List[str]]:
        """Get Mullvad account information."""
        try:
            result = self._run_command(["mullvad", "account", "get"])
            return result.stdout.strip().splitlines()
        except subprocess.CalledProcessError:
            return None
            
    def _login_with_token(self) -> None:
        """Login to Mullvad using token from file."""
        if not self.token_file.exists():
            raise FileNotFoundError(f"Token file not found: {self.token_file}")
            
        token = self.token_file.read_text().strip()
        if not token:
            raise ValueError("Token file is empty")
            
        self.logger.info("Logging out and re-authenticating...")
        self._run_command(["mullvad", "account", "logout"], suppress_output=True)
        self._run_command(["mullvad", "account", "login", token], suppress_output=True)
        self._run_command(["mullvad", "connect"], capture_output=False)
        
    def get_local_device_name(self) -> str:
        """Get the name of the current device."""
        lines = self._get_account_info()
        
        if not lines or len(lines) != 3:
            self.logger.warning("Invalid account info, re-authenticating...")
            self._login_with_token()
            return self.get_local_device_name()  # Recursive retry
            
        device_name = lines[2].replace("Device name:", "").strip()
        self.logger.info(f"Local device: {device_name}")
        return device_name
        
    def get_whitelist(self) -> List[str]:
        """Load whitelist of approved devices."""
        if not self.whitelist_file.exists():
            self.logger.warning(f"Whitelist file not found: {self.whitelist_file}")
            return []
            
        whitelist = self.whitelist_file.read_text().strip().splitlines()
        # Remove empty lines and strip whitespace
        return [device.strip() for device in whitelist if device.strip()]
        
    def get_account_devices(self) -> List[str]:
        """Get list of all devices on the account."""
        result = self._run_command(["mullvad", "account", "list-devices"])
        lines = result.stdout.strip().splitlines()
        
        devices = []
        for line in lines:
            line = line.strip()
            if line and line != "Devices on the account:":
                devices.append(line)
                
        return devices
        
    def remove_device(self, device_name: str) -> None:
        """Remove a device from the account."""
        self.logger.info(f"Removing unauthorized device: {device_name}")
        self._run_command(
            ["mullvad", "account", "revoke-device", device_name],
            capture_output=False
        )
        
    def cleanup_devices(self, local_device: str) -> bool:
        """Remove unauthorized devices, return True if local device is still valid."""
        whitelist = self.get_whitelist()
        devices = self.get_account_devices()
        
        local_device_found = False
        
        for device in devices:
            if device == local_device:
                local_device_found = True
            elif device in whitelist:
                self.logger.debug(f"Whitelisted device: {device}")
            else:
                self.remove_device(device)
                
        return local_device_found
        
    def run_monitoring_loop(self) -> None:
        """Main monitoring loop."""
        self.logger.info("Starting Mullvad device monitoring...")
        
        local_device = self.get_local_device_name()
        
        while True:
            try:
                device_still_valid = self.cleanup_devices(local_device)
                
                if device_still_valid:
                    self.logger.debug(f"Sleeping for {self.check_interval} seconds...")
                    time.sleep(self.check_interval)
                else:
                    self.logger.warning("Local device was removed, re-authenticating...")
                    local_device = self.get_local_device_name()
                    
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                time.sleep(10)  # Brief pause before retrying


def main():
    """Entry point for the script."""
    manager = MullvadManager()
    
    try:
        manager.run_monitoring_loop()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1
        
    return 0


if __name__ == "__main__":
    exit(main())
