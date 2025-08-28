"""
IKEv2 Configuration Management
"""

import os
import json
import yaml
import ipaddress
from typing import Dict, List, Any, Optional
from .const import TransformID, AuthMethod

class Config:
    """IKEv2 Configuration Manager"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._get_default_config()
        
        if config_file:
            self.load_config(config_file)
            
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'daemon': {
                'local_addresses': ['0.0.0.0'],
                'local_port': 500,
                'nat_port': 4500,
                'log_level': 'INFO',
                'log_file': None,
                'retransmit_timeout': 2.0,
                'max_retransmits': 5,
                'cookie_threshold': 10,
                'dpd_interval': 30,
                'sa_lifetime': 86400,
                'child_sa_lifetime': 3600,
            },
            'crypto': {
                'proposals': [
                    {
                        'encryption': [
                            {'algorithm': 'aes256-cbc', 'key_length': 256},
                            {'algorithm': 'aes128-cbc', 'key_length': 128},
                            {'algorithm': 'aes256-gcm', 'key_length': 256},
                        ],
                        'integrity': [
                            'hmac-sha256-128',
                            'hmac-sha384-192',
                            'hmac-sha1-96',
                        ],
                        'prf': [
                            'hmac-sha256',
                            'hmac-sha384',
                            'hmac-sha1',
                        ],
                        'dh_group': [
                            'modp2048',
                            'modp3072',
                            'ecp256',
                            'curve25519',
                        ],
                    }
                ],
                'rekey_margin': 540,
                'rekey_fuzz': 100,
            },
            'connections': {},
            'peers': {},
            'certificates': {
                'ca_dir': '/etc/pyikev2/ca',
                'cert_dir': '/etc/pyikev2/certs',
                'key_dir': '/etc/pyikev2/private',
            },
        }
        
    def load_config(self, config_file: str):
        """Load configuration from file"""
        if not os.path.exists(config_file):
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
            
        with open(config_file, 'r') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                file_config = yaml.safe_load(f)
            elif config_file.endswith('.json'):
                file_config = json.load(f)
            else:
                raise ValueError("Unsupported configuration file format")
                
        self._merge_config(self.config, file_config)
        self._validate_config()
        self._process_config()
        
    def _merge_config(self, base: Dict, override: Dict):
        """Merge configuration recursively"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
                
    def _validate_config(self):
        """Validate configuration"""
        daemon = self.config['daemon']
        
        if daemon['local_port'] < 1 or daemon['local_port'] > 65535:
            raise ValueError("Invalid local_port")
            
        if daemon['nat_port'] < 1 or daemon['nat_port'] > 65535:
            raise ValueError("Invalid nat_port")
            
        for addr in daemon['local_addresses']:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                if addr != '0.0.0.0' and addr != '::':
                    raise ValueError(f"Invalid IP address: {addr}")
                    
        if daemon['log_level'] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError("Invalid log_level")
            
    def _process_config(self):
        """Process configuration to convert string values to enums"""
        for proposal in self.config['crypto']['proposals']:
            if 'encryption' in proposal:
                new_encr = []
                for encr in proposal['encryption']:
                    if isinstance(encr, str):
                        encr_id = self._get_encryption_id(encr)
                        key_len = self._get_key_length_from_name(encr)
                        new_encr.append({'id': encr_id, 'key_length': key_len})
                    elif isinstance(encr, dict):
                        encr_id = self._get_encryption_id(encr.get('algorithm', ''))
                        encr['id'] = encr_id
                        new_encr.append(encr)
                proposal['encryption'] = new_encr
                
            if 'integrity' in proposal:
                new_integ = []
                for integ in proposal['integrity']:
                    if isinstance(integ, str):
                        new_integ.append(self._get_integrity_id(integ))
                    else:
                        new_integ.append(integ)
                proposal['integrity'] = new_integ
                
            if 'prf' in proposal:
                new_prf = []
                for prf in proposal['prf']:
                    if isinstance(prf, str):
                        new_prf.append(self._get_prf_id(prf))
                    else:
                        new_prf.append(prf)
                proposal['prf'] = new_prf
                
            if 'dh_group' in proposal:
                new_dh = []
                for dh in proposal['dh_group']:
                    if isinstance(dh, str):
                        new_dh.append(self._get_dh_group_id(dh))
                    else:
                        new_dh.append(dh)
                proposal['dh_group'] = new_dh
                
    def _get_encryption_id(self, name: str) -> int:
        """Get encryption algorithm ID from name"""
        encryption_map = {
            'aes128-cbc': TransformID.ENCR.AES_CBC,
            'aes192-cbc': TransformID.ENCR.AES_CBC,
            'aes256-cbc': TransformID.ENCR.AES_CBC,
            'aes128-ctr': TransformID.ENCR.AES_CTR,
            'aes192-ctr': TransformID.ENCR.AES_CTR,
            'aes256-ctr': TransformID.ENCR.AES_CTR,
            'aes128-gcm': TransformID.ENCR.AES_GCM_16,
            'aes192-gcm': TransformID.ENCR.AES_GCM_16,
            'aes256-gcm': TransformID.ENCR.AES_GCM_16,
            'aes128-gcm-8': TransformID.ENCR.AES_GCM_8,
            'aes128-gcm-12': TransformID.ENCR.AES_GCM_12,
            'aes128-gcm-16': TransformID.ENCR.AES_GCM_16,
            '3des': TransformID.ENCR.THREE_DES,
            '3des-cbc': TransformID.ENCR.THREE_DES,
            'chacha20-poly1305': TransformID.ENCR.CHACHA20_POLY1305,
        }
        
        return encryption_map.get(name.lower(), TransformID.ENCR.AES_CBC)
        
    def _get_key_length_from_name(self, name: str) -> int:
        """Extract key length from algorithm name"""
        if '128' in name:
            return 128
        elif '192' in name:
            return 192
        elif '256' in name:
            return 256
        elif '3des' in name.lower():
            return 192
        elif 'chacha20' in name.lower():
            return 256
        return 128
        
    def _get_integrity_id(self, name: str) -> int:
        """Get integrity algorithm ID from name"""
        integrity_map = {
            'hmac-md5-96': TransformID.INTEG.AUTH_HMAC_MD5_96,
            'hmac-sha1-96': TransformID.INTEG.AUTH_HMAC_SHA1_96,
            'hmac-sha256-128': TransformID.INTEG.AUTH_HMAC_SHA256_128,
            'hmac-sha384-192': TransformID.INTEG.AUTH_HMAC_SHA384_192,
            'hmac-sha512-256': TransformID.INTEG.AUTH_HMAC_SHA512_256,
            'aes-xcbc-96': TransformID.INTEG.AUTH_AES_XCBC_96,
            'none': TransformID.INTEG.NONE,
        }
        
        return integrity_map.get(name.lower(), TransformID.INTEG.AUTH_HMAC_SHA256_128)
        
    def _get_prf_id(self, name: str) -> int:
        """Get PRF algorithm ID from name"""
        prf_map = {
            'hmac-md5': TransformID.PRF.HMAC_MD5,
            'hmac-sha1': TransformID.PRF.HMAC_SHA1,
            'hmac-sha256': TransformID.PRF.HMAC_SHA256,
            'hmac-sha384': TransformID.PRF.HMAC_SHA384,
            'hmac-sha512': TransformID.PRF.HMAC_SHA512,
            'aes128-xcbc': TransformID.PRF.AES128_XCBC,
            'aes128-cmac': TransformID.PRF.AES128_CMAC,
        }
        
        return prf_map.get(name.lower(), TransformID.PRF.HMAC_SHA256)
        
    def _get_dh_group_id(self, name: str) -> int:
        """Get DH group ID from name"""
        dh_map = {
            'modp768': TransformID.DH.MODP_768,
            'modp1024': TransformID.DH.MODP_1024,
            'modp1536': TransformID.DH.MODP_1536,
            'modp2048': TransformID.DH.MODP_2048,
            'modp3072': TransformID.DH.MODP_3072,
            'modp4096': TransformID.DH.MODP_4096,
            'modp6144': TransformID.DH.MODP_6144,
            'modp8192': TransformID.DH.MODP_8192,
            'ecp256': TransformID.DH.ECP_256,
            'ecp384': TransformID.DH.ECP_384,
            'ecp521': TransformID.DH.ECP_521,
            'curve25519': TransformID.DH.CURVE25519,
            'curve448': TransformID.DH.CURVE448,
        }
        
        return dh_map.get(name.lower(), TransformID.DH.MODP_2048)
        
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
        
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
    def add_connection(self, name: str, config: Dict[str, Any]):
        """Add a connection configuration"""
        self.config['connections'][name] = config
        
    def add_peer(self, peer_id: str, config: Dict[str, Any]):
        """Add a peer configuration"""
        self.config['peers'][peer_id] = config
        
    def get_connection(self, name: str) -> Optional[Dict[str, Any]]:
        """Get connection configuration"""
        return self.config['connections'].get(name)
        
    def get_peer(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """Get peer configuration"""
        return self.config['peers'].get(peer_id)
        
    def save_config(self, config_file: str):
        """Save configuration to file"""
        with open(config_file, 'w') as f:
            if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                yaml.dump(self.config, f, default_flow_style=False)
            elif config_file.endswith('.json'):
                json.dump(self.config, f, indent=2)
            else:
                raise ValueError("Unsupported configuration file format")
                
    def generate_sample_config(self) -> str:
        """Generate a sample configuration file"""
        sample = {
            'daemon': {
                'local_addresses': ['0.0.0.0', '::'],
                'local_port': 500,
                'nat_port': 4500,
                'log_level': 'INFO',
                'log_file': '/var/log/pyikev2.log',
            },
            'crypto': {
                'proposals': [
                    {
                        'encryption': [
                            {'algorithm': 'aes256-gcm', 'key_length': 256},
                            {'algorithm': 'aes128-gcm', 'key_length': 128},
                            {'algorithm': 'chacha20-poly1305'},
                        ],
                        'integrity': ['none'],
                        'prf': ['hmac-sha256', 'hmac-sha384'],
                        'dh_group': ['curve25519', 'ecp256', 'modp2048'],
                    },
                    {
                        'encryption': [
                            {'algorithm': 'aes256-cbc', 'key_length': 256},
                            {'algorithm': 'aes128-cbc', 'key_length': 128},
                        ],
                        'integrity': ['hmac-sha256-128', 'hmac-sha1-96'],
                        'prf': ['hmac-sha256', 'hmac-sha1'],
                        'dh_group': ['modp2048', 'modp3072'],
                    }
                ],
            },
            'connections': {
                'site-to-site': {
                    'type': 'tunnel',
                    'auth_method': 'psk',
                    'psk': 'your-pre-shared-key-here',
                    'local': {
                        'id': 'site-a@example.com',
                        'subnet': '10.1.0.0/16',
                    },
                    'remote': {
                        'id': 'site-b@example.com',
                        'subnet': '10.2.0.0/16',
                    },
                    'dpd': {
                        'interval': 30,
                        'timeout': 120,
                    },
                    'auto': 'start',
                }
            },
            'peers': {
                'site-b.example.com': {
                    'address': '203.0.113.1',
                    'port': 500,
                    'auth_method': 'psk',
                    'psk': 'your-pre-shared-key-here',
                    'id': 'site-b@example.com',
                }
            },
        }
        
        return yaml.dump(sample, default_flow_style=False)