"""
IKEv2 Cryptographic operations
"""

import os
import hmac
import hashlib
import struct
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa, dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from typing import Tuple, Optional, List
from .const import TransformID

class CryptoEngine:
    """IKEv2 Cryptographic Engine"""
    
    def __init__(self):
        self.backend = default_backend()
        self.dh_groups = self._init_dh_groups()
        
    def _init_dh_groups(self):
        """Initialize DH group parameters"""
        groups = {
            TransformID.DH.MODP_2048: {
                'p': int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16),
                'g': 2
            },
            TransformID.DH.MODP_3072: {
                'p': int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16),
                'g': 2
            },
            TransformID.DH.MODP_4096: {
                'p': int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                        "15728E5A8AAACAA68FFFFFFFFFFFFFFFF" * 2, 16),
                'g': 2
            },
        }
        return groups
        
    def generate_dh_keypair(self, group_id: int) -> Tuple[bytes, any]:
        """Generate DH keypair for specified group"""
        if group_id in [TransformID.DH.ECP_256, TransformID.DH.ECP_384, TransformID.DH.ECP_521]:
            return self._generate_ecdh_keypair(group_id)
        elif group_id == TransformID.DH.CURVE25519:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return public_bytes, private_key
        elif group_id == TransformID.DH.CURVE448:
            from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
            private_key = X448PrivateKey.generate()
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return public_bytes, private_key
        else:
            return self._generate_modp_keypair(group_id)
            
    def _generate_modp_keypair(self, group_id: int) -> Tuple[bytes, any]:
        """Generate MODP DH keypair"""
        if group_id not in self.dh_groups:
            raise ValueError(f"Unsupported DH group: {group_id}")
            
        params = self.dh_groups[group_id]
        p = params['p']
        g = params['g']
        
        parameters = dh.DHParameterNumbers(p, g).parameters(self.backend)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        public_numbers = public_key.public_numbers()
        public_bytes = public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')
        
        return public_bytes, private_key
        
    def _generate_ecdh_keypair(self, group_id: int) -> Tuple[bytes, any]:
        """Generate ECDH keypair"""
        curve_map = {
            TransformID.DH.ECP_256: ec.SECP256R1(),
            TransformID.DH.ECP_384: ec.SECP384R1(),
            TransformID.DH.ECP_521: ec.SECP521R1(),
        }
        
        if group_id not in curve_map:
            raise ValueError(f"Unsupported ECDH group: {group_id}")
            
        curve = curve_map[group_id]
        private_key = ec.generate_private_key(curve, self.backend)
        public_key = private_key.public_key()
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        return public_bytes, private_key
        
    def compute_dh_shared_secret(self, private_key: any, peer_public: bytes, group_id: int) -> bytes:
        """Compute DH shared secret"""
        if group_id in [TransformID.DH.ECP_256, TransformID.DH.ECP_384, TransformID.DH.ECP_521]:
            return self._compute_ecdh_shared_secret(private_key, peer_public, group_id)
        elif group_id == TransformID.DH.CURVE25519:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
            peer_key = X25519PublicKey.from_public_bytes(peer_public)
            return private_key.exchange(peer_key)
        elif group_id == TransformID.DH.CURVE448:
            from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
            peer_key = X448PublicKey.from_public_bytes(peer_public)
            return private_key.exchange(peer_key)
        else:
            return self._compute_modp_shared_secret(private_key, peer_public, group_id)
            
    def _compute_modp_shared_secret(self, private_key: any, peer_public: bytes, group_id: int) -> bytes:
        """Compute MODP DH shared secret"""
        if group_id not in self.dh_groups:
            raise ValueError(f"Unsupported DH group: {group_id}")
            
        y = int.from_bytes(peer_public, 'big')
        params = self.dh_groups[group_id]
        p = params['p']
        
        peer_numbers = dh.DHPublicNumbers(y, dh.DHParameterNumbers(p, params['g']))
        peer_key = peer_numbers.public_key(self.backend)
        
        shared_secret = private_key.exchange(peer_key)
        return shared_secret
        
    def _compute_ecdh_shared_secret(self, private_key: any, peer_public: bytes, group_id: int) -> bytes:
        """Compute ECDH shared secret"""
        curve_map = {
            TransformID.DH.ECP_256: ec.SECP256R1(),
            TransformID.DH.ECP_384: ec.SECP384R1(),
            TransformID.DH.ECP_521: ec.SECP521R1(),
        }
        
        if group_id not in curve_map:
            raise ValueError(f"Unsupported ECDH group: {group_id}")
            
        curve = curve_map[group_id]
        peer_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, peer_public)
        
        shared_secret = private_key.exchange(ec.ECDH(), peer_key)
        return shared_secret
        
    def prf(self, key: bytes, data: bytes, prf_id: int) -> bytes:
        """Pseudo-Random Function"""
        prf_map = {
            TransformID.PRF.HMAC_MD5: hashlib.md5,
            TransformID.PRF.HMAC_SHA1: hashlib.sha1,
            TransformID.PRF.HMAC_SHA256: hashlib.sha256,
            TransformID.PRF.HMAC_SHA384: hashlib.sha384,
            TransformID.PRF.HMAC_SHA512: hashlib.sha512,
        }
        
        if prf_id not in prf_map:
            raise ValueError(f"Unsupported PRF: {prf_id}")
            
        hash_func = prf_map[prf_id]
        return hmac.new(key, data, hash_func).digest()
        
    def prf_plus(self, key: bytes, data: bytes, prf_id: int, length: int) -> bytes:
        """PRF+ function for key derivation"""
        result = b''
        counter = 1
        prev = b''
        
        while len(result) < length:
            prev = self.prf(key, prev + data + counter.to_bytes(1, 'big'), prf_id)
            result += prev
            counter += 1
            
        return result[:length]
        
    def encrypt(self, key: bytes, iv: bytes, plaintext: bytes, encr_id: int, 
                integ_key: bytes = None, integ_id: int = None) -> bytes:
        """Encrypt data"""
        if encr_id in [TransformID.ENCR.AES_GCM_8, TransformID.ENCR.AES_GCM_12, 
                       TransformID.ENCR.AES_GCM_16]:
            return self._encrypt_aead(key, iv, plaintext, encr_id)
        elif encr_id == TransformID.ENCR.CHACHA20_POLY1305:
            return self._encrypt_chacha20_poly1305(key, iv, plaintext)
        else:
            ciphertext = self._encrypt_cbc_ctr(key, iv, plaintext, encr_id)
            if integ_key and integ_id:
                mac = self.compute_mac(integ_key, ciphertext, integ_id)
                return ciphertext + mac
            return ciphertext
            
    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, encr_id: int,
                integ_key: bytes = None, integ_id: int = None) -> bytes:
        """Decrypt data"""
        if encr_id in [TransformID.ENCR.AES_GCM_8, TransformID.ENCR.AES_GCM_12,
                       TransformID.ENCR.AES_GCM_16]:
            return self._decrypt_aead(key, iv, ciphertext, encr_id)
        elif encr_id == TransformID.ENCR.CHACHA20_POLY1305:
            return self._decrypt_chacha20_poly1305(key, iv, ciphertext)
        else:
            if integ_key and integ_id:
                mac_len = self.get_mac_length(integ_id)
                if len(ciphertext) < mac_len:
                    raise ValueError("Ciphertext too short for MAC")
                actual_ciphertext = ciphertext[:-mac_len]
                expected_mac = ciphertext[-mac_len:]
                computed_mac = self.compute_mac(integ_key, actual_ciphertext, integ_id)
                if not hmac.compare_digest(expected_mac, computed_mac):
                    raise ValueError("MAC verification failed")
                ciphertext = actual_ciphertext
            return self._decrypt_cbc_ctr(key, iv, ciphertext, encr_id)
            
    def _encrypt_cbc_ctr(self, key: bytes, iv: bytes, plaintext: bytes, encr_id: int) -> bytes:
        """Encrypt using CBC or CTR mode"""
        if encr_id == TransformID.ENCR.AES_CBC:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        elif encr_id == TransformID.ENCR.AES_CTR:
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        elif encr_id == TransformID.ENCR.THREE_DES:
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encr_id}")
            
        encryptor = cipher.encryptor()
        
        if encr_id in [TransformID.ENCR.AES_CBC, TransformID.ENCR.THREE_DES]:
            block_size = 16 if encr_id == TransformID.ENCR.AES_CBC else 8
            pad_len = block_size - (len(plaintext) % block_size)
            if pad_len == 0:
                pad_len = block_size
            padding = bytes([pad_len - 1] * pad_len)
            plaintext = plaintext + padding
            
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext
        
    def _decrypt_cbc_ctr(self, key: bytes, iv: bytes, ciphertext: bytes, encr_id: int) -> bytes:
        """Decrypt using CBC or CTR mode"""
        if encr_id == TransformID.ENCR.AES_CBC:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        elif encr_id == TransformID.ENCR.AES_CTR:
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        elif encr_id == TransformID.ENCR.THREE_DES:
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {encr_id}")
            
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        if encr_id in [TransformID.ENCR.AES_CBC, TransformID.ENCR.THREE_DES]:
            if plaintext:
                pad_len = plaintext[-1] + 1
                if pad_len <= len(plaintext):
                    plaintext = plaintext[:-pad_len]
                    
        return plaintext
        
    def _encrypt_aead(self, key: bytes, iv: bytes, plaintext: bytes, encr_id: int) -> bytes:
        """Encrypt using AEAD (AES-GCM)"""
        tag_map = {
            TransformID.ENCR.AES_GCM_8: 8,
            TransformID.ENCR.AES_GCM_12: 12,
            TransformID.ENCR.AES_GCM_16: 16,
        }
        
        tag_length = tag_map[encr_id]
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return ciphertext[:len(plaintext)] + ciphertext[-tag_length:]
        
    def _decrypt_aead(self, key: bytes, iv: bytes, ciphertext: bytes, encr_id: int) -> bytes:
        """Decrypt using AEAD (AES-GCM)"""
        tag_map = {
            TransformID.ENCR.AES_GCM_8: 8,
            TransformID.ENCR.AES_GCM_12: 12,
            TransformID.ENCR.AES_GCM_16: 16,
        }
        
        tag_length = tag_map[encr_id]
        if len(ciphertext) < tag_length:
            raise ValueError("Ciphertext too short for AEAD tag")
            
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext
        
    def _encrypt_chacha20_poly1305(self, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """Encrypt using ChaCha20-Poly1305"""
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(iv, plaintext, None)
        return ciphertext
        
    def _decrypt_chacha20_poly1305(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(iv, ciphertext, None)
        return plaintext
        
    def compute_mac(self, key: bytes, data: bytes, integ_id: int) -> bytes:
        """Compute MAC/integrity checksum"""
        mac_map = {
            TransformID.INTEG.AUTH_HMAC_MD5_96: (hashlib.md5, 12),
            TransformID.INTEG.AUTH_HMAC_SHA1_96: (hashlib.sha1, 12),
            TransformID.INTEG.AUTH_HMAC_SHA256_128: (hashlib.sha256, 16),
            TransformID.INTEG.AUTH_HMAC_SHA384_192: (hashlib.sha384, 24),
            TransformID.INTEG.AUTH_HMAC_SHA512_256: (hashlib.sha512, 32),
        }
        
        if integ_id not in mac_map:
            raise ValueError(f"Unsupported integrity algorithm: {integ_id}")
            
        hash_func, mac_len = mac_map[integ_id]
        mac = hmac.new(key, data, hash_func).digest()
        return mac[:mac_len]
        
    def get_mac_length(self, integ_id: int) -> int:
        """Get MAC length for integrity algorithm"""
        mac_lengths = {
            TransformID.INTEG.AUTH_HMAC_MD5_96: 12,
            TransformID.INTEG.AUTH_HMAC_SHA1_96: 12,
            TransformID.INTEG.AUTH_HMAC_SHA256_128: 16,
            TransformID.INTEG.AUTH_HMAC_SHA384_192: 24,
            TransformID.INTEG.AUTH_HMAC_SHA512_256: 32,
            TransformID.INTEG.NONE: 0,
        }
        
        return mac_lengths.get(integ_id, 0)
        
    def get_key_length(self, transform_type: int, transform_id: int) -> int:
        """Get key length for transform"""
        if transform_type == TransformType.ENCR:
            key_lengths = {
                TransformID.ENCR.AES_CBC: 16,
                TransformID.ENCR.AES_CTR: 16,
                TransformID.ENCR.AES_GCM_8: 16,
                TransformID.ENCR.AES_GCM_12: 16,
                TransformID.ENCR.AES_GCM_16: 16,
                TransformID.ENCR.THREE_DES: 24,
                TransformID.ENCR.CHACHA20_POLY1305: 32,
            }
            return key_lengths.get(transform_id, 16)
        elif transform_type == TransformType.PRF:
            prf_lengths = {
                TransformID.PRF.HMAC_MD5: 16,
                TransformID.PRF.HMAC_SHA1: 20,
                TransformID.PRF.HMAC_SHA256: 32,
                TransformID.PRF.HMAC_SHA384: 48,
                TransformID.PRF.HMAC_SHA512: 64,
            }
            return prf_lengths.get(transform_id, 32)
        elif transform_type == TransformType.INTEG:
            integ_lengths = {
                TransformID.INTEG.AUTH_HMAC_MD5_96: 16,
                TransformID.INTEG.AUTH_HMAC_SHA1_96: 20,
                TransformID.INTEG.AUTH_HMAC_SHA256_128: 32,
                TransformID.INTEG.AUTH_HMAC_SHA384_192: 48,
                TransformID.INTEG.AUTH_HMAC_SHA512_256: 64,
                TransformID.INTEG.NONE: 0,
            }
            return integ_lengths.get(transform_id, 0)
        return 0
        
    def generate_nonce(self, min_length: int = 16) -> bytes:
        """Generate a random nonce"""
        length = max(min_length, 16)
        return os.urandom(length)
        
    def generate_spi(self) -> bytes:
        """Generate a random SPI"""
        return os.urandom(8)