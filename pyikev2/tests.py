"""
pyIKEv2 Test Suite
"""

import unittest
import os
import struct
import ipaddress
from .const import *
from .message import Message
from .payloads import *
from .crypto import CryptoEngine
from .state import IKEv2SA, IKEv2State
from .config import Config

class TestMessage(unittest.TestCase):
    """Test IKEv2 Message encoding/decoding"""
    
    def test_message_encode_decode(self):
        """Test message encoding and decoding"""
        msg = Message(
            spi_i=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            spi_r=b'\x08\x07\x06\x05\x04\x03\x02\x01',
            exchange_type=ExchangeType.IKE_SA_INIT,
            is_initiator=True,
            is_response=False,
            message_id=0
        )
        
        encoded = msg.encode()
        self.assertEqual(len(encoded), IKE_HEADER_SIZE)
        
        decoded = Message()
        decoded.decode(encoded)
        
        self.assertEqual(decoded.spi_i, msg.spi_i)
        self.assertEqual(decoded.spi_r, msg.spi_r)
        self.assertEqual(decoded.exchange_type, msg.exchange_type)
        self.assertEqual(decoded.message_id, msg.message_id)
        
    def test_message_with_payloads(self):
        """Test message with payloads"""
        msg = Message(exchange_type=ExchangeType.IKE_SA_INIT)
        
        sa_payload = SAPayload()
        ke_payload = KEPayload(dh_group=TransformID.DH.MODP_2048, ke_data=os.urandom(256))
        nonce_payload = NoncePayload(nonce=os.urandom(32))
        
        msg.add_payload(sa_payload)
        msg.add_payload(ke_payload)
        msg.add_payload(nonce_payload)
        
        encoded = msg.encode()
        self.assertGreater(len(encoded), IKE_HEADER_SIZE)
        
        decoded = Message()
        decoded.decode(encoded)
        
        self.assertEqual(len(decoded.payloads), 3)

class TestPayloads(unittest.TestCase):
    """Test IKEv2 Payloads"""
    
    def test_sa_payload(self):
        """Test SA payload encoding/decoding"""
        transforms = [
            Transform(TransformType.ENCR, TransformID.ENCR.AES_CBC, [(14, 128)]),
            Transform(TransformType.PRF, TransformID.PRF.HMAC_SHA256),
            Transform(TransformType.INTEG, TransformID.INTEG.AUTH_HMAC_SHA256_128),
            Transform(TransformType.DH, TransformID.DH.MODP_2048),
        ]
        
        proposal = Proposal(
            num=1,
            protocol_id=ProtocolID.IKE,
            transforms=transforms
        )
        
        sa_payload = SAPayload([proposal])
        encoded = sa_payload.encode()
        
        decoded = SAPayload()
        decoded.decode(encoded)
        
        self.assertEqual(len(decoded.proposals), 1)
        self.assertEqual(len(decoded.proposals[0].transforms), 4)
        
    def test_ke_payload(self):
        """Test KE payload encoding/decoding"""
        ke_data = os.urandom(256)
        ke_payload = KEPayload(dh_group=TransformID.DH.MODP_2048, ke_data=ke_data)
        
        encoded = ke_payload.encode()
        
        decoded = KEPayload()
        decoded.decode(encoded)
        
        self.assertEqual(decoded.dh_group, TransformID.DH.MODP_2048)
        self.assertEqual(decoded.ke_data, ke_data)
        
    def test_nonce_payload(self):
        """Test Nonce payload encoding/decoding"""
        nonce = os.urandom(32)
        nonce_payload = NoncePayload(nonce=nonce)
        
        encoded = nonce_payload.encode()
        
        decoded = NoncePayload()
        decoded.decode(encoded)
        
        self.assertEqual(decoded.nonce, nonce)
        
    def test_id_payload(self):
        """Test ID payload with different identity types"""
        test_cases = [
            (ipaddress.IPv4Address('192.168.1.1'), IDType.IPV4_ADDR),
            (ipaddress.IPv6Address('2001:db8::1'), IDType.IPV6_ADDR),
            ('user@example.com', IDType.RFC822_ADDR),
            ('www.example.com', IDType.FQDN),
            (b'test-key-id', IDType.KEY_ID),
        ]
        
        for identity, expected_type in test_cases:
            id_payload = IDPayload()
            id_payload.set_identity(identity)
            
            self.assertEqual(id_payload.id_type, expected_type)
            
            encoded = id_payload.encode()
            decoded = IDPayload()
            decoded.decode(encoded)
            
            self.assertEqual(decoded.id_type, expected_type)
            
    def test_notify_payload(self):
        """Test Notify payload encoding/decoding"""
        notify = NotifyPayload(
            protocol_id=ProtocolID.IKE,
            notify_type=NotifyType.COOKIE,
            spi=b'\x12\x34\x56\x78',
            notify_data=b'test-cookie-data'
        )
        
        encoded = notify.encode()
        
        decoded = NotifyPayload()
        decoded.decode(encoded)
        
        self.assertEqual(decoded.protocol_id, ProtocolID.IKE)
        self.assertEqual(decoded.notify_type, NotifyType.COOKIE)
        self.assertEqual(decoded.spi, b'\x12\x34\x56\x78')
        self.assertEqual(decoded.notify_data, b'test-cookie-data')
        
    def test_traffic_selector(self):
        """Test Traffic Selector encoding/decoding"""
        ts = TrafficSelector(
            ts_type=TSType.IPV4_ADDR_RANGE,
            ip_proto=6,
            start_port=80,
            end_port=443,
            start_addr=ipaddress.IPv4Address('10.0.0.0'),
            end_addr=ipaddress.IPv4Address('10.255.255.255')
        )
        
        encoded = ts.encode()
        
        decoded = TrafficSelector()
        decoded.decode(encoded)
        
        self.assertEqual(decoded.ts_type, TSType.IPV4_ADDR_RANGE)
        self.assertEqual(decoded.ip_protocol, 6)
        self.assertEqual(decoded.start_port, 80)
        self.assertEqual(decoded.end_port, 443)
        self.assertEqual(decoded.start_addr, ipaddress.IPv4Address('10.0.0.0'))
        self.assertEqual(decoded.end_addr, ipaddress.IPv4Address('10.255.255.255'))

class TestCrypto(unittest.TestCase):
    """Test Cryptographic operations"""
    
    def setUp(self):
        self.crypto = CryptoEngine()
        
    def test_prf(self):
        """Test PRF function"""
        key = b'test-key'
        data = b'test-data'
        
        result = self.crypto.prf(key, data, TransformID.PRF.HMAC_SHA256)
        self.assertEqual(len(result), 32)
        
        result2 = self.crypto.prf(key, data, TransformID.PRF.HMAC_SHA256)
        self.assertEqual(result, result2)
        
    def test_prf_plus(self):
        """Test PRF+ function"""
        key = b'test-key'
        data = b'test-data'
        
        result = self.crypto.prf_plus(key, data, TransformID.PRF.HMAC_SHA256, 100)
        self.assertEqual(len(result), 100)
        
    def test_dh_exchange(self):
        """Test DH key exchange"""
        for dh_group in [TransformID.DH.MODP_2048, TransformID.DH.ECP_256]:
            public1, private1 = self.crypto.generate_dh_keypair(dh_group)
            public2, private2 = self.crypto.generate_dh_keypair(dh_group)
            
            shared1 = self.crypto.compute_dh_shared_secret(private1, public2, dh_group)
            shared2 = self.crypto.compute_dh_shared_secret(private2, public1, dh_group)
            
            self.assertEqual(shared1, shared2)
            
    def test_encryption_decryption(self):
        """Test encryption and decryption"""
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b'This is a test message for encryption'
        
        for encr_id in [TransformID.ENCR.AES_CBC, TransformID.ENCR.AES_CTR]:
            if encr_id == TransformID.ENCR.AES_CBC:
                integ_key = os.urandom(32)
                integ_id = TransformID.INTEG.AUTH_HMAC_SHA256_128
            else:
                integ_key = None
                integ_id = None
                
            ciphertext = self.crypto.encrypt(key, iv, plaintext, encr_id, integ_key, integ_id)
            decrypted = self.crypto.decrypt(key, iv, ciphertext, encr_id, integ_key, integ_id)
            
            self.assertEqual(plaintext, decrypted)
            
    def test_aead_encryption(self):
        """Test AEAD encryption (AES-GCM)"""
        key = os.urandom(16)
        iv = os.urandom(12)
        plaintext = b'Test message for AEAD encryption'
        
        ciphertext = self.crypto.encrypt(key, iv, plaintext, TransformID.ENCR.AES_GCM_16)
        decrypted = self.crypto.decrypt(key, iv, ciphertext, TransformID.ENCR.AES_GCM_16)
        
        self.assertEqual(plaintext, decrypted)

class TestState(unittest.TestCase):
    """Test IKEv2 State Machine"""
    
    def setUp(self):
        self.config = {
            'my_id': 'test@example.com',
            'psk': 'test-pre-shared-key',
            'proposals': [{
                'encryption': [{'id': TransformID.ENCR.AES_CBC, 'key_length': 128}],
                'integrity': [TransformID.INTEG.AUTH_HMAC_SHA256_128],
                'prf': [TransformID.PRF.HMAC_SHA256],
                'dh_group': [TransformID.DH.MODP_2048],
            }]
        }
        
    def test_sa_creation(self):
        """Test SA creation"""
        sa = IKEv2SA(self.config, is_initiator=True)
        
        self.assertIsNotNone(sa.spi_i)
        self.assertIsNone(sa.spi_r)
        self.assertEqual(sa.state, IKEv2State.INITIAL)
        self.assertTrue(sa.is_initiator)
        
    def test_build_ike_sa_init_request(self):
        """Test building IKE_SA_INIT request"""
        sa = IKEv2SA(self.config, is_initiator=True)
        
        message = sa.build_ike_sa_init_request()
        
        self.assertEqual(message.exchange_type, ExchangeType.IKE_SA_INIT)
        self.assertTrue(message.is_request())
        self.assertIsNotNone(message.get_payload(PayloadType.SA))
        self.assertIsNotNone(message.get_payload(PayloadType.KE))
        self.assertIsNotNone(message.get_payload(PayloadType.NONCE))
        self.assertEqual(sa.state, IKEv2State.IKE_SA_INIT_SENT)
        
    def test_proposal_selection(self):
        """Test proposal selection"""
        initiator_sa = IKEv2SA(self.config, is_initiator=True)
        responder_sa = IKEv2SA(self.config, is_initiator=False)
        
        selected = responder_sa._select_proposal(initiator_sa.proposals)
        
        self.assertIsNotNone(selected)
        self.assertEqual(responder_sa.encr_id, TransformID.ENCR.AES_CBC)
        self.assertEqual(responder_sa.integ_id, TransformID.INTEG.AUTH_HMAC_SHA256_128)
        self.assertEqual(responder_sa.prf_id, TransformID.PRF.HMAC_SHA256)
        self.assertEqual(responder_sa.dh_group, TransformID.DH.MODP_2048)

class TestConfig(unittest.TestCase):
    """Test Configuration Management"""
    
    def test_default_config(self):
        """Test default configuration"""
        config = Config()
        
        self.assertEqual(config.get('daemon.local_port'), 500)
        self.assertEqual(config.get('daemon.nat_port'), 4500)
        self.assertEqual(config.get('daemon.log_level'), 'INFO')
        
    def test_config_get_set(self):
        """Test configuration get/set"""
        config = Config()
        
        config.set('test.key', 'test-value')
        self.assertEqual(config.get('test.key'), 'test-value')
        
        config.set('test.nested.key', 42)
        self.assertEqual(config.get('test.nested.key'), 42)
        
    def test_add_connection(self):
        """Test adding connection configuration"""
        config = Config()
        
        conn_config = {
            'type': 'tunnel',
            'auth_method': 'psk',
            'psk': 'secret-key'
        }
        
        config.add_connection('test-conn', conn_config)
        retrieved = config.get_connection('test-conn')
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved['auth_method'], 'psk')
        
    def test_transform_name_conversion(self):
        """Test transform name to ID conversion"""
        config = Config()
        
        self.assertEqual(config._get_encryption_id('aes256-cbc'), TransformID.ENCR.AES_CBC)
        self.assertEqual(config._get_encryption_id('chacha20-poly1305'), TransformID.ENCR.CHACHA20_POLY1305)
        
        self.assertEqual(config._get_integrity_id('hmac-sha256-128'), TransformID.INTEG.AUTH_HMAC_SHA256_128)
        self.assertEqual(config._get_integrity_id('hmac-sha1-96'), TransformID.INTEG.AUTH_HMAC_SHA1_96)
        
        self.assertEqual(config._get_prf_id('hmac-sha256'), TransformID.PRF.HMAC_SHA256)
        
        self.assertEqual(config._get_dh_group_id('modp2048'), TransformID.DH.MODP_2048)
        self.assertEqual(config._get_dh_group_id('curve25519'), TransformID.DH.CURVE25519)

class TestSuite(unittest.TestCase):
    """Main test suite"""
    pass

def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestMessage))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloads))
    suite.addTests(loader.loadTestsFromTestCase(TestCrypto))
    suite.addTests(loader.loadTestsFromTestCase(TestState))
    suite.addTests(loader.loadTestsFromTestCase(TestConfig))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    unittest.main()