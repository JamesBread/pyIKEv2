"""
IKEv2 Payload implementations according to RFC 7296

RFC 7296 - Generic Payload Header:

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       Payload Data                            ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   C = Critical flag (bit 7 of Flags field)
"""

import struct
import socket
import ipaddress
from typing import List, Optional, Union, Tuple
from .const import *

class Payload:
    """Base class for all IKEv2 payloads"""
    
    def __init__(self, next_payload=PayloadType.NO_NEXT_PAYLOAD, critical=False):
        self.next_payload = next_payload
        self.critical = critical
        self.reserved = 0
        
    def encode(self) -> bytes:
        """Encode payload to bytes"""
        raise NotImplementedError
        
    def decode(self, data: bytes):
        """Decode payload from bytes"""
        raise NotImplementedError
        
    def __bytes__(self) -> bytes:
        return self.encode()
    
    def get_header(self, payload_length: int) -> bytes:
        """Generate generic payload header"""
        flags = 0x80 if self.critical else 0
        return struct.pack('!BBH', self.next_payload, flags, payload_length)

class SAPayload(Payload):
    """
    Security Association Payload
    
    SA Payload contains one or more Proposal substructures
    """
    
    def __init__(self, proposals: List['Proposal'] = None):
        super().__init__()
        self.proposals = proposals or []
        
    def encode(self) -> bytes:
        data = b''
        for i, proposal in enumerate(self.proposals):
            is_last = (i == len(self.proposals) - 1)
            data += proposal.encode(is_last)
        
        header = self.get_header(len(data) + 4)
        return header + data
        
    def decode(self, data: bytes):
        offset = 4
        self.proposals = []
        
        while offset < len(data):
            proposal = Proposal()
            prop_len = proposal.decode(data[offset:])
            self.proposals.append(proposal)
            offset += prop_len
            
            if proposal.proposal_num == 0:
                break

class Proposal:
    """
    Proposal substructure
    
    Format: | 0/2 | Res | Length | Prop# | Proto | SPISize | #Trans | SPI | Transforms |
    """
    
    def __init__(self, num=1, protocol_id=ProtocolID.IKE, spi=b'', transforms=None):
        self.proposal_num = num
        self.protocol_id = protocol_id
        self.spi = spi
        self.transforms = transforms or []
        
    def encode(self, is_last=False) -> bytes:
        next_proposal = 0 if is_last else 2
        spi_size = len(self.spi)
        num_transforms = len(self.transforms)
        
        # Build the data part first
        data = self.spi
        for i, transform in enumerate(self.transforms):
            is_last_transform = (i == len(self.transforms) - 1)
            data += transform.encode(is_last_transform)
            
        # Total length includes the 8-byte header
        proposal_length = 8 + len(data)
        
        # Build the 8-byte header
        header = struct.pack('!BBHBBBB', 
                           next_proposal, 0, proposal_length,
                           self.proposal_num, self.protocol_id,
                           spi_size, num_transforms)
        
        return header + data
        
    def decode(self, data: bytes) -> int:
        if len(data) < 8:
            raise ValueError("Invalid proposal data")
            
        next_proposal, _, prop_length = struct.unpack('!BBH', data[:4])
        self.proposal_num, self.protocol_id, spi_size, num_transforms = struct.unpack('!BBBB', data[4:8])
        
        offset = 8
        if spi_size > 0:
            self.spi = data[offset:offset + spi_size]
            offset += spi_size
            
        self.transforms = []
        for _ in range(num_transforms):
            transform = Transform()
            trans_len = transform.decode(data[offset:])
            self.transforms.append(transform)
            offset += trans_len
            
        return prop_length

class Transform:
    """
    Transform substructure
    
    Format: | 0/3 | Res | Length | Type | Res | Transform ID | Attributes |
    """
    
    def __init__(self, transform_type=None, transform_id=None, attributes=None):
        self.transform_type = transform_type
        self.transform_id = transform_id
        self.attributes = attributes or []
        
    def encode(self, is_last=False) -> bytes:
        next_transform = 0 if is_last else 3
        
        attr_data = b''
        for attr_type, attr_value in self.attributes:
            if isinstance(attr_value, int) and attr_value < 65536:
                attr_data += struct.pack('!HH', 0x8000 | attr_type, attr_value)
            else:
                if isinstance(attr_value, int):
                    value_bytes = attr_value.to_bytes((attr_value.bit_length() + 7) // 8, 'big')
                else:
                    value_bytes = attr_value
                attr_data += struct.pack('!HH', attr_type, len(value_bytes)) + value_bytes
                
        transform_length = 8 + len(attr_data)
        return struct.pack('!BBHHH', next_transform, 0, transform_length,
                         self.transform_type, self.transform_id) + attr_data
                         
    def decode(self, data: bytes) -> int:
        if len(data) < 8:
            raise ValueError("Invalid transform data")
            
        next_transform, _, trans_length, self.transform_type, self.transform_id = struct.unpack('!BBHHH', data[:8])
        
        offset = 8
        self.attributes = []
        
        while offset < trans_length:
            attr_type, attr_len = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            
            if attr_type & 0x8000:
                attr_type &= 0x7fff
                self.attributes.append((attr_type, attr_len))
            else:
                attr_value = data[offset:offset+attr_len]
                self.attributes.append((attr_type, attr_value))
                offset += attr_len
                
        return trans_length

class KEPayload(Payload):
    """
    Key Exchange Payload
    
    Format: | DH Group # | RESERVED | Key Exchange Data |
    """
    
    def __init__(self, dh_group=0, ke_data=b''):
        super().__init__()
        self.dh_group = dh_group
        self.ke_data = ke_data
        
    def encode(self) -> bytes:
        payload_data = struct.pack('!HH', self.dh_group, 0) + self.ke_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid KE payload")
        self.dh_group = struct.unpack('!H', data[4:6])[0]
        self.ke_data = data[8:]

class NoncePayload(Payload):
    """
    Nonce Payload
    
    Format: | Nonce Data (16-256 bytes) |
    """
    
    def __init__(self, nonce=b''):
        super().__init__()
        self.nonce = nonce
        
    def encode(self) -> bytes:
        header = self.get_header(len(self.nonce) + 4)
        return header + self.nonce
        
    def decode(self, data: bytes):
        if len(data) < 4:
            raise ValueError("Invalid Nonce payload")
        self.nonce = data[4:]

class IDPayload(Payload):
    """
    Identification Payload
    
    Format: | ID Type | RESERVED | Identification Data |
    """
    
    def __init__(self, id_type=IDType.IPV4_ADDR, id_data=b''):
        super().__init__()
        self.id_type = id_type
        self.id_data = id_data
        
    def encode(self) -> bytes:
        payload_data = struct.pack('!BBH', self.id_type, 0, 0) + self.id_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid ID payload")
        self.id_type = data[4]
        self.id_data = data[8:]
        
    def set_identity(self, identity: Union[str, bytes, ipaddress.IPv4Address, ipaddress.IPv6Address]):
        """Set identity based on type"""
        if isinstance(identity, ipaddress.IPv4Address):
            self.id_type = IDType.IPV4_ADDR
            self.id_data = identity.packed
        elif isinstance(identity, ipaddress.IPv6Address):
            self.id_type = IDType.IPV6_ADDR
            self.id_data = identity.packed
        elif isinstance(identity, str):
            if '@' in identity:
                self.id_type = IDType.RFC822_ADDR
                self.id_data = identity.encode()
            else:
                self.id_type = IDType.FQDN
                self.id_data = identity.encode()
        elif isinstance(identity, bytes):
            self.id_type = IDType.KEY_ID
            self.id_data = identity

class AuthPayload(Payload):
    """
    Authentication Payload
    
    Format: | Auth Method | RESERVED | Authentication Data |
    """
    
    def __init__(self, auth_method=AuthMethod.SHARED_KEY, auth_data=b''):
        super().__init__()
        self.auth_method = auth_method
        self.auth_data = auth_data
        
    def encode(self) -> bytes:
        payload_data = struct.pack('!BBH', self.auth_method, 0, 0) + self.auth_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid Auth payload")
        self.auth_method = data[4]
        self.auth_data = data[8:]

class CertPayload(Payload):
    """Certificate Payload"""
    
    def __init__(self, cert_encoding=CertificateEncoding.X509_CERT_SIGNATURE, cert_data=b''):
        super().__init__()
        self.cert_encoding = cert_encoding
        self.cert_data = cert_data
        
    def encode(self) -> bytes:
        payload_data = struct.pack('!B', self.cert_encoding) + self.cert_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 5:
            raise ValueError("Invalid Cert payload")
        self.cert_encoding = data[4]
        self.cert_data = data[5:]

class CertReqPayload(Payload):
    """Certificate Request Payload"""
    
    def __init__(self, cert_encoding=CertificateEncoding.X509_CERT_SIGNATURE, ca_data=b''):
        super().__init__()
        self.cert_encoding = cert_encoding
        self.ca_data = ca_data
        
    def encode(self) -> bytes:
        payload_data = struct.pack('!B', self.cert_encoding) + self.ca_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 5:
            raise ValueError("Invalid CertReq payload")
        self.cert_encoding = data[4]
        self.ca_data = data[5:]

class NotifyPayload(Payload):
    """
    Notify Payload
    
    Format: | Protocol ID | SPI Size | Notify Type | SPI | Notification Data |
    """
    
    def __init__(self, protocol_id=ProtocolID.IKE, notify_type=0, spi=b'', notify_data=b''):
        super().__init__()
        self.protocol_id = protocol_id
        self.notify_type = notify_type
        self.spi = spi
        self.notify_data = notify_data
        
    def encode(self) -> bytes:
        spi_size = len(self.spi)
        # Reserved field is 2 bytes after notify_type
        payload_data = struct.pack('!BBH', self.protocol_id, spi_size, 
                                  self.notify_type) + self.spi + self.notify_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid Notify payload")
        # Skip reserved field at data[5:8]
        self.protocol_id = data[4]
        spi_size = data[5]
        self.notify_type = struct.unpack('!H', data[6:8])[0]
        offset = 8
        if spi_size > 0:
            self.spi = data[offset:offset + spi_size]
            offset += spi_size
        self.notify_data = data[offset:]

class DeletePayload(Payload):
    """
    Delete Payload
    
    Format: | Protocol ID | SPI Size | Num SPIs | SPIs |
    """
    
    def __init__(self, protocol_id=ProtocolID.IKE, spis=None):
        super().__init__()
        self.protocol_id = protocol_id
        self.spis = spis or []
        
    def encode(self) -> bytes:
        if not self.spis:
            spi_size = 0
            spi_data = b''
        else:
            spi_size = len(self.spis[0])
            spi_data = b''.join(self.spis)
            
        num_spis = len(self.spis)
        payload_data = struct.pack('!BBHH', self.protocol_id, spi_size,
                                  num_spis, 0) + spi_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid Delete payload")
        self.protocol_id, spi_size, num_spis = struct.unpack('!BBH', data[4:8])
        
        offset = 8
        self.spis = []
        for _ in range(num_spis):
            if offset + spi_size > len(data):
                break
            self.spis.append(data[offset:offset + spi_size])
            offset += spi_size

class VendorIDPayload(Payload):
    """Vendor ID Payload"""
    
    def __init__(self, vendor_id=b''):
        super().__init__()
        self.vendor_id = vendor_id
        
    def encode(self) -> bytes:
        header = self.get_header(len(self.vendor_id) + 4)
        return header + self.vendor_id
        
    def decode(self, data: bytes):
        if len(data) < 4:
            raise ValueError("Invalid VendorID payload")
        self.vendor_id = data[4:]

class TSPayload(Payload):
    """Traffic Selector Payload"""
    
    def __init__(self, traffic_selectors=None):
        super().__init__()
        self.traffic_selectors = traffic_selectors or []
        
    def encode(self) -> bytes:
        num_ts = len(self.traffic_selectors)
        ts_data = b''
        
        for ts in self.traffic_selectors:
            ts_data += ts.encode()
            
        payload_data = struct.pack('!BBH', num_ts, 0, 0) + ts_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid TS payload")
        num_ts = data[4]
        
        offset = 8
        self.traffic_selectors = []
        for _ in range(num_ts):
            ts = TrafficSelector()
            ts_len = ts.decode(data[offset:])
            self.traffic_selectors.append(ts)
            offset += ts_len

class TrafficSelector:
    """
    Traffic Selector substructure
    
    Format: | TS Type | IP Proto | Length | Start Port | End Port | Start Addr | End Addr |
    """
    
    def __init__(self, ts_type=TSType.IPV4_ADDR_RANGE, ip_proto=0,
                 start_port=0, end_port=65535, start_addr=None, end_addr=None):
        self.ts_type = ts_type
        self.ip_protocol = ip_proto
        self.start_port = start_port
        self.end_port = end_port
        self.start_addr = start_addr
        self.end_addr = end_addr
        
    def encode(self) -> bytes:
        if self.ts_type == TSType.IPV4_ADDR_RANGE:
            addr_data = self.start_addr.packed + self.end_addr.packed
        elif self.ts_type == TSType.IPV6_ADDR_RANGE:
            addr_data = self.start_addr.packed + self.end_addr.packed
        else:
            addr_data = b''
            
        ts_length = 8 + len(addr_data)
        return struct.pack('!BBHBBHH', self.ts_type, self.ip_protocol, ts_length,
                         0, 0, self.start_port, self.end_port) + addr_data
                         
    def decode(self, data: bytes) -> int:
        if len(data) < 8:
            raise ValueError("Invalid TS data")
            
        self.ts_type, self.ip_protocol, ts_length = struct.unpack('!BBH', data[:4])
        # The format is: type(1), proto(1), length(2), reserved(2), start_port(2), end_port(2), addresses...
        self.start_port, self.end_port = struct.unpack('!HH', data[6:10])
        
        if self.ts_type == TSType.IPV4_ADDR_RANGE:
            self.start_addr = ipaddress.IPv4Address(data[10:14])
            self.end_addr = ipaddress.IPv4Address(data[14:18])
        elif self.ts_type == TSType.IPV6_ADDR_RANGE:
            self.start_addr = ipaddress.IPv6Address(data[10:26])
            self.end_addr = ipaddress.IPv6Address(data[26:42])
            
        return ts_length

class SKPayload(Payload):
    """
    Encrypted Payload
    
    Format: | IV | Encrypted Payloads | Padding | Pad Length | Integrity Data |
    """
    
    def __init__(self, encrypted_data=b''):
        super().__init__()
        self.encrypted_data = encrypted_data
        
    def encode(self) -> bytes:
        header = self.get_header(len(self.encrypted_data) + 4)
        return header + self.encrypted_data
        
    def decode(self, data: bytes):
        if len(data) < 4:
            raise ValueError("Invalid SK payload")
        self.encrypted_data = data[4:]

class CPPayload(Payload):
    """Configuration Payload"""
    
    def __init__(self, cfg_type=ConfigType.CFG_REQUEST, attributes=None):
        super().__init__()
        self.cfg_type = cfg_type
        self.attributes = attributes or []
        
    def encode(self) -> bytes:
        attr_data = b''
        for attr_type, attr_value in self.attributes:
            if attr_value is None:
                attr_data += struct.pack('!HH', attr_type, 0)
            else:
                if isinstance(attr_value, bytes):
                    value_bytes = attr_value
                elif isinstance(attr_value, ipaddress.IPv4Address):
                    value_bytes = attr_value.packed
                elif isinstance(attr_value, ipaddress.IPv6Address):
                    value_bytes = attr_value.packed
                else:
                    value_bytes = attr_value
                attr_data += struct.pack('!HH', attr_type, len(value_bytes)) + value_bytes
                
        payload_data = struct.pack('!BBH', self.cfg_type, 0, 0) + attr_data
        header = self.get_header(len(payload_data) + 4)
        return header + payload_data
        
    def decode(self, data: bytes):
        if len(data) < 8:
            raise ValueError("Invalid CP payload")
        self.cfg_type = data[4]
        
        offset = 8
        self.attributes = []
        while offset < len(data):
            if offset + 4 > len(data):
                break
            attr_type, attr_len = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            if attr_len > 0:
                attr_value = data[offset:offset+attr_len]
                offset += attr_len
            else:
                attr_value = None
            self.attributes.append((attr_type, attr_value))

class EAPPayload(Payload):
    """EAP Payload"""
    
    def __init__(self, eap_data=b''):
        super().__init__()
        self.eap_data = eap_data
        
    def encode(self) -> bytes:
        header = self.get_header(len(self.eap_data) + 4)
        return header + self.eap_data
        
    def decode(self, data: bytes):
        if len(data) < 4:
            raise ValueError("Invalid EAP payload")
        self.eap_data = data[4:]

def parse_payload(payload_type: int, data: bytes) -> Optional[Payload]:
    """Parse payload based on type"""
    payload_map = {
        PayloadType.SA: SAPayload,
        PayloadType.KE: KEPayload,
        PayloadType.IDI: IDPayload,
        PayloadType.IDR: IDPayload,
        PayloadType.CERT: CertPayload,
        PayloadType.CERTREQ: CertReqPayload,
        PayloadType.AUTH: AuthPayload,
        PayloadType.NONCE: NoncePayload,
        PayloadType.NOTIFY: NotifyPayload,
        PayloadType.DELETE: DeletePayload,
        PayloadType.VENDOR: VendorIDPayload,
        PayloadType.TSI: TSPayload,
        PayloadType.TSR: TSPayload,
        PayloadType.SK: SKPayload,
        PayloadType.CP: CPPayload,
        PayloadType.EAP: EAPPayload,
    }
    
    payload_class = payload_map.get(payload_type)
    if not payload_class:
        return None
        
    payload = payload_class()
    payload.decode(data)
    return payload