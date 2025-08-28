"""
IKEv2 Message structure implementation
"""

import struct
import os
from typing import List, Optional, Tuple
from .const import *
from .payloads import Payload, parse_payload

class Message:
    """IKEv2 Message structure"""
    
    def __init__(self, spi_i=None, spi_r=None, exchange_type=ExchangeType.IKE_SA_INIT,
                 is_initiator=True, is_response=False, message_id=0):
        self.spi_i = spi_i or os.urandom(8)
        self.spi_r = spi_r or b'\x00' * 8
        self.next_payload = PayloadType.NO_NEXT_PAYLOAD
        self.version = IKE_VERSION
        self.exchange_type = exchange_type
        self.flags = 0
        self.message_id = message_id
        self.payloads = []
        
        if is_initiator:
            self.flags |= FLAGS_INITIATOR
        if is_response:
            self.flags |= FLAGS_RESPONSE
            
    def add_payload(self, payload: Payload):
        """Add a payload to the message"""
        if self.payloads:
            self.payloads[-1].next_payload = self._get_payload_type(payload)
        else:
            self.next_payload = self._get_payload_type(payload)
        self.payloads.append(payload)
        
    def encode(self) -> bytes:
        """Encode message to bytes"""
        payload_data = b''
        
        for i, payload in enumerate(self.payloads):
            if i < len(self.payloads) - 1:
                next_type = self._get_payload_type(self.payloads[i + 1])
                payload.next_payload = next_type
            else:
                payload.next_payload = PayloadType.NO_NEXT_PAYLOAD
                
            payload_data += payload.encode()
            
        length = IKE_HEADER_SIZE + len(payload_data)
        
        header = struct.pack('!8s8sBBBBLL',
                           self.spi_i,
                           self.spi_r,
                           self.next_payload if self.payloads else 0,
                           self.version,
                           self.exchange_type,
                           self.flags,
                           self.message_id,
                           length)
                           
        return header + payload_data
        
    def decode(self, data: bytes) -> bool:
        """Decode message from bytes"""
        if len(data) < IKE_HEADER_SIZE:
            raise ValueError(f"Message too short: {len(data)} bytes")
            
        header = struct.unpack('!8s8sBBBBLL', data[:IKE_HEADER_SIZE])
        
        self.spi_i = header[0]
        self.spi_r = header[1]
        self.next_payload = header[2]
        self.version = header[3]
        self.exchange_type = header[4]
        self.flags = header[5]
        self.message_id = header[6]
        length = header[7]
        
        if self.version != IKE_VERSION:
            raise ValueError(f"Unsupported IKE version: {self.version >> 4}.{self.version & 0x0f}")
            
        if length != len(data):
            raise ValueError(f"Length mismatch: header says {length}, got {len(data)}")
            
        payload_data = data[IKE_HEADER_SIZE:]
        self.payloads = []
        
        next_payload_type = self.next_payload
        offset = 0
        
        while next_payload_type != PayloadType.NO_NEXT_PAYLOAD and offset < len(payload_data):
            if offset + 4 > len(payload_data):
                break
                
            pl_next, pl_flags, pl_length = struct.unpack('!BBH', payload_data[offset:offset+4])
            
            if offset + pl_length > len(payload_data):
                raise ValueError(f"Payload length exceeds message bounds")
                
            payload_bytes = payload_data[offset:offset+pl_length]
            payload = parse_payload(next_payload_type, payload_bytes)
            
            if payload:
                payload.critical = bool(pl_flags & 0x80)
                self.payloads.append(payload)
                
            offset += pl_length
            next_payload_type = pl_next
            
        return True
        
    def is_request(self) -> bool:
        """Check if message is a request"""
        return not bool(self.flags & FLAGS_RESPONSE)
        
    def is_response(self) -> bool:
        """Check if message is a response"""
        return bool(self.flags & FLAGS_RESPONSE)
        
    def is_initiator(self) -> bool:
        """Check if message is from initiator"""
        return bool(self.flags & FLAGS_INITIATOR)
        
    def get_payload(self, payload_type: PayloadType) -> Optional[Payload]:
        """Get first payload of specified type"""
        for payload in self.payloads:
            if self._get_payload_type(payload) == payload_type:
                return payload
        return None
        
    def get_payloads(self, payload_type: PayloadType) -> List[Payload]:
        """Get all payloads of specified type"""
        return [p for p in self.payloads if self._get_payload_type(p) == payload_type]
        
    def _get_payload_type(self, payload: Payload) -> PayloadType:
        """Get payload type from payload instance"""
        from .payloads import (SAPayload, KEPayload, IDPayload, AuthPayload,
                              NoncePayload, NotifyPayload, DeletePayload,
                              VendorIDPayload, TSPayload, SKPayload,
                              CPPayload, EAPPayload, CertPayload, CertReqPayload)
        
        type_map = {
            SAPayload: PayloadType.SA,
            KEPayload: PayloadType.KE,
            IDPayload: PayloadType.IDI,
            AuthPayload: PayloadType.AUTH,
            NoncePayload: PayloadType.NONCE,
            NotifyPayload: PayloadType.NOTIFY,
            DeletePayload: PayloadType.DELETE,
            VendorIDPayload: PayloadType.VENDOR,
            TSPayload: PayloadType.TSI,
            SKPayload: PayloadType.SK,
            CPPayload: PayloadType.CP,
            EAPPayload: PayloadType.EAP,
            CertPayload: PayloadType.CERT,
            CertReqPayload: PayloadType.CERTREQ,
        }
        
        for cls, ptype in type_map.items():
            if isinstance(payload, cls):
                return ptype
                
        return PayloadType.NO_NEXT_PAYLOAD
        
    def __repr__(self) -> str:
        return (f"Message(exchange={self.exchange_type.name}, "
                f"initiator={'Y' if self.is_initiator() else 'N'}, "
                f"response={'Y' if self.is_response() else 'N'}, "
                f"msg_id={self.message_id}, "
                f"payloads={len(self.payloads)})")
                
    def __bytes__(self) -> bytes:
        return self.encode()