"""
IKEv2 State Machine and Security Association Management
"""

import os
import time
import struct
import hashlib
import ipaddress
from enum import Enum
from typing import Optional, Dict, List, Tuple, Any
from .const import *
from .message import Message
from .payloads import *
from .crypto import CryptoEngine

class IKEv2State(Enum):
    """IKEv2 SA States"""
    INITIAL = 0
    IKE_SA_INIT_SENT = 1
    IKE_SA_INIT_RECEIVED = 2
    IKE_AUTH_SENT = 3
    IKE_AUTH_RECEIVED = 4
    ESTABLISHED = 5
    REKEYING = 6
    DELETING = 7
    DELETED = 8

class ChildSAState(Enum):
    """Child SA States"""
    INITIAL = 0
    CREATED = 1
    ESTABLISHED = 2
    REKEYING = 3
    DELETING = 4
    DELETED = 5

class IKEv2SA:
    """IKEv2 Security Association"""
    
    def __init__(self, config: Dict[str, Any], is_initiator: bool = True):
        self.config = config
        self.is_initiator = is_initiator
        self.state = IKEv2State.INITIAL
        self.crypto = CryptoEngine()
        
        self.spi_i = os.urandom(8) if is_initiator else None
        self.spi_r = None if is_initiator else os.urandom(8)
        
        self.ni = None
        self.nr = None
        self.dh_private = None
        self.dh_public = None
        self.dh_shared_secret = None
        
        self.sk_d = None
        self.sk_ai = None
        self.sk_ar = None
        self.sk_ei = None
        self.sk_er = None
        self.sk_pi = None
        self.sk_pr = None
        
        self.message_id = 0
        self.peer_addr = None
        self.peer_port = None
        
        self.child_sas = {}
        self.proposals = self._build_proposals()
        
        self.encr_id = None
        self.integ_id = None
        self.prf_id = None
        self.dh_group = None
        
        self.auth_data = None
        self.peer_auth_data = None
        self.my_id = None
        self.peer_id = None
        
        self.last_message = None
        self.retransmit_count = 0
        self.last_transmit_time = 0
        
    def _build_proposals(self) -> List[Proposal]:
        """Build IKE proposals from config"""
        proposals = []
        proposal_num = 1
        
        for proposal_config in self.config.get('proposals', [self._get_default_proposal()]):
            transforms = []
            
            if 'encryption' in proposal_config:
                for encr in proposal_config['encryption']:
                    transform = Transform(
                        transform_type=TransformType.ENCR,
                        transform_id=encr['id'],
                        attributes=[(14, encr['key_length'])] if 'key_length' in encr else []
                    )
                    transforms.append(transform)
                    
            if 'integrity' in proposal_config:
                for integ in proposal_config['integrity']:
                    transform = Transform(
                        transform_type=TransformType.INTEG,
                        transform_id=integ
                    )
                    transforms.append(transform)
                    
            if 'prf' in proposal_config:
                for prf in proposal_config['prf']:
                    transform = Transform(
                        transform_type=TransformType.PRF,
                        transform_id=prf
                    )
                    transforms.append(transform)
                    
            if 'dh_group' in proposal_config:
                for dh in proposal_config['dh_group']:
                    transform = Transform(
                        transform_type=TransformType.DH,
                        transform_id=dh
                    )
                    transforms.append(transform)
                    
            proposal = Proposal(
                num=proposal_num,
                protocol_id=ProtocolID.IKE,
                transforms=transforms
            )
            proposals.append(proposal)
            proposal_num += 1
            
        return proposals
        
    def _get_default_proposal(self) -> Dict:
        """Get default IKE proposal"""
        return {
            'encryption': [
                {'id': TransformID.ENCR.AES_CBC, 'key_length': 128},
                {'id': TransformID.ENCR.AES_CBC, 'key_length': 256},
            ],
            'integrity': [
                TransformID.INTEG.AUTH_HMAC_SHA256_128,
                TransformID.INTEG.AUTH_HMAC_SHA1_96,
            ],
            'prf': [
                TransformID.PRF.HMAC_SHA256,
                TransformID.PRF.HMAC_SHA1,
            ],
            'dh_group': [
                TransformID.DH.MODP_2048,
                TransformID.DH.ECP_256,
            ],
        }
        
    def process_ike_sa_init_request(self, message: Message) -> Optional[Message]:
        """Process IKE_SA_INIT request"""
        if self.state != IKEv2State.INITIAL:
            return None
            
        self.spi_i = message.spi_i
        self.spi_r = os.urandom(8) if not self.spi_r else self.spi_r
        self.peer_addr = message.peer_addr if hasattr(message, 'peer_addr') else None
        self.peer_port = message.peer_port if hasattr(message, 'peer_port') else None
        
        sa_payload = message.get_payload(PayloadType.SA)
        if not sa_payload:
            return self._build_notify_response(message, NotifyType.INVALID_SYNTAX)
            
        selected_proposal = self._select_proposal(sa_payload.proposals)
        if not selected_proposal:
            return self._build_notify_response(message, NotifyType.NO_PROPOSAL_CHOSEN)
            
        ke_payload = message.get_payload(PayloadType.KE)
        if not ke_payload:
            return self._build_notify_response(message, NotifyType.INVALID_SYNTAX)
            
        if ke_payload.dh_group != self.dh_group:
            return self._build_notify_response(message, NotifyType.INVALID_KE_PAYLOAD,
                                              struct.pack('!H', self.dh_group))
                                              
        nonce_payload = message.get_payload(PayloadType.NONCE)
        if not nonce_payload:
            return self._build_notify_response(message, NotifyType.INVALID_SYNTAX)
            
        self.ni = nonce_payload.nonce
        
        try:
            self.dh_shared_secret = self.crypto.compute_dh_shared_secret(
                self.dh_private, ke_payload.ke_data, self.dh_group
            )
        except Exception:
            return self._build_notify_response(message, NotifyType.INVALID_KE_PAYLOAD)
            
        response = self._build_ike_sa_init_response(message, selected_proposal)
        
        self._derive_keys(message.encode(), response.encode())
        
        self.state = IKEv2State.IKE_SA_INIT_RECEIVED
        self.last_message = response
        
        return response
        
    def process_ike_sa_init_response(self, message: Message) -> bool:
        """Process IKE_SA_INIT response"""
        if self.state != IKEv2State.IKE_SA_INIT_SENT:
            return False
            
        self.spi_r = message.spi_r
        
        sa_payload = message.get_payload(PayloadType.SA)
        if not sa_payload:
            return False
            
        if not self._verify_selected_proposal(sa_payload.proposals[0]):
            return False
            
        ke_payload = message.get_payload(PayloadType.KE)
        if not ke_payload:
            return False
            
        nonce_payload = message.get_payload(PayloadType.NONCE)
        if not nonce_payload:
            return False
            
        self.nr = nonce_payload.nonce
        
        try:
            self.dh_shared_secret = self.crypto.compute_dh_shared_secret(
                self.dh_private, ke_payload.ke_data, self.dh_group
            )
        except Exception:
            return False
            
        init_request = self.last_message.encode()
        init_response = message.encode()
        
        self._derive_keys(init_request, init_response)
        
        self.state = IKEv2State.IKE_AUTH_SENT
        return True
        
    def process_ike_auth_request(self, message: Message) -> Optional[Message]:
        """Process IKE_AUTH request"""
        if self.state != IKEv2State.IKE_SA_INIT_RECEIVED:
            return None
            
        sk_payload = message.get_payload(PayloadType.SK)
        if not sk_payload:
            return None
            
        try:
            decrypted = self._decrypt_sk_payload(sk_payload, False)
        except Exception:
            return None
            
        inner_message = Message()
        inner_message.decode(decrypted)
        
        id_payload = inner_message.get_payload(PayloadType.IDI)
        if not id_payload:
            return self._build_encrypted_notify(message, NotifyType.INVALID_SYNTAX)
            
        self.peer_id = id_payload.id_data
        
        auth_payload = inner_message.get_payload(PayloadType.AUTH)
        if not auth_payload:
            return self._build_encrypted_notify(message, NotifyType.INVALID_SYNTAX)
            
        if not self._verify_auth(auth_payload, False):
            return self._build_encrypted_notify(message, NotifyType.AUTHENTICATION_FAILED)
            
        sa_payload = inner_message.get_payload(PayloadType.SA)
        tsi_payload = inner_message.get_payload(PayloadType.TSI)
        tsr_payload = inner_message.get_payload(PayloadType.TSR)
        
        if sa_payload and tsi_payload and tsr_payload:
            child_sa = self._create_child_sa(sa_payload, tsi_payload, tsr_payload)
            if not child_sa:
                return self._build_encrypted_notify(message, NotifyType.NO_PROPOSAL_CHOSEN)
                
        response = self._build_ike_auth_response(message)
        
        self.state = IKEv2State.ESTABLISHED
        self.message_id += 1
        
        return response
        
    def process_ike_auth_response(self, message: Message) -> bool:
        """Process IKE_AUTH response"""
        if self.state != IKEv2State.IKE_AUTH_SENT:
            return False
            
        sk_payload = message.get_payload(PayloadType.SK)
        if not sk_payload:
            return False
            
        try:
            decrypted = self._decrypt_sk_payload(sk_payload, True)
        except Exception:
            return False
            
        inner_message = Message()
        inner_message.decode(decrypted)
        
        notify = inner_message.get_payload(PayloadType.NOTIFY)
        if notify and notify.notify_type < 16384:
            return False
            
        id_payload = inner_message.get_payload(PayloadType.IDR)
        if not id_payload:
            return False
            
        self.peer_id = id_payload.id_data
        
        auth_payload = inner_message.get_payload(PayloadType.AUTH)
        if not auth_payload:
            return False
            
        if not self._verify_auth(auth_payload, True):
            return False
            
        self.state = IKEv2State.ESTABLISHED
        self.message_id += 1
        
        return True
        
    def build_ike_sa_init_request(self) -> Message:
        """Build IKE_SA_INIT request"""
        message = Message(
            spi_i=self.spi_i,
            spi_r=b'\x00' * 8,
            exchange_type=ExchangeType.IKE_SA_INIT,
            is_initiator=True,
            is_response=False,
            message_id=self.message_id
        )
        
        sa_payload = SAPayload(self.proposals)
        message.add_payload(sa_payload)
        
        # Find DH transform in the first proposal
        for transform in self.proposals[0].transforms:
            if transform.transform_type == TransformType.DH:
                self.dh_group = transform.transform_id
                break
        
        if not self.dh_group:
            raise ValueError("No DH group found in proposal")
            
        self.dh_public, self.dh_private = self.crypto.generate_dh_keypair(self.dh_group)
        
        ke_payload = KEPayload(self.dh_group, self.dh_public)
        message.add_payload(ke_payload)
        
        self.ni = self.crypto.generate_nonce()
        nonce_payload = NoncePayload(self.ni)
        message.add_payload(nonce_payload)
        
        if self.config.get('nat_detection', True):
            src_nat = self._compute_nat_detection_hash(True)
            dst_nat = self._compute_nat_detection_hash(False)
            
            notify_src = NotifyPayload(
                notify_type=NotifyType.NAT_DETECTION_SOURCE_IP,
                notify_data=src_nat
            )
            message.add_payload(notify_src)
            
            notify_dst = NotifyPayload(
                notify_type=NotifyType.NAT_DETECTION_DESTINATION_IP,
                notify_data=dst_nat
            )
            message.add_payload(notify_dst)
            
        self.state = IKEv2State.IKE_SA_INIT_SENT
        self.last_message = message
        
        return message
        
    def build_ike_auth_request(self, child_sa_config: Optional[Dict] = None) -> Message:
        """Build IKE_AUTH request"""
        message = Message(
            spi_i=self.spi_i,
            spi_r=self.spi_r,
            exchange_type=ExchangeType.IKE_AUTH,
            is_initiator=True,
            is_response=False,
            message_id=self.message_id
        )
        
        inner_payloads = []
        
        id_payload = IDPayload()
        id_payload.set_identity(self.config.get('my_id', 'ikev2@example.com'))
        inner_payloads.append(id_payload)
        
        auth_payload = self._build_auth_payload(True)
        inner_payloads.append(auth_payload)
        
        if child_sa_config:
            sa_payload, tsi_payload, tsr_payload = self._build_child_sa_payloads(child_sa_config)
            inner_payloads.extend([sa_payload, tsi_payload, tsr_payload])
            
        encrypted_data = self._build_encrypted_payloads(inner_payloads, True)
        sk_payload = SKPayload(encrypted_data)
        message.add_payload(sk_payload)
        
        return message
        
    def _build_ike_sa_init_response(self, request: Message, proposal: Proposal) -> Message:
        """Build IKE_SA_INIT response"""
        message = Message(
            spi_i=request.spi_i,
            spi_r=self.spi_r,
            exchange_type=ExchangeType.IKE_SA_INIT,
            is_initiator=False,
            is_response=True,
            message_id=request.message_id
        )
        
        sa_payload = SAPayload([proposal])
        message.add_payload(sa_payload)
        
        self.dh_public, self.dh_private = self.crypto.generate_dh_keypair(self.dh_group)
        
        ke_payload = KEPayload(self.dh_group, self.dh_public)
        message.add_payload(ke_payload)
        
        self.nr = self.crypto.generate_nonce()
        nonce_payload = NoncePayload(self.nr)
        message.add_payload(nonce_payload)
        
        return message
        
    def _build_ike_auth_response(self, request: Message) -> Message:
        """Build IKE_AUTH response"""
        message = Message(
            spi_i=request.spi_i,
            spi_r=self.spi_r,
            exchange_type=ExchangeType.IKE_AUTH,
            is_initiator=False,
            is_response=True,
            message_id=request.message_id
        )
        
        inner_payloads = []
        
        id_payload = IDPayload()
        id_payload.set_identity(self.config.get('my_id', 'responder@example.com'))
        inner_payloads.append(id_payload)
        
        auth_payload = self._build_auth_payload(False)
        inner_payloads.append(auth_payload)
        
        encrypted_data = self._build_encrypted_payloads(inner_payloads, False)
        sk_payload = SKPayload(encrypted_data)
        message.add_payload(sk_payload)
        
        return message
        
    def _derive_keys(self, init_request: bytes, init_response: bytes):
        """Derive IKE SA keys"""
        skeyseed = self.crypto.prf(
            self.ni + self.nr,
            self.dh_shared_secret,
            self.prf_id
        )
        
        keymat = self.crypto.prf_plus(
            skeyseed,
            self.ni + self.nr + self.spi_i + self.spi_r,
            self.prf_id,
            self._calculate_keymat_len()
        )
        
        offset = 0
        key_len = self.crypto.get_key_length(TransformType.PRF, self.prf_id)
        
        self.sk_d = keymat[offset:offset + key_len]
        offset += key_len
        
        integ_len = self.crypto.get_key_length(TransformType.INTEG, self.integ_id)
        self.sk_ai = keymat[offset:offset + integ_len]
        offset += integ_len
        
        self.sk_ar = keymat[offset:offset + integ_len]
        offset += integ_len
        
        encr_len = self.crypto.get_key_length(TransformType.ENCR, self.encr_id)
        self.sk_ei = keymat[offset:offset + encr_len]
        offset += encr_len
        
        self.sk_er = keymat[offset:offset + encr_len]
        offset += encr_len
        
        self.sk_pi = keymat[offset:offset + key_len]
        offset += key_len
        
        self.sk_pr = keymat[offset:offset + key_len]
        
        self.auth_data = self._compute_auth_data(init_request, self.ni, self.sk_pi, True)
        self.peer_auth_data = self._compute_auth_data(init_response, self.nr, self.sk_pr, False)
        
    def _calculate_keymat_len(self) -> int:
        """Calculate total keymat length needed"""
        prf_len = self.crypto.get_key_length(TransformType.PRF, self.prf_id)
        integ_len = self.crypto.get_key_length(TransformType.INTEG, self.integ_id)
        encr_len = self.crypto.get_key_length(TransformType.ENCR, self.encr_id)
        
        return prf_len + 2 * integ_len + 2 * encr_len + 2 * prf_len
        
    def _select_proposal(self, proposals: List[Proposal]) -> Optional[Proposal]:
        """Select a proposal from peer's proposals"""
        for peer_proposal in proposals:
            for my_proposal in self.proposals:
                selected = self._match_proposals(peer_proposal, my_proposal)
                if selected:
                    self._extract_transforms(selected)
                    return selected
        return None
        
    def _match_proposals(self, peer_proposal: Proposal, my_proposal: Proposal) -> Optional[Proposal]:
        """Match two proposals and return selected transforms"""
        selected_transforms = []
        
        transform_types = {
            TransformType.ENCR: None,
            TransformType.PRF: None,
            TransformType.INTEG: None,
            TransformType.DH: None,
        }
        
        for ttype in transform_types:
            peer_transforms = [t for t in peer_proposal.transforms if t.transform_type == ttype]
            my_transforms = [t for t in my_proposal.transforms if t.transform_type == ttype]
            
            for pt in peer_transforms:
                for mt in my_transforms:
                    if pt.transform_id == mt.transform_id:
                        transform_types[ttype] = pt
                        break
                if transform_types[ttype]:
                    break
                    
        if all(transform_types.values()):
            selected_transforms = list(transform_types.values())
            return Proposal(
                num=peer_proposal.proposal_num,
                protocol_id=peer_proposal.protocol_id,
                transforms=selected_transforms
            )
            
        return None
        
    def _extract_transforms(self, proposal: Proposal):
        """Extract selected transform IDs"""
        for transform in proposal.transforms:
            if transform.transform_type == TransformType.ENCR:
                self.encr_id = transform.transform_id
            elif transform.transform_type == TransformType.PRF:
                self.prf_id = transform.transform_id
            elif transform.transform_type == TransformType.INTEG:
                self.integ_id = transform.transform_id
            elif transform.transform_type == TransformType.DH:
                self.dh_group = transform.transform_id
                
    def _verify_selected_proposal(self, proposal: Proposal) -> bool:
        """Verify that responder selected our proposal correctly"""
        for transform in proposal.transforms:
            if transform.transform_type == TransformType.ENCR:
                if transform.transform_id != self.encr_id:
                    return False
            elif transform.transform_type == TransformType.PRF:
                if transform.transform_id != self.prf_id:
                    return False
            elif transform.transform_type == TransformType.INTEG:
                if transform.transform_id != self.integ_id:
                    return False
            elif transform.transform_type == TransformType.DH:
                if transform.transform_id != self.dh_group:
                    return False
        return True
        
    def _build_auth_payload(self, is_initiator: bool) -> AuthPayload:
        """Build AUTH payload"""
        auth_method = self.config.get('auth_method', AuthMethod.SHARED_KEY)
        
        if auth_method == AuthMethod.SHARED_KEY:
            psk = self.config.get('psk', b'default-psk').encode() if isinstance(self.config.get('psk'), str) else self.config.get('psk', b'default-psk')
            auth_key = self.crypto.prf(psk, b"Key Pad for IKEv2", self.prf_id)
            
            if is_initiator:
                auth_data = self.crypto.prf(auth_key, self.auth_data, self.prf_id)
            else:
                auth_data = self.crypto.prf(auth_key, self.peer_auth_data, self.prf_id)
                
            return AuthPayload(auth_method, auth_data)
            
        return AuthPayload(auth_method, b'')
        
    def _verify_auth(self, auth_payload: AuthPayload, is_responder: bool) -> bool:
        """Verify AUTH payload"""
        if auth_payload.auth_method == AuthMethod.SHARED_KEY:
            psk = self.config.get('psk', b'default-psk').encode() if isinstance(self.config.get('psk'), str) else self.config.get('psk', b'default-psk')
            auth_key = self.crypto.prf(psk, b"Key Pad for IKEv2", self.prf_id)
            
            if is_responder:
                expected = self.crypto.prf(auth_key, self.peer_auth_data, self.prf_id)
            else:
                expected = self.crypto.prf(auth_key, self.auth_data, self.prf_id)
                
            return auth_payload.auth_data == expected
            
        return False
        
    def _compute_auth_data(self, msg: bytes, nonce: bytes, sk_p: bytes, is_initiator: bool) -> bytes:
        """Compute AUTH data"""
        id_payload = IDPayload()
        id_payload.set_identity(self.config.get('my_id', 'ikev2@example.com'))
        id_bytes = id_payload.encode()[4:]
        
        return msg + nonce + self.crypto.prf(sk_p, id_bytes, self.prf_id)
        
    def _encrypt_sk_payload(self, plaintext: bytes, is_initiator: bool) -> bytes:
        """Encrypt SK payload content"""
        iv_len = 16
        iv = os.urandom(iv_len)
        
        sk_e = self.sk_ei if is_initiator else self.sk_er
        sk_a = self.sk_ai if is_initiator else self.sk_ar
        
        ciphertext = self.crypto.encrypt(sk_e, iv, plaintext, self.encr_id, sk_a, self.integ_id)
        
        return iv + ciphertext
        
    def _decrypt_sk_payload(self, sk_payload: SKPayload, is_initiator: bool) -> bytes:
        """Decrypt SK payload content"""
        iv_len = 16
        data = sk_payload.encrypted_data
        
        if len(data) < iv_len:
            raise ValueError("SK payload too short")
            
        iv = data[:iv_len]
        ciphertext = data[iv_len:]
        
        sk_e = self.sk_er if is_initiator else self.sk_ei
        sk_a = self.sk_ar if is_initiator else self.sk_ai
        
        plaintext = self.crypto.decrypt(sk_e, iv, ciphertext, self.encr_id, sk_a, self.integ_id)
        
        return plaintext
        
    def _build_encrypted_payloads(self, payloads: List[Payload], is_initiator: bool) -> bytes:
        """Build and encrypt multiple payloads"""
        data = b''
        for i, payload in enumerate(payloads):
            if i < len(payloads) - 1:
                next_type = self._get_next_payload_type(payloads[i + 1])
                payload.next_payload = next_type
            else:
                payload.next_payload = PayloadType.NO_NEXT_PAYLOAD
            data += payload.encode()
            
        return self._encrypt_sk_payload(data, is_initiator)
        
    def _get_next_payload_type(self, payload: Payload) -> PayloadType:
        """Get payload type for next payload pointer"""
        type_map = {
            IDPayload: PayloadType.IDI,
            AuthPayload: PayloadType.AUTH,
            SAPayload: PayloadType.SA,
            TSPayload: PayloadType.TSI,
            NotifyPayload: PayloadType.NOTIFY,
        }
        
        for cls, ptype in type_map.items():
            if isinstance(payload, cls):
                return ptype
        return PayloadType.NO_NEXT_PAYLOAD
        
    def _build_notify_response(self, request: Message, notify_type: int, data: bytes = b'') -> Message:
        """Build error notification response"""
        message = Message(
            spi_i=request.spi_i,
            spi_r=self.spi_r or b'\x00' * 8,
            exchange_type=request.exchange_type,
            is_initiator=False,
            is_response=True,
            message_id=request.message_id
        )
        
        notify = NotifyPayload(
            protocol_id=ProtocolID.IKE,
            notify_type=notify_type,
            notify_data=data
        )
        message.add_payload(notify)
        
        return message
        
    def _build_encrypted_notify(self, request: Message, notify_type: int, data: bytes = b'') -> Message:
        """Build encrypted error notification"""
        message = Message(
            spi_i=request.spi_i,
            spi_r=self.spi_r,
            exchange_type=request.exchange_type,
            is_initiator=False,
            is_response=True,
            message_id=request.message_id
        )
        
        notify = NotifyPayload(
            protocol_id=ProtocolID.IKE,
            notify_type=notify_type,
            notify_data=data
        )
        
        encrypted = self._build_encrypted_payloads([notify], False)
        sk_payload = SKPayload(encrypted)
        message.add_payload(sk_payload)
        
        return message
        
    def _compute_nat_detection_hash(self, is_source: bool) -> bytes:
        """Compute NAT detection hash"""
        if is_source:
            addr = self.config.get('local_addr', '0.0.0.0')
            port = self.config.get('local_port', 500)
        else:
            addr = self.config.get('peer_addr', '0.0.0.0')
            port = self.config.get('peer_port', 500)
            
        if ':' in addr:
            ip_bytes = ipaddress.IPv6Address(addr).packed
        else:
            ip_bytes = ipaddress.IPv4Address(addr).packed
            
        spi_r = self.spi_r if self.spi_r else b'\x00' * 8
        data = self.spi_i + spi_r + ip_bytes + struct.pack('!H', port)
        return hashlib.sha1(data).digest()
        
    def _create_child_sa(self, sa_payload: SAPayload, tsi: TSPayload, tsr: TSPayload) -> Optional[Dict]:
        """Create a child SA"""
        return {
            'spi': os.urandom(4),
            'proposals': sa_payload.proposals,
            'tsi': tsi.traffic_selectors,
            'tsr': tsr.traffic_selectors,
            'state': ChildSAState.CREATED
        }
        
    def _build_child_sa_payloads(self, config: Dict) -> Tuple[SAPayload, TSPayload, TSPayload]:
        """Build child SA related payloads"""
        proposals = []
        
        transforms = []
        transforms.append(Transform(TransformType.ENCR, TransformID.ENCR.AES_CBC, [(14, 128)]))
        transforms.append(Transform(TransformType.INTEG, TransformID.INTEG.AUTH_HMAC_SHA256_128))
        transforms.append(Transform(TransformType.ESN, TransformID.ESN.NO_ESN))
        
        proposal = Proposal(
            num=1,
            protocol_id=ProtocolID.ESP,
            spi=os.urandom(4),
            transforms=transforms
        )
        proposals.append(proposal)
        
        sa_payload = SAPayload(proposals)
        
        tsi = TrafficSelector(
            ts_type=TSType.IPV4_ADDR_RANGE,
            ip_proto=0,
            start_port=0,
            end_port=65535,
            start_addr=ipaddress.IPv4Address('0.0.0.0'),
            end_addr=ipaddress.IPv4Address('255.255.255.255')
        )
        tsi_payload = TSPayload([tsi])
        
        tsr = TrafficSelector(
            ts_type=TSType.IPV4_ADDR_RANGE,
            ip_proto=0,
            start_port=0,
            end_port=65535,
            start_addr=ipaddress.IPv4Address('0.0.0.0'),
            end_addr=ipaddress.IPv4Address('255.255.255.255')
        )
        tsr_payload = TSPayload([tsr])
        
        return sa_payload, tsi_payload, tsr_payload