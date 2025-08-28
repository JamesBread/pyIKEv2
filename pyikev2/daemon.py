"""
IKEv2 Daemon - Network handling and SA management
"""

import os
import sys
import socket
import select
import threading
import time
import logging
import ipaddress
from typing import Dict, List, Tuple, Optional, Any
from .const import *
from .message import Message
from .state import IKEv2SA, IKEv2State
from .config import Config

class IKEv2Daemon:
    """IKEv2 Daemon for handling IKE exchanges"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = Config(config_file) if config_file else Config()
        self.sockets = {}
        self.sas = {}
        self.running = False
        self.threads = []
        
        self.logger = logging.getLogger('pyikev2.daemon')
        self._setup_logging()
        
        self.local_addresses = self.config.get('local_addresses', ['0.0.0.0'])
        self.local_port = self.config.get('local_port', IKE_PORT)
        self.nat_port = self.config.get('nat_port', IKE_NAT_PORT)
        
        self.retransmit_timeout = self.config.get('retransmit_timeout', 2.0)
        self.max_retransmits = self.config.get('max_retransmits', 5)
        
        self.cookie_secret = os.urandom(32)
        self.cookie_counter = 0
        self.cookie_threshold = self.config.get('cookie_threshold', COOKIE_THRESHOLD)
        
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        log_file = self.config.get('log_file', None)
        
        handlers = [logging.StreamHandler()]
        if log_file:
            handlers.append(logging.FileHandler(log_file))
            
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )
        
    def start(self):
        """Start the IKEv2 daemon"""
        self.logger.info("Starting IKEv2 daemon")
        
        self._create_sockets()
        
        self.running = True
        
        receiver_thread = threading.Thread(target=self._receive_loop)
        receiver_thread.daemon = True
        receiver_thread.start()
        self.threads.append(receiver_thread)
        
        retransmit_thread = threading.Thread(target=self._retransmit_loop)
        retransmit_thread.daemon = True
        retransmit_thread.start()
        self.threads.append(retransmit_thread)
        
        self.logger.info("IKEv2 daemon started successfully")
        
    def stop(self):
        """Stop the IKEv2 daemon"""
        self.logger.info("Stopping IKEv2 daemon")
        self.running = False
        
        for thread in self.threads:
            thread.join(timeout=5)
            
        self._close_sockets()
        
        self.logger.info("IKEv2 daemon stopped")
        
    def _create_sockets(self):
        """Create UDP sockets for IKE communication"""
        for addr in self.local_addresses:
            try:
                if ':' in addr:
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((addr, self.local_port))
                sock.setblocking(False)
                
                self.sockets[(addr, self.local_port)] = sock
                self.logger.info(f"Listening on {addr}:{self.local_port}")
                
                if self.nat_port != self.local_port:
                    nat_sock = socket.socket(
                        socket.AF_INET6 if ':' in addr else socket.AF_INET,
                        socket.SOCK_DGRAM
                    )
                    nat_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    nat_sock.bind((addr, self.nat_port))
                    nat_sock.setblocking(False)
                    
                    self.sockets[(addr, self.nat_port)] = sock
                    self.logger.info(f"Listening on {addr}:{self.nat_port} (NAT-T)")
                    
            except Exception as e:
                self.logger.error(f"Failed to create socket on {addr}: {e}")
                
    def _close_sockets(self):
        """Close all sockets"""
        for sock in self.sockets.values():
            sock.close()
        self.sockets.clear()
        
    def _receive_loop(self):
        """Main receive loop for incoming packets"""
        while self.running:
            try:
                readable, _, _ = select.select(list(self.sockets.values()), [], [], 1.0)
                
                for sock in readable:
                    try:
                        data, addr = sock.recvfrom(65535)
                        
                        if len(data) < IKE_HEADER_SIZE:
                            continue
                            
                        if addr[1] == self.nat_port and data[:4] == b'\x00\x00\x00\x00':
                            data = data[4:]
                            
                        self._handle_packet(data, addr, sock)
                        
                    except Exception as e:
                        self.logger.error(f"Error receiving packet: {e}")
                        
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in receive loop: {e}")
                    
    def _handle_packet(self, data: bytes, addr: Tuple[str, int], sock: socket.socket):
        """Handle received IKE packet"""
        try:
            message = Message()
            message.decode(data)
            message.peer_addr = addr[0]
            message.peer_port = addr[1]
            
            self.logger.debug(f"Received {message.exchange_type.name} from {addr[0]}:{addr[1]}")
            
            sa_key = self._get_sa_key(message)
            
            if message.exchange_type == ExchangeType.IKE_SA_INIT:
                if message.is_request():
                    self._handle_ike_sa_init_request(message, addr, sock)
                else:
                    self._handle_ike_sa_init_response(message, addr)
                    
            elif message.exchange_type == ExchangeType.IKE_AUTH:
                if sa_key not in self.sas:
                    self.logger.warning(f"No SA found for {sa_key}")
                    return
                    
                sa = self.sas[sa_key]
                
                if message.is_request():
                    response = sa.process_ike_auth_request(message)
                    if response:
                        self._send_message(response, addr, sock)
                else:
                    sa.process_ike_auth_response(message)
                    
            elif message.exchange_type == ExchangeType.CREATE_CHILD_SA:
                if sa_key not in self.sas:
                    return
                    
                sa = self.sas[sa_key]
                self._handle_create_child_sa(message, sa, addr, sock)
                
            elif message.exchange_type == ExchangeType.INFORMATIONAL:
                if sa_key not in self.sas:
                    return
                    
                sa = self.sas[sa_key]
                self._handle_informational(message, sa, addr, sock)
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
            
    def _handle_ike_sa_init_request(self, message: Message, addr: Tuple[str, int], sock: socket.socket):
        """Handle IKE_SA_INIT request"""
        if self._should_send_cookie(addr):
            response = self._build_cookie_response(message)
            self._send_message(response, addr, sock)
            return
            
        config = self._get_peer_config(addr[0])
        sa = IKEv2SA(config, is_initiator=False)
        
        response = sa.process_ike_sa_init_request(message)
        if response:
            self._send_message(response, addr, sock)
            
            sa_key = (sa.spi_i, sa.spi_r)
            self.sas[sa_key] = sa
            sa.peer_addr = addr[0]
            sa.peer_port = addr[1]
            
            self.logger.info(f"Created SA {sa_key} with {addr[0]}:{addr[1]}")
            
    def _handle_ike_sa_init_response(self, message: Message, addr: Tuple[str, int]):
        """Handle IKE_SA_INIT response"""
        sa_key = (message.spi_i, b'\x00' * 8)
        
        for key, sa in self.sas.items():
            if key[0] == message.spi_i and sa.state == IKEv2State.IKE_SA_INIT_SENT:
                if sa.process_ike_sa_init_response(message):
                    del self.sas[key]
                    
                    new_key = (sa.spi_i, sa.spi_r)
                    self.sas[new_key] = sa
                    
                    auth_request = sa.build_ike_auth_request({'create_child': True})
                    self._send_message(auth_request, addr, None)
                    
                    self.logger.info(f"IKE_SA_INIT completed for {new_key}")
                break
                
    def _handle_create_child_sa(self, message: Message, sa: IKEv2SA, addr: Tuple[str, int], sock: socket.socket):
        """Handle CREATE_CHILD_SA exchange"""
        pass
        
    def _handle_informational(self, message: Message, sa: IKEv2SA, addr: Tuple[str, int], sock: socket.socket):
        """Handle INFORMATIONAL exchange"""
        pass
        
    def _should_send_cookie(self, addr: Tuple[str, int]) -> bool:
        """Check if we should send a cookie challenge"""
        return False
        
    def _build_cookie_response(self, request: Message) -> Message:
        """Build cookie challenge response"""
        message = Message(
            spi_i=request.spi_i,
            spi_r=b'\x00' * 8,
            exchange_type=ExchangeType.IKE_SA_INIT,
            is_initiator=False,
            is_response=True,
            message_id=request.message_id
        )
        
        import hashlib
        import struct
        
        cookie_data = struct.pack('!Q', int(time.time()))
        cookie_data += request.spi_i
        cookie_data += self.cookie_secret
        cookie = hashlib.sha256(cookie_data).digest()[:COOKIE_SIZE // 2]
        
        notify = NotifyPayload(
            protocol_id=ProtocolID.IKE,
            notify_type=NotifyType.COOKIE,
            notify_data=cookie
        )
        message.add_payload(notify)
        
        return message
        
    def _get_sa_key(self, message: Message) -> Tuple[bytes, bytes]:
        """Get SA key from message"""
        return (message.spi_i, message.spi_r)
        
    def _get_peer_config(self, peer_addr: str) -> Dict[str, Any]:
        """Get configuration for a peer"""
        peers = self.config.get('peers', {})
        
        for peer_id, peer_config in peers.items():
            if peer_config.get('address') == peer_addr:
                return peer_config
                
        return self.config.get('default_peer', {})
        
    def _send_message(self, message: Message, addr: Tuple[str, int], sock: Optional[socket.socket]):
        """Send IKE message"""
        try:
            data = message.encode()
            
            if addr[1] == self.nat_port:
                data = b'\x00\x00\x00\x00' + data
                
            if sock:
                sock.sendto(data, addr)
            else:
                for s in self.sockets.values():
                    try:
                        s.sendto(data, addr)
                        break
                    except:
                        continue
                        
            self.logger.debug(f"Sent {message.exchange_type.name} to {addr[0]}:{addr[1]}")
            
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            
    def _retransmit_loop(self):
        """Handle retransmissions"""
        while self.running:
            try:
                time.sleep(1)
                
                current_time = time.time()
                
                for sa in list(self.sas.values()):
                    if sa.last_message and sa.state in [IKEv2State.IKE_SA_INIT_SENT, IKEv2State.IKE_AUTH_SENT]:
                        if current_time - sa.last_transmit_time > self.retransmit_timeout:
                            if sa.retransmit_count < self.max_retransmits:
                                self._send_message(
                                    sa.last_message,
                                    (sa.peer_addr, sa.peer_port),
                                    None
                                )
                                sa.retransmit_count += 1
                                sa.last_transmit_time = current_time
                                
                                self.logger.debug(f"Retransmitting (attempt {sa.retransmit_count})")
                            else:
                                self.logger.warning("Max retransmits reached, removing SA")
                                sa_key = (sa.spi_i, sa.spi_r or b'\x00' * 8)
                                if sa_key in self.sas:
                                    del self.sas[sa_key]
                                    
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in retransmit loop: {e}")
                    
    def initiate(self, peer_addr: str, peer_port: int = IKE_PORT) -> Optional[IKEv2SA]:
        """Initiate IKE SA with a peer"""
        config = self._get_peer_config(peer_addr)
        config['peer_addr'] = peer_addr
        config['peer_port'] = peer_port
        
        sa = IKEv2SA(config, is_initiator=True)
        
        init_request = sa.build_ike_sa_init_request()
        
        sa_key = (sa.spi_i, b'\x00' * 8)
        self.sas[sa_key] = sa
        sa.peer_addr = peer_addr
        sa.peer_port = peer_port
        sa.last_transmit_time = time.time()
        
        self._send_message(init_request, (peer_addr, peer_port), None)
        
        self.logger.info(f"Initiating IKE SA with {peer_addr}:{peer_port}")
        
        return sa
        
    def get_established_sas(self) -> List[IKEv2SA]:
        """Get list of established SAs"""
        return [sa for sa in self.sas.values() if sa.state == IKEv2State.ESTABLISHED]
        
    def delete_sa(self, spi_i: bytes, spi_r: bytes):
        """Delete an IKE SA"""
        sa_key = (spi_i, spi_r)
        if sa_key in self.sas:
            sa = self.sas[sa_key]
            sa.state = IKEv2State.DELETED
            del self.sas[sa_key]
            self.logger.info(f"Deleted SA {sa_key}")