#!/usr/bin/env python3
"""
pyIKEv2 Command Line Interface
"""

import os
import sys
import argparse
import signal
import time
import logging
from typing import Optional
from .daemon import IKEv2Daemon
from .config import Config

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    print("\nShutting down...")
    sys.exit(0)

def cmd_start(args):
    """Start IKEv2 daemon"""
    config_file = args.config or '/etc/pyikev2/config.yaml'
    
    if not os.path.exists(config_file) and args.config:
        print(f"Error: Configuration file not found: {config_file}")
        return 1
        
    try:
        daemon = IKEv2Daemon(config_file if os.path.exists(config_file) else None)
        
        if args.daemon:
            import daemon as python_daemon
            with python_daemon.DaemonContext():
                daemon.start()
                while True:
                    time.sleep(1)
        else:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            daemon.start()
            print("IKEv2 daemon started. Press Ctrl+C to stop.")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                daemon.stop()
                
    except Exception as e:
        print(f"Error starting daemon: {e}")
        return 1
        
    return 0

def cmd_stop(args):
    """Stop IKEv2 daemon"""
    pid_file = '/var/run/pyikev2.pid'
    
    if not os.path.exists(pid_file):
        print("IKEv2 daemon is not running")
        return 1
        
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
            
        os.kill(pid, signal.SIGTERM)
        print(f"Sent stop signal to daemon (PID: {pid})")
        
        os.remove(pid_file)
        
    except Exception as e:
        print(f"Error stopping daemon: {e}")
        return 1
        
    return 0

def cmd_status(args):
    """Show daemon status"""
    pid_file = '/var/run/pyikev2.pid'
    
    if os.path.exists(pid_file):
        try:
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
                
            os.kill(pid, 0)
            print(f"IKEv2 daemon is running (PID: {pid})")
            return 0
            
        except OSError:
            print("IKEv2 daemon is not running (stale PID file)")
            os.remove(pid_file)
            return 1
    else:
        print("IKEv2 daemon is not running")
        return 1

def cmd_connect(args):
    """Initiate connection to peer"""
    config_file = args.config or '/etc/pyikev2/config.yaml'
    
    try:
        daemon = IKEv2Daemon(config_file if os.path.exists(config_file) else None)
        daemon.start()
        
        sa = daemon.initiate(args.peer, args.port)
        
        if sa:
            print(f"Initiated connection to {args.peer}:{args.port}")
            
            timeout = 10
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                if sa.state.value >= 5:
                    print("Connection established successfully")
                    return 0
                time.sleep(0.5)
                
            print("Connection timeout")
            return 1
        else:
            print("Failed to initiate connection")
            return 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        daemon.stop()

def cmd_list(args):
    """List active connections"""
    print("Active IKE SAs:")
    print("-" * 60)
    print(f"{'Local':<20} {'Remote':<20} {'State':<20}")
    print("-" * 60)
    
    return 0

def cmd_config(args):
    """Configuration management"""
    config = Config()
    
    if args.generate:
        sample_config = config.generate_sample_config()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(sample_config)
            print(f"Sample configuration saved to {args.output}")
        else:
            print(sample_config)
            
    elif args.validate:
        try:
            config.load_config(args.validate)
            print(f"Configuration file {args.validate} is valid")
            return 0
        except Exception as e:
            print(f"Configuration error: {e}")
            return 1
            
    return 0

def cmd_test(args):
    """Test IKEv2 functionality"""
    import unittest
    from .tests import TestSuite
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSuite)
    
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='pyIKEv2 - Python3 IKEv2 Implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='pyIKEv2 1.0.0'
    )
    
    subparsers = parser.add_subparsers(
        title='commands',
        help='Available commands',
        dest='command'
    )
    
    parser_start = subparsers.add_parser(
        'start',
        help='Start IKEv2 daemon'
    )
    parser_start.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default='/etc/pyikev2/config.yaml'
    )
    parser_start.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Run as daemon in background'
    )
    parser_start.set_defaults(func=cmd_start)
    
    parser_stop = subparsers.add_parser(
        'stop',
        help='Stop IKEv2 daemon'
    )
    parser_stop.set_defaults(func=cmd_stop)
    
    parser_status = subparsers.add_parser(
        'status',
        help='Show daemon status'
    )
    parser_status.set_defaults(func=cmd_status)
    
    parser_connect = subparsers.add_parser(
        'connect',
        help='Initiate connection to peer'
    )
    parser_connect.add_argument(
        'peer',
        help='Peer IP address or hostname'
    )
    parser_connect.add_argument(
        '-p', '--port',
        type=int,
        default=500,
        help='Peer port (default: 500)'
    )
    parser_connect.add_argument(
        '-c', '--config',
        help='Configuration file path'
    )
    parser_connect.set_defaults(func=cmd_connect)
    
    parser_list = subparsers.add_parser(
        'list',
        help='List active connections'
    )
    parser_list.set_defaults(func=cmd_list)
    
    parser_config = subparsers.add_parser(
        'config',
        help='Configuration management'
    )
    parser_config.add_argument(
        '-g', '--generate',
        action='store_true',
        help='Generate sample configuration'
    )
    parser_config.add_argument(
        '-o', '--output',
        help='Output file for generated configuration'
    )
    parser_config.add_argument(
        '-v', '--validate',
        help='Validate configuration file'
    )
    parser_config.set_defaults(func=cmd_config)
    
    parser_test = subparsers.add_parser(
        'test',
        help='Run tests'
    )
    parser_test.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser_test.set_defaults(func=cmd_test)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
        
    return args.func(args)

if __name__ == '__main__':
    sys.exit(main())