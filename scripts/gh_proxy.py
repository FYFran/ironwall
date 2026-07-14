#!/usr/bin/env python3
"""HTTP CONNECT proxy redirecting github.com to working CDN IP (20.205.243.167).

Usage:
    Start:  python gh_proxy.py 9443
    Test:   curl -x http://127.0.0.1:9443 -I https://github.com
    Git:    git -c http.proxy=http://127.0.0.1:9443 push origin master

The GFW blocks github.com IP (20.205.243.166:443) but NOT 20.205.243.167:443.
This proxy connects to the working IP while preserving the TLS SNI for github.com."""

import socket
import ssl
import threading
import select
import sys
import re

WORKING_IP = "20.205.243.167"
WORKING_PORT = 443
GITHUB_HOST_RE = re.compile(r'^(github\.com|api\.github\.com)$')
DEBUG = '--debug' in sys.argv


def log(msg):
    if DEBUG:
        print(f'[gh_proxy] {msg}', flush=True)


def parse_connect(header_bytes):
    line = header_bytes.split(b'\r\n')[0].decode('ascii', errors='replace')
    parts = line.split()
    if len(parts) < 2:
        return None, None
    hostport = parts[1]
    if ':' in hostport:
        host, port = hostport.rsplit(':', 1)
        return host, int(port)
    return hostport, 443


def handle_client(client_sock, addr):
    remote = None
    log(f'new connection from {addr}')
    try:
        client_sock.settimeout(10)
        header_data = b''
        while b'\r\n\r\n' not in header_data:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            header_data += chunk
            if len(header_data) > 16384:
                return

        host, port = parse_connect(header_data)
        log(f'CONNECT {host}:{port}')

        if not host:
            client_sock.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            return

        is_github = bool(GITHUB_HOST_RE.match(host))
        connect_host = WORKING_IP if is_github else host
        connect_port = WORKING_PORT if is_github else port
        log(f'connecting to {connect_host}:{connect_port} (github={is_github})')

        remote = socket.create_connection((connect_host, connect_port), timeout=15)
        log(f'TCP connected to {connect_host}:{connect_port}')

        if is_github:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # CDN cert covers github.com, we trust it
            remote = ctx.wrap_socket(remote, server_hostname=host)
            log(f'TLS established with SNI={host}')

        client_sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        log('tunnel established, start piping')

        client_sock.settimeout(None)
        remote.settimeout(None)

        sockets = [client_sock, remote]
        while True:
            r, _, _ = select.select(sockets, [], [], 120)
            if not r:
                log('pipe timeout')
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    log(f'{"client" if s is client_sock else "remote"} closed')
                    return
                if s is client_sock:
                    remote.sendall(data)
                else:
                    client_sock.sendall(data)

    except Exception as e:
        log(f'ERROR: {type(e).__name__}: {e}')
        try:
            client_sock.sendall(f'HTTP/1.1 502 Bad Gateway\r\n\r\n'.encode())
        except Exception:
            pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        if remote:
            try:
                remote.close()
            except Exception:
                pass
        log('connection closed')


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 9443

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(32)
    print(f'[gh_proxy] listening on 127.0.0.1:{port}', flush=True)

    try:
        while True:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print('[gh_proxy] stopped')


if __name__ == '__main__':
    main()
