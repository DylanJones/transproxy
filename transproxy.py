#!/usr/bin/env python3
import socket
import sys
import struct
import threading
import subprocess
import argparse
import configparser

# some code stolen from mitmproxy, see 
# https://github.com/mitmproxy/mitmproxy/blob/master/mitmproxy/platform/linux.py
# according to mitmproxy SO_ORIGINAL_DST = 80
SO_ORIGINAL_DST = 80
SOL_IPV6 = 41

# Firewall lock - prevents server threads from tripping over each other at startup.
fw_lock = threading.Lock()


def connect_sockets(from_socket, to_socket):
    """
    Copy data from from_socket to to_socket until the connection is closed.
    """
    if config['use_native']:
        transproxy_native.copy_fd(from_socket.fileno(), to_socket.fileno())
    else:
        data = 'invalid'
        while len(data) > 0:
            data = from_socket.recv(1024)
            to_socket.send(data)


def http_setup(proxy_conn, client_sock, dst_ip):
    """
    Do the initial header parsing/setup required to proxy plain HTTP connections.
    """
    # Catch the initial request line
    start_line = []
    while len(start_line) < 1 or start_line[-1] != b'\n':
        start_line.append(client_sock.recv(1))
    start_line = b''.join(start_line)

    # Read all of the headers.
    # This doesn't fully comply with HTTP standard (header continuation over multiple lines)
    # but it shouldn't really matter much for our usecase.
    header_lines = []
    while True:
        header_line = [client_sock.recv(1)]
        if header_line[0] == b'\r':
            header_line.append(client_sock.recv(1))
            if header_line[1] == b'\n':
                break
        while header_line[-1] != b'\n':
            header_line.append(client_sock.recv(1))
        header_line = b''.join(header_line)
        header_lines.append(header_line)
    
    # See if there's a Host header in there somewhere, but default to the destination IP
    destination = dst_ip.encode('ascii')
    for line in header_lines:
        header, value = line.split(b':', maxsplit=1)
        if header == b'Host':
            destination = value.strip()
    
    # Fix up the original start line and send it
    verb, uri, version = start_line.strip().split(b' ')
    uri = b'http://' + destination + uri
    proxy_conn.send(b'%b %b %b\r\n' % (verb, uri, version))

    # Finally, send out all of the header lines exactly as we received them
    for line in header_lines:
        proxy_conn.send(line)
    # And the final \r\n:
    proxy_conn.send(b'\r\n')


def connect_setup(proxy_conn, dst_ip, port):
    """
    Perform the initial setup required to open a CONNECT proxy path.  Must be called
    before any copying threads are started.
    """
    proxy_conn.send(b'CONNECT %b:%b\n' % (dst_ip.encode('ascii'), str(port).encode('ascii')))
    resp = proxy_conn.recv(39) # this should get the "HTTP/1.1 200 Connection Established\n\n" response out of the way


def proxy_connection(client_sock, src_ip, method, port):
    """
    This function will take an established client connection and set up the transparent proxy
    connection to the proxy server.  This method blocks until the connection is finished, so it
    should be called in another thread.
    """
    # we're gonna do a real bad and assume ipv4
    # apparently this can crash the entire python runtime!
    dst = client_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, raw_ip = struct.unpack_from('!2xH4s', dst)
    dst_ip = socket.inet_ntop(socket.AF_INET, raw_ip)

    print(f'Connecting {src_ip}:{port} to {dst_ip}:{port} method {method}.')
    
    # connect to the http proxy
    proxy_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    p_addr, p_port = config['proxy_addr']
    proxy_conn.connect((p_addr, int(p_port)))

    # Perform initial CONNECT proxy setup
    if method == 'connect':
        connect_setup(proxy_conn, dst_ip, port)

    # Start forwarding proxy data back to the client
    it = threading.Thread(target=lambda: connect_sockets(proxy_conn, client_sock))
    it.start()

    try:
        if method == 'http':
            # Perform HTTP proxy setup
            http_setup(proxy_conn, client_sock, dst_ip)
        # From here, we just need to transparently proxy - no more 
        connect_sockets(client_sock, proxy_conn)
        it.join()
    finally:
        proxy_conn.close()
        client_sock.close()
        print(f'Closed connection to {dst_ip}.')


def proxy_dispatch(port, method='connect'):
    """
    Set up a proxy server for the given port.  Listens for any incoming connections
    on port and dispatches a proxy_connection thread for each received connection.
    `method` controls how transproxy communicates with the upstream proxy server.
    It can be either 'connect' for a CONNECT-based proxy or 'http' for a plain HTTP proxy.
    """
    # method can be either 'connect' or 'http'
    # server socket - listens for all incoming connections
    print(f"Starting server thread for port {port} with method {method}...")
    with fw_lock:
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'OUTPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DNAT', '--to-destination', '127.0.0.1'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(50)

    try:
        while True:
            client, src = s.accept()
            cthread = threading.Thread(target=proxy_connection, args=(client, src[0], method, port))
            cthread.start()

    finally:
        print("Server thread for port {port} is shutting down.")
        s.close()
        subprocess.run(['iptables', '-t', 'nat', '-F', 'OUTPUT'])


def main():
    # "fix" the firewall
    subprocess.run(['iptables', '-t', 'nat', '-F', 'OUTPUT'])
    for subnet in config['excluded_ips']:
        subprocess.run(['iptables', '-t', 'nat', '-A', 'OUTPUT', '--destination', subnet, '-j', 'ACCEPT'])

    http_thread = threading.Thread(target=proxy_dispatch, args=(80, 'http'), daemon=True)
    https_thread = threading.Thread(target=proxy_dispatch, args=(443, 'connect'), daemon=True)
    http_thread.start()
    https_thread.start()

    try:
        http_thread.join()
        https_thread.join()
    finally:
        subprocess.run(['iptables', '-t', 'nat', '-F', 'OUTPUT'])


# Read and parse config
with open('transproxy.cfg') as f:
    cp = configparser.ConfigParser()
    cp.read_file(f)
cp = cp['transproxy']
config = {
    'use_native': cp['use_native'].lower() == 'true',
    'excluded_ips': [s.strip() for s in cp['excluded_ips'].strip().split(',')],
    'proxy_addr': cp['proxy_addr'].split(':')
}

if config['use_native']:
    import transproxy_native

if __name__ == '__main__':
    main()
