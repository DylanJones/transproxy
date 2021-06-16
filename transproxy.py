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

fw_lock = threading.Lock()

def proxy(lport, oport, method='connect'):
    # method can be either 'connect' or 'http'
    # server socket - listens for all incoming connections
    print(f"Starting server thread for port {lport}->{oport} with method {method}...")
    with fw_lock:
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'OUTPUT', '-p', 'tcp', '--dport', str(oport), '-j', 'DNAT', '--to-destination', '127.0.0.1'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', lport))
    s.listen(50)
    try:
        while True:
            # whoo boy i do love me some nested closures
            def conn_thread(client_sock, src_ip):
                # we're gonna do a real bad and assume ipv4
                # apparently this can crash the entire python runtime!

                dst = client_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                port, raw_ip = struct.unpack_from('!2xH4s', dst)
                dst_ip = socket.inet_ntop(socket.AF_INET, raw_ip)

                print(f'Connecting {src_ip}:{lport} to {dst_ip}:{oport} method {method}.')
                
                # connect to the http proxy
                proxy_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                p_addr, p_port = config['proxy_addr']
                proxy_conn.connect((p_addr, int(p_port)))
                if method == 'connect':
                    proxy_conn.send(b'CONNECT ' + dst_ip.encode('ASCII') + b':' + str(oport).encode('ascii') + b'\n')
                    resp = proxy_conn.recv(39) # this should get the "HTTP/1.1 200 Connection Established\n\n" response out of the way

                def in_thread():
                    if config['use_native']:
                        transproxy_native.copy_fd(proxy_conn.fileno(), client_sock.fileno())
                    else:
                        data = 'invalid'
                        while len(data) > 0:
                            data = proxy_conn.recv(1024)
                            client_sock.send(data)


                it = threading.Thread(target=in_thread)
                it.start()

                try:
                    data = 'invalid'
                    if method == 'http':
                        # wait until after the verb to inject the 'http://{dst_ip}' part
                        while data != b' ':
                            data = client_sock.recv(1)
                            proxy_conn.send(data)

                        # inject the uri, then continue
                        proxy_conn.send(b'http://' + dst_ip.encode('ascii'))

                    if config['use_native']:
                        transproxy_native.copy_fd(client_sock.fileno(), proxy_conn.fileno())
                    else:
                        while len(data) > 0:
                            data = client_sock.recv(1024)
                            proxy_conn.send(data)
                    it.join()
                finally:
                    proxy_conn.close()
                    client_sock.close()
                    print(f'Closed connection to {dst_ip}.')

            client, src = s.accept()
            cthread = threading.Thread(target=conn_thread, args=(client, src[0]))
            cthread.start()

    finally:
        print("DYING")
        s.close()
        subprocess.run(['iptables', '-t', 'nat', '-F', 'OUTPUT'])

def main():
    # fix up the firewall
    subprocess.run(['iptables', '-t', 'nat', '-F', 'OUTPUT'])
    for subnet in config['excluded_ips']:
        subprocess.run(['iptables', '-t', 'nat', '-A', 'OUTPUT', '--destination', subnet, '-j', 'ACCEPT'])

    http_thread = threading.Thread(target=proxy, args=(80, 80, 'http'), daemon=True)
    https_thread = threading.Thread(target=proxy, args=(443, 443, 'connect'), daemon=True)
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
