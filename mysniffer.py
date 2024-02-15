from scapy.all import sniff, Raw
from scapy.layers.inet import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello
from datetime import datetime
import argparse

def get_default_iface_name():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue
def parse_http(packet):
    if packet.haslayer(HTTPRequest):
        return f"{packet[HTTPRequest].Host.decode()} {packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Path.decode()}"

    return None

def parse_tls(packet):
    if packet.haslayer(TLSClientHello):
        sni = ''
        for ext in packet[TLSClientHello].ext:
            if ext.name == 'server_name':
                sni = ext.servernames[0].servername.decode()
        return f"TLS v{packet[TLSClientHello].version}", sni
    return None, None

def packet_callback(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    if packet.haslayer(HTTPRequest):
        http_info = parse_http(packet)
        print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {http_info}")
    elif packet.haslayer(TLSClientHello):
        tls_info, servername = parse_tls(packet)
        print(f"{timestamp} {tls_info} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {servername}")

    # if http_info:
    #     print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {http_info}")
    # elif tls_info and servername:
    #     print(f"{timestamp} {tls_info} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {servername}")


def main():
    parser = argparse.ArgumentParser(description='HTTP/TLS connection monitoring tool')

    parser.add_argument('-i', '--interface', help='Network device interface', default=get_default_iface_name())
    parser.add_argument('-r', '--tracefile', help='Read packets from trace file', default=None)
    parser.add_argument('expression', nargs='?', help='BPF filter expression', default='')
    args = parser.parse_args()

    if args.tracefile:
        sniff(offline=args.tracefile, prn=packet_callback, filter=args.expression, store=0)
    else:
        sniff(iface=args.interface, prn=packet_callback, filter=args.expression, store=0)

if __name__ == "__main__":
    main()
