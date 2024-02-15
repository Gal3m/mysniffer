from scapy.all import sniff, Raw
from scapy.layers.inet import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello

from datetime import datetime
import argparse
import re

from scapy.main import load_layer



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

def http_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        return "GET" in payload or "POST" in payload
    return False

def http_nonstandard(packet):
    if http_packet(packet):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            # Extract HTTP details
            http_method = re.search(r"^(GET|POST)", payload, re.MULTILINE)
            host = re.search(r"Host: ([^:\r\n]+)", payload, re.MULTILINE)
            path = re.search(r"(GET|POST) ([^\s]+)", payload, re.MULTILINE)

            # Format timestamp
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')

            # Construct and print the formatted string
            formatted_output = (
                f"{timestamp} HTTP {source_ip}:{source_port} -> "
                f"{destination_ip}:{destination_port} "
                f"{host.group(1) if host else 'N/A'} "
                f"{http_method.group(0) if http_method else 'N/A'} "
                f"{path.group(2) if path else 'N/A'}"
            )
            print(formatted_output)
        except Exception as e:
            print(f"Error processing packet: {e}")

def parse_http(packet):
    if packet.haslayer(HTTPRequest):
        return f"{packet[HTTPRequest].Host.decode()} {packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Path.decode()}"

    return None

def parse_tls(packet):
    if packet.haslayer(TLSClientHello):
        tls_client_hello = packet[TLSClientHello]

        # Extracting TLS version
        tls_version = tls_client_hello.version

        # Attempting to extract SNI (this method is not reliable for all TLS configurations)
        raw_payload = bytes(packet[TLSClientHello])
        sni = None
        sni_match = re.search(b'\x00\x00(.+?)\x00', raw_payload)
        if sni_match:
            sni = sni_match.group(1).decode('utf-8', errors='ignore')

        return f"TLS v{tls_version}", sni

    return None, None

def packet_callback(packet):
    load_layer("http")
    load_layer("tls")
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    if packet.haslayer(TLSClientHello):
        tls_info, servername = parse_tls(packet)
        print(f"{timestamp} {tls_info} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {servername}")
    elif packet.haslayer(HTTPRequest):
        http_info = parse_http(packet)
        print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {http_info}")
    else:
         http_nonstandard(packet)

    # if http_info:
    #     print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {http_info}")
    # elif tls_info and servername:
    #     print(f"{timestamp} {tls_info} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {servername}")


def main():
    parser = argparse.ArgumentParser(description='HTTP/TLS connection monitoring tool')

    parser.add_argument('-i', '--interface', help='Network device interface', default=get_default_iface_name())
    parser.add_argument('-r', '--tracefile', help='Read packets from trace file', default=None)
    parser.add_argument('-f', '--filter', nargs='?', help = 'BPF formatted packet filter.', default='')
    args = parser.parse_args()

    if args.tracefile:
        sniff(offline=args.tracefile, prn=packet_callback, filter=args.filter, store=0)
    else:
        sniff(iface=args.interface, prn=packet_callback, filter=args.filter, store=0)

if __name__ == "__main__":
    main()
