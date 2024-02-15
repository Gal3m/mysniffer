import scapy.layers.tls.record_tls13
from scapy.all import sniff, Raw
from scapy.layers.inet import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.extensions import ServerName
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
        tls_version = ''
        decoded_serverName = ''
        # Extracting TLS version
        tls_versionCodes = tls_client_hello.version
        versionCodes = [769, 770, 771, 772]
        versions = ['1.0', '1.1', '1.2', '1.3']
        if tls_versionCodes in versionCodes:
            tls_version = versions[versionCodes.index(tls_versionCodes)]

        if packet.haslayer(ServerName):
            serverName = packet[ServerName].servername
            decoded_serverName = serverName.decode('utf-8')
        return f"TLS v{tls_version}", decoded_serverName
    return None, None

def get_server_name(raw_payload):
    pattern = re.compile(b'\x00\x00..(\x00)..(.*?)$', re.DOTALL)
    match = pattern.search(raw_payload)
    if match:
        server_name_length = match.group(1)
        if server_name_length:
            sni_length = int.from_bytes(server_name_length, byteorder='big')
            server_name = match.group(2)[:sni_length]
            return server_name.decode('utf-8', errors='ignore')
    return "SNI not found"

def get_tls_version(raw_payload):
    # Extract TLS version from the handshake layer
    if len(raw_payload) > 9:
        version_bytes = raw_payload[9:11]
        version_map = {
            b'\x03\x01': '1.0',
            b'\x03\x02': '1.1',
            b'\x03\x03': '1.2',
            b'\x03\x04': '1.3',
        }
        return f"TLS v{version_map.get(version_bytes, 'Unknown')}"
    return None


def is_tls_client_hello(packet):
    if packet.haslayer(Raw):
        raw_payload = packet[Raw].load
        if len(raw_payload) > 5 and raw_payload[0] == 0x16:
            handshake_type = raw_payload[5]
            if handshake_type == 0x01:
                return True
    return False
def parse_tls_nonstandard(packet):
    raw_payload = packet[Raw].load
    serverName = get_server_name(raw_payload)
    tls_version = get_tls_version(raw_payload)
    return tls_version, serverName


def packet_callback(packet):
    load_layer("http")
    load_layer("tls")
    if not packet.haslayer(IP) or not packet.haslayer(TCP) :
        return

    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    if packet.haslayer(TLSClientHello):
        tls_info, servername = parse_tls(packet)
        print(f"{timestamp} {tls_info} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {servername}")
    elif packet.haslayer(TCP) and is_tls_client_hello(packet):
        tls_info, servername = parse_tls_nonstandard(packet)
        print(f"{timestamp} {tls_info} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {servername}")
    elif packet.haslayer(HTTPRequest):
        http_info = parse_http(packet)
        print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {http_info}")
    else:
         http_nonstandard(packet)

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
