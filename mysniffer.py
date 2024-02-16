import scapy.layers.tls.record_tls13
from mitmproxy.io.proto.http_pb2 import TLSExtension
from scapy.all import sniff, Raw
from scapy.layers.inet import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.extensions import ServerName
from scapy.layers.tls.handshake import TLSClientHello

from datetime import datetime
import argparse
import re
import ssl
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
            packet_time_float = float(packet.time)
            timestamp = datetime.fromtimestamp(packet_time_float).strftime('%Y-%m-%d %H:%M:%S.%f')

            # Construct and print the formatted string
            formatted_output = (
                f"{timestamp} HTTP {source_ip}:{source_port} -> "
                f"{destination_ip}:{destination_port} "
                f"{host.group(1) if host else 'None'} "
                f"{http_method.group(0) if http_method else 'None'} "
                f"{path.group(2) if path else 'None'}"
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


def remove_unprintable_prefix(sni_server_name):
    # Convert the string to bytes
    sni_bytes = sni_server_name.encode('utf-8')

    # Find the index of the first printable character
    first_printable = next((i for i, c in enumerate(sni_bytes) if c >= 0x20 and c <= 0x7E), None)

    # If there are no printable characters, return an empty string
    if first_printable is None:
        return ''

    # Decode the remaining bytes as a string
    return sni_bytes[first_printable:].decode('utf-8')

def get_server_name(raw_payload):
    try:
        # Parse the packet as a TLS ClientHello
        tls_header = raw_payload[0:5]
        tls_version = tls_header[1:3]
        tls_length = int.from_bytes(tls_header[3:5], byteorder='big')
        tls_data = raw_payload[5:5 + tls_length]

        # Check if the handshake is a ClientHello
        if tls_data[0] != 0x01:
            return False, None

        # Extract the SNI extension
        extensions_offset = 5 + 32 + 1 + 1 + 2 + 32
        extensions_length = int.from_bytes(tls_data[extensions_offset:extensions_offset + 2], byteorder='big')
        extensions_data = tls_data[extensions_offset + 2:extensions_offset + 2 + extensions_length]

        # Search for the SNI extension type (0x00, 0x00)
        sni_start = extensions_data.find(b'\x00\x00')
        if sni_start == -1:
            return False, None

        # Extract the SNI extension length and data
        sni_length = int.from_bytes(extensions_data[sni_start + 2:sni_start + 4], byteorder='big')
        sni_data = extensions_data[sni_start + 4:sni_start + 4 + sni_length]

        # Split the SNI data into type (0x00) and length fields
        type_length = sni_data.find(b'\x00')
        if type_length == -1:
            return False, None

        # Extract the SNI server name
        sni_server_name = sni_data[type_length + 3:]
        return remove_unprintable_prefix(sni_server_name.decode('utf-8'))
    except Exception as e:

        return None

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

    packet_time_float = float(packet.time)
    timestamp = datetime.fromtimestamp(packet_time_float).strftime('%Y-%m-%d %H:%M:%S.%f')
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
