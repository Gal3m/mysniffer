# mysniffer
a Scapy-based Network Monitoring Tools

# Project Overview

This project aims to develop two network monitoring tools using the Scapy framework. These tools are designed to capture, analyze, and generate network traffic, specifically focusing on HTTP/TLS connections. The primary objective is to create efficient and reliable tools for network monitoring that can be used in various scenarios, including security analysis and network troubleshooting.
Target Platform

Primary Platform: Linux (Specifically 64-bit Kali Linux 2023.4 virtual machine)
Optional Platforms: Other platforms where Python and Scapy are supported (Windows, MacOS, etc.)

Tool 1: HTTP/TLS Connection Monitoring

# Description

This tool is designed to monitor HTTP and TLS connections over a network. It should be able to capture live network data or read from a pre-captured trace file.

# Usage

```
mysniffer.py [-i interface] [-r tracefile] [expression]
```

# Arguments

-i interface: Specifies the network interface for live capture (e.g., eth0). If not specified, the tool should select a default interface.

-r tracefile: Allows reading from a tcpdump format trace file for offline analysis.

\<expression\>: An optional BPF filter to narrow down the traffic for monitoring.

# Features

HTTP Traffic Monitoring:
  Parse GET and POST requests.
  Print the method (GET/POST), destination host name, and Request URI.

TLS Traffic Monitoring:
  Parse the Client Hello message.
  Print the TLS version and destination host name from the Server Name Indication field.

General Output for Both HTTP and TLS:
  Display timestamp, source and destination IP addresses, and ports.

# Output Example

```
2020-02-04 13:14:33.224487 HTTP 192.168.190.128:57234 -> 23.185.0.4:80 www.cs.stonybrook.edu GET /research/area/Security-and-Privacy
2020-02-04 13:14:24.494045 TLS v1.3 192.168.190.128:59330 -> 104.244.42.193:443 google.com
```

# Special Considerations

The tool should identify HTTP and TLS traffic regardless of the destination port, facilitating the detection of services on non-standard ports.
TCP stream reassembly is not required; packet-level analysis is sufficient.

# Technical Requirements

Programming Language: Python
Key Library/Framework: Scapy
Compatibility: Ensure functionality in the specified Kali Linux environment.

# Evaluation Criteria

Functionality: Accuracy and reliability in monitoring network traffic.
Code Quality: Cleanliness, organization, and documentation of the code.
Compatibility: Smooth operation on the specified Kali Linux version.
