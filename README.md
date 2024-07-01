# pcap_glance
A tool to allow an analysts to have a first glance on a pcap file before deciding to go further with their investigation.

Overview

The Tool (pcap_glance.py) is designed to provide comprehensive analysis of network traffic captured in PCAP (Packet Capture) files. This tool aims to assist analysts in identifying key insights from network traffic, including protocol usage, IP addresses, port activities, and potential security threats such as port scanning.
Features

Basic Network Analysis: Provides statistics on total packets, unique IP addresses (source and destination), top protocols by packet count, and packet length analysis.

Timestamps: Displays capture start time, end time, and duration to understand the timeframe of network activity.

Port Scanning Detection: Identifies potential port scanning activities by analyzing source IPs and the number of unique ports they attempt to connect to.

HTTP Inspection: Parses and displays example HTTP requests and responses from the PCAP file for deeper protocol analysis.

Usage

Prerequisites:
Python 3.x
scapy library (pip install scapy)

Running the Script:
Place your PCAP file in the same directory as pcap_glance.py.
Open a terminal or command prompt.
Run the script with the command:

        python pcap_glance.py

Follow the prompts to enter the filename of your PCAP file when prompted.

Customization

Adjust the script parameters, such as thresholds for port scanning detection or additional HTTP inspection rules, to fit your specific network environment and analysis requirements.
