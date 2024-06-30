# Firewall Rule Generator

## Overview

The Firewall Rule Generator is a command-line tool for creating firewall rules in different formats (JSON, YAML, TXT). It supports generating rules for `iptables`, `ufw`, and `firewalld`.

## Features

- Generate firewall rules for different systems: `iptables`, `ufw`, `firewalld`
- Support for various protocols: TCP, UDP, ICMP, and ANY
- Export rules in multiple formats: JSON, YAML, and TXT
- Validate inputs to ensure correct rule creation
- Activity logging for tracking rule generation

## Requirements

- Python 3.6+
- `PyYAML` library

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/Jsec8/firewall_rule_generator.git
   cd firewall_rule_generator

## Options

    Action: The action to perform on matching packets (ACCEPT, DROP, REJECT).
    Protocol: The protocol to match (tcp, udp, icmp, any).
    Port Number: The port number to match (or any for all ports).
    IP Address: The IP address to match (or any for all IPs).
    Firewall System: The firewall system to generate the rule for (iptables, ufw, firewalld).
    Save to File: Option to save the rule to a file.
    File Format: The format to save the rule (json, yaml, txt).

## Activity Logging

The Firewall Rule Generator creates logs of all activities, including rule generation and errors. Logs are saved in the firewall_rule_generator.log file in the same directory as the script.
