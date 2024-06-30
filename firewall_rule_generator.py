import os
import re
import json
import yaml
import logging
import argparse

# Configurar logging
logging.basicConfig(level=logging.INFO, filename='firewall_rule_generator.log', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_port(port, protocol):
    if protocol in ["icmp", "any"]:
        return port == "any"
    return port.isdigit() and 0 < int(port) <= 65535 or port == "any"

def is_valid_ip(ip):
    ipv4_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    ipv6_pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
    return ipv4_pattern.match(ip) or ipv6_pattern.match(ip) or ip == "any"

def generate_iptables_rule(action, protocol, port, ip):
    if protocol == "any":
        return f"iptables -A INPUT -s {ip} -j {action.upper()}"
    if protocol == "icmp":
        return f"iptables -A INPUT -p icmp -s {ip} -j {action.upper()}"
    return f"iptables -A INPUT -p {protocol} --dport {port} -s {ip} -j {action.upper()}"

def generate_ufw_rule(action, protocol, port, ip):
    if protocol == "any":
        return f"ufw {action.lower()} from {ip}"
    if protocol == "icmp":
        return f"ufw allow from {ip} proto icmp"
    return f"ufw {action.lower()} {protocol} from {ip} to any port {port}"

def generate_firewalld_rule(action, protocol, port, ip):
    if protocol == "any":
        return f"firewall-cmd --add-rich-rule='rule family=\"ipv4\" source address=\"{ip}\" accept'"
    if protocol == "icmp":
        return f"firewall-cmd --add-icmp-block=echo-request"
    return f"firewall-cmd --add-rich-rule='rule family=\"ipv4\" source address=\"{ip}\" port protocol=\"{protocol}\" port=\"{port}\" accept'"

def save_rules(rules, format_choice):
    filename = f"firewall_rules.{format_choice}"
    try:
        if format_choice == "json":
            with open(filename, "w") as file:
                json.dump(rules, file, indent=4)
        elif format_choice == "yaml":
            with open(filename, "w") as file:
                yaml.dump(rules, file, default_flow_style=False)
        elif format_choice == "txt":
            with open(filename, "w") as file:
                for rule in rules:
                    file.write(f"{rule}\n")
        logging.info(f"Rules saved to {filename}")
        print(f"Rules saved to {filename}")
    except Exception as e:
        logging.error(f"Failed to save rules: {e}")
        print(f"Failed to save rules: {e}")

def get_user_input():
    action = input("Enter action (ACCEPT/DROP/REJECT): ").strip().upper()
    protocol = input("Enter protocol (tcp/udp/icmp/any): ").strip().lower()
    port = input("Enter port number (or 'any' for all ports): ").strip()
    ip = input("Enter IP address (or 'any' for all IPs): ").strip()
    return action, protocol, port, ip

def main():
    parser = argparse.ArgumentParser(description='Firewall Rule Generator')
    parser.add_argument('--action', type=str, help='Action for the rule (ACCEPT/DROP/REJECT)')
    parser.add_argument('--protocol', type=str, help='Protocol for the rule (tcp/udp/icmp/any)')
    parser.add_argument('--port', type=str, help='Port number for the rule (or "any" for all ports)')
    parser.add_argument('--ip', type=str, help='IP address for the rule (or "any" for all IPs)')
    parser.add_argument('--format', type=str, choices=['json', 'yaml', 'txt'], help='Format for saving the rules (json/yaml/txt)')
    args = parser.parse_args()

    print("Firewall Rule Generator")
    print("========================")

    rules = []
    while True:
        if args.action and args.protocol and args.port and args.ip:
            action, protocol, port, ip = args.action, args.protocol, args.port, args.ip
        else:
            action, protocol, port, ip = get_user_input()

        if not action or action not in ["ACCEPT", "DROP", "REJECT"]:
            print("Invalid action. Please enter ACCEPT, DROP, or REJECT.")
            logging.warning("Invalid action input.")
            continue
        if not protocol or protocol not in ["tcp", "udp", "icmp", "any"]:
            print("Invalid protocol. Please enter tcp, udp, icmp, or any.")
            logging.warning("Invalid protocol input.")
            continue
        if not port or not is_valid_port(port, protocol):
            print("Invalid port number. Please enter a number between 1 and 65535, or 'any'.")
            logging.warning("Invalid port input.")
            continue
        if not ip or not is_valid_ip(ip):
            print("Invalid IP address. Please enter a valid IPv4 or IPv6 address, or 'any'.")
            logging.warning("Invalid IP input.")
            continue

        iptables_rule = generate_iptables_rule(action, protocol, port, ip)
        ufw_rule = generate_ufw_rule(action, protocol, port, ip)
        firewalld_rule = generate_firewalld_rule(action, protocol, port, ip)

        rules.append({"iptables": iptables_rule, "ufw": ufw_rule, "firewalld": firewalld_rule})

        logging.info(f"Generated rules: iptables: {iptables_rule}, ufw: {ufw_rule}, firewalld: {firewalld_rule}")
        print("\nGenerated rules:")
        print(f"iptables rule: {iptables_rule}")
        print(f"ufw rule: {ufw_rule}")
        print(f"firewalld rule: {firewalld_rule}")

        if args.action and args.protocol and args.port and args.ip:
            break
        else:
            another = input("\nDo you want to generate another rule? (yes/no): ").strip().lower()
            if another != 'yes':
                break

    save_option = input("\nDo you want to save the rules to a file? (yes/no): ").strip().lower()
    if save_option == 'yes':
        if not args.format:
            format_choice = input("Enter the format for saving the rules (json/yaml/txt): ").strip().lower()
        else:
            format_choice = args.format
        save_rules(rules, format_choice)
    else:
        print("Rules not saved.")

if __name__ == "__main__":
    main()




