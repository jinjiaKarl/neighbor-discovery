# This script is based on the following:
# https://github.com/n0a/telegram-get-remote-ip/blob/main/tg_get_ip.py

import pyshark
import platform
import os
import sys
import argparse
import netifaces


def check_tshark_availability():
    """Check Tshark install."""
    wireshark_path = None
    if platform.system() == "Darwin":
        wireshark_path = "/Applications/Wireshark.app/Contents/MacOS"
    elif platform.system() == "Linux":
        wireshark_path = os.popen('which wireshark').read().strip()
        tshark_path = os.popen('which tshark').read().strip()
        if os.path.isfile(wireshark_path):
            wireshark_path = os.path.dirname(wireshark_path)
        elif os.path.isfile(tshark_path):
            wireshark_path = os.path.dirname(tshark_path)

    if not wireshark_path:
        os_type = platform.system()
        if os_type == "Linux":
            print("Install tshark first: sudo apt update && apt install tshark")
        elif os_type == "Darwin":  # macOS
            print("Install Wireshark first: https://www.wireshark.org/download.html")
        else:
            print("Please install tshark.")
        sys.exit(1)
    else:
        print("[+] tshark is available.")

def choose_interface():
    """Prompt the user to select a network interface."""
    interfaces = netifaces.interfaces()
    print("[+] Available interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface}")
        try:
            ip_address = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
            print(f"[+] Selected interface: {iface} IP address: {ip_address}")
        except KeyError:
            print("[!] Unable to retrieve IP address for the selected interface.")

    choice = int(input("[+] Enter the number of the interface you want to use: "))
    return interfaces[choice - 1]


def parse_snd_packet(interface):
    # sniff traffic on interface needs sudo 
    print("[+] Capturing traffic, please wait...")
    capture = pyshark.LiveCapture(interface=interface, display_filter="tcp.port == 8080")
    for packet in capture.sniff_continuously(packet_count=100):
        # see all fields
        # print(packet.tcp.field_names)
        # print(packet.ip.field_names)
        if 'payload' in packet.tcp.field_names:
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            payload = packet.tcp.payload.binary_value.decode('utf-8')
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            print(f"[+] {src_ip}:{src_port} -> {dst_ip}:{dst_port} {payload}")
        

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='intercept and parse neighbor discovery packets')
    parser.add_argument('-i', '--interface', help='Network interface to use', default=None)
    return parser.parse_args()

def main():
    try:
        check_tshark_availability()
        args = parse_arguments()

        if args.interface:
            interface_name = args.interface 
        else:
            interface_name = choose_interface()

        parse_snd_packet(interface_name)

    except (KeyboardInterrupt, EOFError):
        print("\n[+] Exiting gracefully...")
        pass

if __name__ == "__main__":
    main()
