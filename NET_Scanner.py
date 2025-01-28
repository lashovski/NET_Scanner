import scapy.all as scapy
import optparse


def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--ipaddress", dest="ip_address", help="Enter IP address (e.g., 10.0.2.1/24)")

    (user_input, arguments) = parse_object.parse_args()

    if not user_input.ip_address:
        parse_object.error("IP Address is required. Use -i or --ipaddress to specify it.")
    return user_input


def scan_my_network(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    answered_list, unanswered_list = scapy.srp(combined_packet, timeout=1, verbose=False)

    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for element in answered_list:
        print(f"{element[1].psrc}\t\t{element[1].hwsrc}")

user_ip_address = get_user_input()
scan_my_network(user_ip_address.ip_address)