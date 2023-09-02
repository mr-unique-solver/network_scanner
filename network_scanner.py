import scapy.all as scapy
import argparse
def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--t",dest="target",help="ipv4/ipv6")
    options=parser.parse_args()
    return options
def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    print(answered_list.show())
    clients_list=[]
    for client in answered_list:
        client_dict={"ip":client[1].psrc,"mac":client[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
def print_result(results):
    print("IP\t\t\tMAC ADDRESS\n________________________________________________________")
    for client in results:
        print(client["ip"]+"\t\t"+client["mac"])
options=get_arguments()

scan_result=scan(options.target)
print(scan_result)

print_result(scan_result)


