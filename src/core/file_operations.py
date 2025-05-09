from scapy.all import rdpcap, wrpcap

def import_packets_from_file(filename):
    return rdpcap(filename)

def export_packets_to_file(filename, packets):
    wrpcap(filename, packets)

