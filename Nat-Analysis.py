import pcapy

# Set the network interface to capture packets on
iface = "eth0"

# Open the network interface for capturing packets
cap = pcapy.open_live(iface, 65536, True, 0)

# Set a filter to capture only TCP packets
cap.setfilter('tcp')

# Loop through the captured packets and print their data
while True:
    (header, packet) = cap.next()
    print(packet)
