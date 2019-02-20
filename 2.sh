# Create hosts
sudo ip netns add h1
sudo ip netns add h2
sudo ip netns add h3

# Create switch
sudo ovs-vsctl add-br s1
sudo ovs-vsctl add-br s2

# Create links
sudo ip link add h1-eth0 type veth peer name s1-eth1
sudo ip link add h2-eth0 type veth peer name s1-eth2
sudo ip link add h3-eth0 type veth peer name s2-eth1
sudo ip link add s1-eth0 type veth peer name s2-eth0

# Move host ports into namespaces
sudo ip link set h1-eth0 netns h1
sudo ip link set h2-eth0 netns h2
sudo ip link set h3-eth0 netns h3

# Connect switch ports to OVS
sudo ovs-vsctl add-port s1 s1-eth1
sudo ovs-vsctl add-port s1 s1-eth2
sudo ovs-vsctl add-port s2 s2-eth1
sudo ovs-vsctl add-port s1 s1-eth0
sudo ovs-vsctl add-port s2 s2-eth0

# Set up OpenFlow controller
sudo ovs-vsctl set-controller s1 tcp:127.0.0.1
sudo ovs-vsctl set-controller s2 tcp:127.0.0.1
sudo ovs-controller ptcp: &

# Configure network
sudo ip netns exec h1 ifconfig h1-eth0 10.1
sudo ip netns exec h1 ifconfig lo up
sudo ip netns exec h2 ifconfig h2-eth0 10.2
sudo ip netns exec h2 ifconfig lo up
sudo ip netns exec h3 ifconfig h3-eth0 10.3
sudo ip netns exec h3 ifconfig lo up

sudo ifconfig s1-eth1 up
sudo ifconfig s1-eth2 up
sudo ifconfig s2-eth1 up
sudo ifconfig s1-eth0 up
sudo ifconfig s2-eth0 up

# Test network
sudo ip netns exec h1 ping -c1 10.3