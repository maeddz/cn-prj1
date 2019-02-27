"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo


class MyTopo(Topo):
    """Simple topology example."""

    def __init__(self):
        """Create custom topo."""

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        l1_host = self.addHost('h1')
        l2_host = self.addHost('h2')
        r1_host = self.addHost('h3')
        r2_host = self.addHost('h4')

        left_switch = self.addSwitch('s1')
        right_switch = self.addSwitch('s2')

        # Add links
        self.addLink(l1_host, left_switch)
        self.addLink(l2_host, left_switch)
        self.addLink(r1_host, right_switch)
        self.addLink(r2_host, right_switch)
        self.addLink(right_switch, left_switch)


topos = {'mytopo': (lambda: MyTopo())}
