"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        l1Host = self.addHost('h1')
        l2Host = self.addHost('h2')
        r1Host = self.addHost('h3')
        r2Host = self.addHost('h4')

        leftSwitch = self.addSwitch('s1')
        rightSwitch = self.addSwitch('s2')

        # Add links
        self.addLink(l1Host, leftSwitch)
        self.addLink(l2Host, leftSwitch)
        self.addLink(r1Host, rightSwitch)
        self.addLink(r2Host, rightSwitch)
        self.addLink(rightSwitch, leftSwitch)


topos = { 'mytopo': ( lambda: MyTopo() ) }