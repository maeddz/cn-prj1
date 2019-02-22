from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self, n=2):
        if n < 2:
            n = 2

        Topo.__init__(self)

        leftHost = self.addHost('h1')
        rightHost = self.addHost('h2')

        for i in range(n):
            switchName = 's' + str(i+1)
            newSwitch = self.addSwitch(switchName)
            if i == 0:
                self.addLink(leftHost, newSwitch)
            else:
                prevSwitchName = 's' + str(i)
                self.addLink(prevSwitchName, switchName)
                # self.addLink(prevSwitchName, switchName, max_queue_size=1)

            if i == n - 1:
                self.addLink(rightHost, newSwitch)
                

num_of_switches = 2

topos = {'mytopo': (lambda: MyTopo(num_of_switches))}
