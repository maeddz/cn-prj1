from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self, n=2):
        if n < 2:
            n = 2

        Topo.__init__(self)

        self.addSwitch('s1')

        for i in range(n):
            host_name = 'h' + str(i+1)
            self.addHost(host_name)
            self.addLink(host_name, 's1')


num_of_hosts = 4

topos = {'mytopo': (lambda: MyTopo(num_of_hosts))}
