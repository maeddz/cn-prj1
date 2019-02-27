from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self, n=2):
        if n < 2:
            n = 2

        Topo.__init__(self)

        left_host = self.addHost('h1')
        right_host = self.addHost('h2')

        for i in range(n):
            switch_name = 's' + str(i+1)
            new_switch = self.addSwitch(switch_name)
            if i == 0:
                self.addLink(left_host, new_switch)
            else:
                prev_switch_name = 's' + str(i)
                self.addLink(prev_switch_name, switch_name)
                # self.addLink(prev_switch_name, switchName, max_queue_size=1)

            if i == n - 1:
                self.addLink(right_host, new_switch)
                

num_of_switches = 2

topos = {'mytopo': (lambda: MyTopo(num_of_switches))}
