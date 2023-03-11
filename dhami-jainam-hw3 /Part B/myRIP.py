from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class LinuxRouter(Node):

    def config (self, **params):
        super (LinuxRouter, self).config(**params)
        self.cmd ('sysctl net.ipv4.ip_forward=1')
        self.cmd (" cd %s " % self.name)
        self.cmd ('sudo bird -l')
        self.cmd('cd ..')
    
    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        self.cmd (" cd %s " % self.name)
        self.cmd ('sudo birdc -l down')
        self.cmd('cd ..')

        super(LinuxRouter, self).terminate()

class NetworkTopo( Topo ):

    def build( self, **_opts ):

        r1 = self.addNode( 'r1', cls=LinuxRouter, ip=None)
        r2 = self.addNode( 'r2', cls=LinuxRouter, ip=None)
        r3 = self.addNode( 'r3', cls=LinuxRouter, ip=None)
        r4 = self.addNode( 'r4', cls=LinuxRouter, ip=None)

        h1 = self.addHost( 'h1', ip='172.2.7.2/24',
                           defaultRoute='via 172.2.7.1' )
        h2 = self.addHost( 'h2', ip='172.2.9.2/24',
                           defaultRoute='via 172.2.9.1' )

        self.addLink( h1, r1, intfName2='r1-eth0',
                      params2={ 'ip' : '172.2.7.1/24'} )
        self.addLink( h2, r4, intfName2='r4-eth0',
                      params2={ 'ip' : '172.2.9.1/24' } )

        self.addLink( r1, r2, intfName1='r1-eth1', intfName2='r2-eth0', params1={'ip': '172.2.0.1/24'},
                     params2={'ip': '172.2.0.2/24'} )
        self.addLink( r2, r4, intfName1='r2-eth1', intfName2='r4-eth1', params1={'ip': '172.2.1.3/24'},
                     params2={'ip': '172.2.1.4/24'} )
        self.addLink( r1, r3, intfName1='r1-eth2', intfName2='r3-eth0', params1={'ip': '172.2.2.5/24'},
                params2={'ip': '172.2.2.6/24'} )
        self.addLink( r3, r4, intfName1='r3-eth1', intfName2='r4-eth2', params1={'ip': '172.2.3.7/24'},
                params2={'ip': '172.2.3.8/24'} )

def run():

    topo = NetworkTopo()
    net = Mininet(topo=topo)
    net.start()
    #info( '*** Routing Table on Router:\n' )
 
    #info(net['r1'].cmd('ip addr add {} {}'.format('172.2.0.1/24','r1-eth1')))
    #info(net['r1'].cmd('ip addr add {} {}'.format('172.2.2.5/24','r1-eth2')))

    #info(net['r2'].cmd('ip addr add {} {}'.format('172.2.1.3/24','r2-eth1')))

    #info(net['r3'].cmd('ip addr add {} {}'.format('172.2.3.7/24','r3-eth1')))

    #info(net['r4'].cmd('ip addr add {} {}'.format('172.2.1.4/24','r4-eth1')))
    #info(net['r4'].cmd('ip addr add {} {}'.format('172.2.3.8/24','r4-eth2')))

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()