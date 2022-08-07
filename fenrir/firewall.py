#!/usr/bin/env python3

from iptc import Rule, Chain, Match, Table, Target
from argparse import ArgumentParser


class Firewall:
    @staticmethod
    def allowforward(input_interface, output_interface, states=None):
        chain = Chain(Table(Table.FILTER), 'FORWARD')
        rule = Rule()
        rule.target = rule.create_target('ACCEPT')
        rule.in_interface = input_interface
        rule.out_interface = output_interface
        if states:
            match = Match(rule, 'state')
            match.state = states
            rule.add_match(match)
        chain.insert_rule(rule)

    @staticmethod
    def masquerade(output_interface, routingmode='POSTROUTING'):
        chain = Chain(Table(Table.NAT), routingmode)
        rule = Rule()
        rule.out_interface = output_interface
        rule.target = Target(rule, 'MASQUERADE')
        chain.insert_rule(rule)

    @staticmethod
    def rewriteDNS(destination_dns_server):
        chain = Chain(Table(Table.NAT), "PREROUTING")
        rule = Rule()
        rule.protocol = 'udp'
        target = rule.create_target('DNAT')
        target.to_destination = destination_dns_server
        rule.target = target
        match = Match(rule, 'udp')
        match.dport = '53'
        chain.insert_rule(rule)

    @staticmethod
    def forwarding(allow):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(f'{1 if allow else 0}')
            f.close()

    @staticmethod
    def clear():
        Chain(Table(Table.FILTER), 'INPUT').flush()
        Chain(Table(Table.FILTER), 'OUTPUT').flush()
        Chain(Table(Table.FILTER), 'FORWARD').flush()

    def enable(self, input_interface, output_interface):
        self.clear()
        self.forwarding(allow=True)
        self.allowforward(input_interface=input_interface,
                          output_interface=output_interface)
        self.allowforward(input_interface=input_interface, output_interface=output_interface,
                          states='RELATED,ESTABLISHED')
        self.masquerade(output_interface='tun0')


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--disable', help='disable firewall', action='store_true')
    parser.add_argument(
        '--inputinterface', help='interface for traffic interception (input)', default='eth0')
    parser.add_argument(
        '--outputinterface', help='interface for destination routing (output)', default='tun0')
    parser.add_argument(
        '--dnsserver', help='DNSServer for intercepted traffic to be re-routed', default='1.1.1.1')
    args = parser.parse_args()
    fw = Firewall()
    fw.enable(input_interface=args.inputinterface,
              output_interface=args.outputinterface)
    fw.rewriteDNS(destination_dns_server=args.dnsserver)


if __name__ == "__main__":
    main()
