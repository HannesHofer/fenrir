#!/usr/bin/env python3

from iptc import Rule, Chain, Match, Table, Target
from argparse import ArgumentParser


class Firewall:
    """ class to contain all Firewall handling

    Handles all firewall handling.
    En/Disabling firewall/ forwarding
    Clear all firewall rules
    """
    @staticmethod
    def allowforward(input_interface, output_interface, states=None) -> None:
        """ enable forwarding from given input_interface to output_interface

        :param input_interface: allow traffic from interface
        :param output_interface: allow traffic to interface
        """
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
    def masquerade(output_interface, routingmode='POSTROUTING') -> None:
        """ enable NAT / masquerading on given output_interface

        :param output_interface: allow NAT / masquerade on interface
        :param routingmode: mode to allow NAT (postrouting/ prerouting)
        """
        chain = Chain(Table(Table.NAT), routingmode)
        rule = Rule()
        rule.out_interface = output_interface
        rule.target = Target(rule, 'MASQUERADE')
        chain.insert_rule(rule)

    @staticmethod
    def rewriteDNS(destination_dns_server) -> None:
        """ redirect all DNS requests to given server

        :param destination_dns_server: DNSServer all DNS requests are sent to
        """
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
    def forwarding(allow) -> None:
        """ allow/disallow systemwide forwarding

        :param allow: allow systemwide forwarding if True, disallow on False
        """
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write(f'{1 if allow else 0}')
            f.close()
        Chain(Table(Table.FILTER), 'FORWARD').set_policy('ACCEPT')

    @staticmethod
    def clear() -> None:
        """ clear all firewall rules """
        Chain(Table(Table.FILTER), 'INPUT').flush()
        Chain(Table(Table.FILTER), 'OUTPUT').flush()
        Chain(Table(Table.FILTER), 'FORWARD').flush()

    @staticmethod
    def enable(input_interface, output_interface) -> None:
        """ enable firewall settings for forwarding

        :param input_interface: interface for ingress traffic
        :param output_interface: interface to route spoofed traffic to

        enable system-wide forwarding.
        enable forwarding from input to output interface
        """
        Firewall.forwarding(allow=True)
        Firewall.allowforward(input_interface=input_interface,
                              output_interface=output_interface)
        Firewall.allowforward(input_interface=input_interface,
                              output_interface=output_interface,
                              states='RELATED,ESTABLISHED')
        Firewall.masquerade(output_interface=output_interface)

    @staticmethod
    def disable(input_interface, output_interface) -> None:
        """ enable firewall settings for forwarding

        :param input_interface: interface for ingress traffic
        :param output_interface: interface for routed/spoofed traffic

        disable forwarding for given input/outputinterface
        """
        chain = Chain(Table(Table.FILTER), 'FORWARD')
        deleterules = []
        for rule in chain.rules:
            if rule.in_interface == input_interface and rule.out_interface == output_interface:
                deleterules.append(rule)
                chain.delete_rule(rule)


def main() -> None:
    """ main method

    parse given commandline arguments
    start Firewall
    """
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
