# -*- coding: utf-8 -*-

# GOAL: Send LLDP discovery broadcast packet, receive responses, and output JSON blobs for each received packet.

import click
import scapy.all as scapy
from scapy.contrib import lldp


@click.command()
@click.argument("interface", type=str)
def cli(interface: str):
    upstream = scapy.sniff(
        iface=interface,
        monitor=True,
        count=1,
        # This filters for raw ethernet packets with the LLDP protocol magic set
        filter="ether proto 0x88cc",
    )
    # There should only be one, but maybe we want to handle cases where there
    # could be more from different devices? Is there even a valid case where
    # that would happen?
    for packet in upstream:
        if lldp.LLDPDU in packet:
            # Hooray, this is actually an LLDP packet!
            packet = packet[lldp.LLDPDU]
            print(packet)