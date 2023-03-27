# -*- coding: utf-8 -*-

# GOAL: Send LLDP discovery broadcast packet, receive responses, and output JSON blobs for each received packet.

import ipaddress

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
            upstream = {}

            # What TLVs do we care about?
            # - Chassis ID
            # - Port ID
            # - Port Description
            # - System Name
            # - System Description
            # - System Capabilities
            # - Management Address
            # or, in other words, all of them. Except for the organization/vendor-specific TLVs.
            if lldp.LLDPDUChassisID in packet:
                chassis_id_tlv = packet[lldp.LLDPDUChassisID]
                upstream.setdefault("chassis", {})
                upstream["chassis"]["mac"] = chassis_id_tlv.id

            if lldp.LLDPDUPortDescription in packet:
                port_desc_tlv = packet[lldp.LLDPDUPortDescription]
                upstream.setdefault("link", {})
                upstream["link"]["description"] = port_desc_tlv.description

            if lldp.LLDPDUSystemName in packet:
                system_name_tlv = packet[lldp.LLDPDUSystemName]
                upstream.setdefault("system", {})
                upstream["system"]["name"] = system_name_tlv.system_name

            if lldp.LLDPDUSystemDescription in packet:
                system_desc_tlv = packet[lldp.LLDPDUSystemDescription]
                upstream.setdefault("system", {})
                upstream["system"]["description"] = system_desc_tlv.description

            if lldp.LLDPDUSystemCapabilities in packet:
                caps_tlvs = packet[lldp.LLDPDUSystemCapabilities]
                upstream.setdefault("system", {})
                upstream["system"]["is_router"] = caps_tlvs.router_enabled == 1
                upstream["system"]["is_mac_bridge"] = caps_tlvs.mac_bridge_enabled == 1
                upstream["system"]["id_repeater"] = caps_tlvs.repeater_enabled == 1
                upstream["system"]["is_wlan_access_point"] = caps_tlvs.wlan_access_point_enabled == 1

            if lldp.LLDPDUManagementAddress in packet:
                mgmt_tlv = packet[lldp.LLDPDUManagementAddress]
                upstream.setdefault("management", {})
                if mgmt_tlv.management_address_subtype == lldp.LLDPDUManagementAddress.SUBTYPE_MANAGEMENT_ADDRESS_IPV4:
                    upstream["management"]["ipv4"] = str(ipaddress.IPv4Address(mgmt_tlv.management_address))

                upstream["management"]["interface_number"] = mgmt_tlv.interface_number

                hex_oid = mgmt_tlv.object_id
                pretty_oid = []
                for oid_byte in bytearray(hex_oid):
                    pretty_oid.append(str(int(oid_byte)))

                pretty_oid = ".".join(pretty_oid)
                upstream["management"]["oid"] = pretty_oid

            print(upstream)