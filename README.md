# Clerk

Clerk is a passive netflow/IPFIX generator designed for high-throughput and
testimony-based packet sharing.

## Architecture

`clerk` uses https://github.com/google/testimony to get packets across N threads.

   1 Packet hits NIC
   1 Kernel places packet in `AF_PACKET` mmap region
   1 `testimonyd` hands mmap region to `clerk` packet thread
   1 `clerk` thread looks up and updates flow info
      * creates a key based on identifiers (src/dst IP/port, protocol, qos, etc)
      * looks up current stats, creating empty statistics if necessary
      * updates stats with new bytes/packets/tcp flags/etc.
   1 every minute, `clerk` main thread sends IPFIX
      * gathers flows from each of N packet threads
      * combines flows
      * generates IPFIX packets based on combined flow from all threads
      * sends out UDP socket

## Flow Information

Currently, `clerk` uses a fixed template (actually 2, one for IPv4, the other
for IPv6):

   * `IPV4_SRC_ADDR` (4 bytes) or `IPV6_SRC_ADDR` (16 bytes)
   * `IPV4_DST_ADDR` (4 bytes) or `IPV6_DST_ADDR` (16 bytes)
   * `L4_SRC_PORT` (2 bytes)
   * `L4_DST_PORT` (2 bytes)
   * `PROTOCOL` (1 byte)
   * `TCP_FLAGS` (1 byte)
   * `ICMP_TYPE` (2 bytes)
   * `BGP_SOURCE_AS_NUMBER` (4 bytes)
   * `BGP_DESTINATION_AS_NUMBER` (4 bytes)
   * `IN_BYTES` (8 bytes)
   * `IN_PKTS` (8 bytes)
   * `FLOW_START_NANOSECONDS` (8 bytes)
   * `FLOW_END_NANOSECONDS` (8 bytes)
   * `IP_CLASS_OF_SERVICE` (1 byte)
   * `FLOW_END_REASON` (1 byte)
   * `VLAN_ID` (2 bytes)

It's probably possible to expand this further in the future, but for now this
solves most of our internal needs quite nicely.

## Disclaimer

This is not an official Google product.
