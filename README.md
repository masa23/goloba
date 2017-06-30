# goloba


## ToDo

* lvs contorol 
* hearthcheck 
* vrrp 

## Credits

* [google/seesaw: Seesaw v2 is a Linux Virtual Server (LVS) based load balancing platform.](https://github.com/google/seesaw/) - VRRP code is copied from this library and modified for this package.
* [mqliang/libipvs: Pure Go lib to work with IPVS using generic netlink socket](https://github.com/mqliang/libipvs) - for accessing IPVS.
* [hkwi/nlgo: golang libnl library](https://github.com/hkwi/nlgo) - used in mqliang/libipvs.
* [mdlayher/arp: Package arp implements the ARP protocol, as described in RFC 826. MIT Licensed.](https://github.com/mdlayher/arp) - for sending GARP packets.
* [hnakamur/netutil: netutil provides some Go network utility functions.](https://github.com/hnakamur/netutil) - for adding IP addresses to a network interface and deleting them from one.
* and other libraries
