#ifndef ETHER_SOC_H
#define ETHER_SOC_H

#include "net.h"

extern struct net_device *ether_soc_init(const char *name);
extern char *ip_soc_netmask(struct net_device *dev, char *mask_addr, size_t size);

#endif