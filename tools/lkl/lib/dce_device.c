#include <lkl.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ethtool.h>

struct SimDevice *dce_dev_create (const char *iface, void *priv, enum SimDevFlags flags)
{
  int err;
  struct SimDevice *dev =
    (struct SimDevice *)alloc_netdev(sizeof(struct SimDevice),
             ifname, NET_NAME_UNKNOWN,
             &lib_dev_setup);
  ether_setup((struct net_device *)dev);

  if (flags & SIM_DEV_NOARP)
    dev->dev.flags |= IFF_NOARP;
  if (flags & SIM_DEV_POINTTOPOINT)
    dev->dev.flags |= IFF_POINTOPOINT;
  if (flags & SIM_DEV_MULTICAST)
    dev->dev.flags |= IFF_MULTICAST;
  if (flags & SIM_DEV_BROADCAST) {
    dev->dev.flags |= IFF_BROADCAST; 
    memset(dev->dev.broadcast, 0xff, 6);
  }
  dev->= priv;
  err = register_netdev(&dev->dev);
  return dev;
}


void dce_dev_destroy (struct SimDevice *dev)
{
  unregister_netdev(&dev->dev);
  /* XXX */
  free_netdev(&dev->dev);
}

void dce_dev_set_address (struct SimDevice *dev, unsigned char buffer[6])
{
  int ifindex = get_device_ifindex (dev); 
  if (dev->dev.type == AF_INET)
  {
    lkl_if_set_ipv4 (ifindex, addr, netmask_len);
  }
  else if (dev->dev.type == AF_INET6)
  {
    lkl_if_set_ipv6 (ifindex, addr, netprefix_len);
  }
  else
  {
    // Notify dev.type doesn't support
  }
}

void dce_dev_set_mtu (struct SimDevice *dev, int mtu)
{
  int ifindex = get_device_ifindex (dev);
  lkl_if_set_mtu (ifindex, mtu);
}

void dce_dev_rx (struct SimDevice *dev, struct SimDevicePacket packet)
{

}

struct SimDevicePacket dce_dev_create_packet (struct SimDevice *dev, int size)
{

}

int get_device_ifindex (struct SimDevice *dev)
{
  return dev->dev.ifindex;
}
