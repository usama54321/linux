#include <lkl.h>


struct SimDevice *dce_dev_create (const char *iface, void *priv, enum SimDevFlags flags)
{

}


void dce_dev_destroy (struct SimDevice *dev)
{

}

void * dce_dev_get_private (struct SimDevice *task)
{

}

void dce_dev_set_address (struct SimDevice *dev, unsigned char buffer[6])
{
  int ifindex = lkl_name_to_ifindex (dev);
  if (dev->dev.type == AF_INET)
  {
    lkl_if_set_ipv4 (ifindex, addr, netmask_len);
  }
  else if (dev->dev.type == AF_INET6)
  {
    lkl_if_set_ipv4 (ifindex, addr, netprefix_len);
  }
  else
  {
    // Notify dev.type doesn't support
  }
}

void dce_dev_set_mtu (struct SimDevice *dev, int mtu)
{
  int ifindex = lkl_name_to_ifindex (dev);
  lkl_if_set_mtu (ifindex);
}

void dce_dev_rx (struct SimDevice *dev, struct SimDevicePacket packet)
{

}

struct SimDevicePacket dce_dev_create_packet (struct SimDevice *dev, int size)
{

}

