#ifndef _DCE_INIT_H_
#define _DCE_INIT_H_

#include <lkl.h>
#include "dce-types.h"

#ifdef __cplusplus
extern "C" {
#endif


//Inspired from net-next-nuse: sim-init.h
struct DceExport {
  /*
   * Function pointer to \
   * the functions declared \
   * in lkl.h.
   * Will remove unused function \
   * from this list.
   */
  int (*dce_lkl_add_gateway)(int af,void * gwaddr);
  int (*dce_lkl_add_neighbor)(int ifindex,int af,void * addr,void * mac);
  int (*dce_lkl_closedir)(struct lkl_dir * dir);
  int (*dce_lkl_dirfd)(struct lkl_dir * dir);
  int (*dce_lkl_disk_add)(struct lkl_disk * disk);
  int (*dce_lkl_disk_remove)(struct lkl_disk disk);
  int (*dce_lkl_encode_dev_from_sysfs)(const char * sysfs_path,uint32_t * pdevid);
  int (*dce_lkl_errdir)(struct lkl_dir * dir);
  struct lkl_dir * (*dce_lkl_fdopendir)(int fd,int * err);
  int (*dce_lkl_get_virtio_blkdev)(int disk_id,unsigned int part,uint32_t * pdevid);
  int (*dce_lkl_if_add_gateway)(int ifindex,int af,void * gwaddr);
  int (*dce_lkl_if_add_ip)(int ifindex,int af,void * addr,unsigned int netprefix_len);
  int (*dce_lkl_if_add_linklocal)(int ifindex,int af,void * addr,int netprefix_len);
  int (*dce_lkl_if_add_rule_from_saddr)(int ifindex,int af,void * saddr);
  int (*dce_lkl_if_del_ip)(int ifindex,int af,void * addr,unsigned int netprefix_len);
  int (*dce_lkl_if_down)(int ifindex);
  int (*dce_lkl_if_set_ipv4)(int ifindex,unsigned int addr,unsigned int netmask_len);
  int (*dce_lkl_if_set_ipv4_gateway)(int ifindex,unsigned int addr,unsigned int netmask_len,unsigned int gw_addr);
  int (*dce_lkl_if_set_ipv6)(int ifindex,void * addr,unsigned int netprefix_len);
  int (*dce_lkl_if_set_ipv6_gateway)(int ifindex,void * addr,unsigned int netmask_len,void * gw_addr);
  int (*dce_lkl_if_set_mtu)(int ifindex,int mtu);
  int (*dce_lkl_if_up)(int ifindex);
  int (*dce_lkl_if_wait_ipv6_dad)(int ifindex,void * addr);
  long (*dce_lkl_mount_dev)(unsigned int disk_id,unsigned int part,const char * fs_type,int flags,const char * opts,char * mnt_str,unsigned int mnt_str_len);
  int (*dce_lkl_mount_fs)(char * fstype);
  int (*dce_lkl_netdev_add)(struct lkl_netdev * nd,struct lkl_netdev_args * args);
  struct lkl_netdev * (*dce_lkl_netdev_dpdk_create)(const char * ifname,int offload,unsigned char * mac);
  void (*dce_lkl_netdev_free)(struct lkl_netdev * nd);
  int (*dce_lkl_netdev_get_ifindex)(int id);
  struct lkl_netdev * (*dce_lkl_netdev_macvtap_create)(const char * path,int offload);
  struct lkl_netdev * (*dce_lkl_netdev_pipe_create)(char * ifname,int offload);
  struct lkl_netdev * (*dce_lkl_netdev_raw_create)(const char * ifname);
  void (*dce_lkl_netdev_remove)(int id);
  struct lkl_netdev * (*dce_lkl_netdev_tap_create)(const char * ifname,int offload);
  struct lkl_netdev * (*dce_lkl_netdev_vde_create)(const char * switch_path);
  struct lkl_dir * (*dce_lkl_opendir)(const char * path,int * err);
  void (*dce_lkl_perror)(char * msg,int err);
  int (*dce_lkl_qdisc_add)(int ifindex,char * root,char * type);
  void (*dce_lkl_qdisc_parse_add)(int ifindex,char * entries);
  struct lkl_linux_dirent64 * (*dce_lkl_readdir)(struct lkl_dir * dir);
  void (*dce_lkl_register_dbg_handler)(void);
  void (*dce_lkl_rewinddir)(struct lkl_dir * dir);
  int (*dce_lkl_set_fd_limit)(unsigned int fd_limit);
  int (*dce_lkl_set_ipv4_gateway)(unsigned int addr);
  int (*dce_lkl_set_ipv6_gateway)(void * addr);
  const char * (*dce_lkl_strerror)(int err);
  long long (*dce_lkl_sys_lseek)(unsigned int fd, __lkl__kernel_loff_t off,unsigned int whence);
  void * (*dce_lkl_sys_mmap)(void * addr,size_t length,int prot,int flags,int fd,off_t offset);
  int (*dce_lkl_sysctl)(const char * path,const char * value);
  void (*dce_lkl_sysctl_parse_write)(const char * sysctls);
  long (*dce_lkl_umount_dev)(unsigned int disk_id,unsigned int part,int flags,long timeout_ms);
  long (*dce_lkl_umount_timeout)(char * path,int flags,long timeout_ms);

  /*
   * Socket related export function.
   */
  int (*sock_socket)(int domain, int type, int protocol,
      struct SimSocket **socket);
  int (*sock_close)(struct SimSocket *socket);
  ssize_t (*sock_recvmsg)(struct SimSocket *socket, struct msghdr *msg,
          int flags);
  ssize_t (*sock_sendmsg)(struct SimSocket *socket,
          const struct msghdr *msg, int flags);
  int (*sock_getsockname)(struct SimSocket *socket,
      struct sockaddr *name, int *namelen);
  int (*sock_getpeername)(struct SimSocket *socket,
      struct sockaddr *name, int *namelen);
  int (*sock_bind)(struct SimSocket *socket, const struct sockaddr *name,
      int namelen);
  int (*sock_connect)(struct SimSocket *socket,
      const struct sockaddr *name, int namelen,
      int flags);
  int (*sock_listen)(struct SimSocket *socket, int backlog);
  int (*sock_shutdown)(struct SimSocket *socket, int how);
  int (*sock_accept)(struct SimSocket *socket,
      struct SimSocket **newSocket, int flags);
  int (*sock_ioctl)(struct SimSocket *socket, int request, char *argp);
  int (*sock_setsockopt)(struct SimSocket *socket, int level,
      int optname,
      const void *optval, int optlen);
  int (*sock_getsockopt)(struct SimSocket *socket, int level,
      int optname,
      void *optval, int *optlen);

  // socket poll 
  void (*sock_poll)(struct SimSocket *socket, void *ret);
  void (*sock_pollfreewait)(void *polltable);

  // Device related calls.
  // TODO: Checl which are already \
  // present in lkl.h
  struct SimDevice *(*dev_create)(const char *ifname, void *priv,
          enum SimDevFlags flags);
  void (*dev_destroy)(struct SimDevice *dev);
  void *(*dev_get_private)(struct SimDevice *task);
  void (*dev_set_address)(struct SimDevice *dev,
        unsigned char buffer[6]);
  void (*dev_set_mtu)(struct SimDevice *dev, int mtu);
  struct SimDevicePacket (*dev_create_packet)(struct SimDevice *dev,
            int size);
  void (*dev_rx)(struct SimDevice *dev, struct SimDevicePacket packet);

  void (*sys_iterate_files)(const struct SimSysIterator *iter);
  int (*sys_file_read)(const struct SimSysFile *file, char *buffer,
      int size, int offset);
  int (*sys_file_write)(const struct SimSysFile *file,
      const char *buffer, int size, int offset);
}

struct DceImport {
  int (*vprintf)(struct SimKernel *kernel, const char *str,
      va_list args);
  void *(*malloc)(struct SimKernel *kernel, unsigned long size);
  void (*free)(struct SimKernel *kernel, void *buffer);
  void *(*memcpy)(struct SimKernel *kernel, void *dst, const void *src,
       unsigned long size);
  void *(*memset)(struct SimKernel *kernel, void *dst, char value,
       unsigned long size);
  int (*atexit)(struct SimKernel *kernel, void (*function)(void));
  int (*access)(struct SimKernel *kernel, const char *pathname,
      int mode);
  char *(*getenv)(struct SimKernel *kernel, const char *name);
  int (*mkdir)(struct SimKernel *kernel, const char *pathname,
      mode_t mode);
  int (*open)(struct SimKernel *kernel, const char *pathname, int flags);
  int (*__fxstat)(struct SimKernel *kernel, int ver, int fd, void *buf);
  int (*fseek)(struct SimKernel *kernel, FILE *stream, long offset,
      int whence);
  void (*setbuf)(struct SimKernel *kernel, FILE *stream, char *buf);
  FILE *(*fdopen)(struct SimKernel *kernel, int fd, const char *mode);
  long (*ftell)(struct SimKernel *kernel, FILE *stream);
  int (*fclose)(struct SimKernel *kernel, FILE *fp);
  size_t (*fread)(struct SimKernel *kernel, void *ptr, size_t size,
         size_t nmemb, FILE *stream);
  size_t (*fwrite)(struct SimKernel *kernel, const void *ptr, size_t size,
         size_t nmemb, FILE *stream);
  unsigned long (*random)(struct SimKernel *kernel);
  void *(*event_schedule_ns)(struct SimKernel *kernel, __u64 ns,
       void (*fn)(void *context), void *context,
       void (*pre_fn)(void));
  void (*event_cancel)(struct SimKernel *kernel, void *event);
  __u64 (*current_ns)(struct SimKernel *kernel);

  struct SimTask *(*task_start)(struct SimKernel *kernel,
        void (*callback)(void *),
        void *context);
  void (*task_wait)(struct SimKernel *kernel);
  struct SimTask *(*task_current)(struct SimKernel *kernel);
  int (*task_wakeup)(struct SimKernel *kernel, struct SimTask *task);
  void (*task_yield)(struct SimKernel *kernel);

  void (*dev_xmit)(struct SimKernel *kernel, struct SimDevice *dev,
       unsigned char *data, int len);
  void (*signal_raised)(struct SimKernel *kernel, struct SimTask *task,
       int sig);
  void (*poll_event)(int flag, void *context);
}

// DCE will locate dce_init function after loading lkl library file.i
typedef void (*DceInit)(struct DceExported *, const struct DceImported *,
      struct DceKernel *kernel);
void dce_init(struct DceExported *exported, const struct DceImported *imported,
      struct DceKernel *kernel);
#ifdef __cplusplus
}
#endif

#ifdef /* DCE_INIT_SEEN */
