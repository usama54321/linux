#include <linux/net.h>
#include <linux/errno.h>
#include <net/sock.h>
#include "dce-init.h"
#include "../include/dce-types.h"


int dce_sock_socket (int domain, int type, int protocol, struct DceSocket **socket)
{
  struct socket **kernel_socket = (struct socket **)socket;
  // Check type if any unsupport flag is passed
  if (type)
  {
    return -EINVAL;
  }

  int reteval = sock_create(domain, type, protocol, kernel_socket);
  struct file *fp = lib_malloc(sizeof(struct file));
  (*kernel_socket)->file = fp;
  fp->f_cred = lib_malloc(sizeof(struct cred));
  return retval;
}

//TDOD: Do we need remove the scoket file descriptor created in dce_sock_socket.
int dce_sock_close (struct DceSocket *socket)
{
  struct socket *kernel_socket = (struct socket *)socket;
  sock_release(kernel_socket);
  return 0;
}

ssize_t dce_sock_recvmsg (struct DceSocket *socket, struct msghdr *msg, int flags)
{

}

ssize_t dce_sock_sendmsg (struct DceSocket *socket, const struct msghdr *msg, int flags)
{

}

int dce_sock_getsockname (struct DceSocket *socket, struct sockaddr *name, int *namelen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->getname(kernel_socket, name, namelen, 0);
  return error;
}

int dce_sock_getpeername (struct DceSocket *socket, struct sockaddr *name, int *namelen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->getname(kernel_socket, name, namelen, 1);

  return error;
}

int dce_sock_bind (struct DceSocket *socket, const struct sockaddr *name, int namelen)
{
  struct socket * kernel_socket = (struct socket *)socket;
  struct sockaddr_storage address;

  memcpy(&address, name, namelen);
  int error = kernel_socket->ops->bind(kernel_socket, (struct sockaddr *)&address, namelen);
  return error;

}

int dce_sock_connect (struct DceSocket *socket, const struct sockaddr *name, int namelen, int flags);
{
  struct socket *kernel_socket = (struct socket *)socket;
  struct sockaddr_storage address;
  
  memcpy(&address, name, namelen);
  
  kernel_socket->file->f_flags = flags;
  int retval = kernel_socket->ops->connect(kernel_socket, (struct sockaddr *)&address,
          namelen, flags);
  return retval;
}

int dce_sock_listen (struct DceSocket *socket, int backlog)
{
  struct socket * kernel_socket = (struct socket *)socket;
  int error = kernel_socket->ops->listen(kernel_socket, backlog);
  return error;
}

int dce_sock_shutdown (struct DceSocket *socket, int how)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int retval = kernel_socket->ops->shutdown(kernel_socket, how);
  return error;
}

int dce_sock_accept (struct DceSocket *socket, struct DceSocket **newSocket, int flags)
{

}

int dce_sock_ioctl (struct DceSocket *socket, int request, char *argp)
{
  // Need to create lkl_device first
}

int dce_sock_setsockopt (struct DceSocket *socket, int level, int optname, const void *optval, int optlen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  char *coptval = (char *)optval;
  int error;

  if (level == SOL_SOCKET)
    err = sock_setsockopt(sock, level, optname, coptval, optlen);
  return error;
}

int dce_sock_getsockopt (struct DceSocket *socket, int level, int optname, void *optval, int *optlen)
{
  struct socket *kernel_socket = (struct socket *)socket;
  int error;
  error = sock_getsockopt(sock, level, optname, optval, optlen);
  return err;
}
