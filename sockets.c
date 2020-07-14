/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Sharan Santhanam <sharan.santhanam@neclab.eu>
 *          Alexander Jung <alexander.jung@neclab.eu>
 *
 * Copyright (c) 2020, NEC Laboratories Europe GmbH, NEC Corporation.
 *                     All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <uk/config.h>
#include <uk/assert.h>
#include <sys/socket.h>
#include <uk/socket.h>
#include <lwip/sockets.h>
#include <uk/print.h>

struct lwip_socket {
  int lwip_fd;
};

int
lwip_lib_socket_init(struct posix_socket_driver *d)
{
  return 0;
}

static void *
lwip_glue_create(struct posix_socket_driver *d,
          int family, int type, int protocol)
{
  void *ret = NULL;
  struct lwip_socket *lwip_sock;

  /* Use our socket data store to hold onto LwIP's file descriptor. */
  lwip_sock = uk_calloc(d->allocator, 1, sizeof(struct lwip_socket));
  if (!lwip_sock) {
    ret = NULL;
    SOCKET_LIB_ERR(d, -1, "could not allocate socket: out of memory");
    goto EXIT;
  }
  
  /* Create an LwIP socket */
  lwip_sock->lwip_fd = lwip_socket(family, type, protocol);
  if (lwip_sock->lwip_fd < 0) {
    ret = NULL;
    goto LWIP_SOCKET_CLEANUP;
  }

  /* Return the whole LwIP socket struct for the driver */
  ret = lwip_sock;

EXIT:
  return ret;

LWIP_SOCKET_CLEANUP:
  uk_free(d->allocator, lwip_sock);
  goto EXIT;
}

static void *
lwip_glue_accept(struct posix_socket_driver *d,
          void *sock, struct sockaddr *restrict addr,
          socklen_t *restrict addr_len)
{
  void *ret = NULL;
  struct lwip_socket *lwip_sock;
  struct lwip_socket *new_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = NULL;
    SOCKET_LIB_ERR(d, -1, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Use our socket data store to hold onto LwIP's file descriptor. */
  new_sock = uk_calloc(d->allocator, 1, sizeof(struct lwip_socket));
  if (!new_sock) {
    ret = NULL;
    SOCKET_LIB_ERR(d, -1, "could not allocate socket: out of memory");
    goto EXIT;
  }
  
  /* Create an LwIP socket */
  new_sock->lwip_fd = lwip_accept(lwip_sock->lwip_fd, addr, addr_len);
  if (new_sock->lwip_fd < 0) {
    ret = NULL;
    goto LWIP_SOCKET_CLEANUP;
  }

  /* Return the whole LwIP socket struct for the driver */
  ret = new_sock;

EXIT:
  return ret;

LWIP_SOCKET_CLEANUP:
  uk_free(d->allocator, new_sock);
  goto EXIT;
}

static int
lwip_glue_bind(struct posix_socket_driver *d,
          void *sock, const struct sockaddr *addr, socklen_t addr_len)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }
  
  /* Bind an LwIP socket */
  ret = lwip_bind(lwip_sock->lwip_fd, addr, addr_len);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_shutdown(struct posix_socket_driver *d,
          void *sock, int how)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }
  
  /* Bind an LwIP socket */
  ret = lwip_shutdown(lwip_sock->lwip_fd, how);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_getpeername(struct posix_socket_driver *d,
          void *sock, struct sockaddr *restrict addr,
          socklen_t *restrict addr_len)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Get the peer name using LwIP */
  ret = lwip_getpeername(lwip_sock->lwip_fd, addr, addr_len);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_getsockname(struct posix_socket_driver *d,
          void *sock, struct sockaddr *restrict addr,
          socklen_t *restrict addr_len)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Get the socket name using LwIP */
  ret = lwip_getsockname(lwip_sock->lwip_fd, addr, addr_len);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_getsockopt(struct posix_socket_driver *d,
          void *sock, int level, int optname, void *restrict optval,
          socklen_t *restrict optlen)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Get the socket options using LwIP */
  ret = lwip_getsockopt(lwip_sock->lwip_fd, level, optname, optval, optlen);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_setsockopt(struct posix_socket_driver *d,
          void *sock, int level, int optname, const void *optval,
          socklen_t optlen)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Set the socket options using LwIP */
  ret = lwip_setsockopt(lwip_sock->lwip_fd, level, optname, optval, optlen);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_connect(struct posix_socket_driver *d,
          void *sock, const struct sockaddr *addr,
          socklen_t addr_len)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Connect to a socket using LwIP */
  ret = lwip_connect(lwip_sock->lwip_fd, addr, addr_len);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_listen(struct posix_socket_driver *d,
          void *sock, int backlog)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }
  
  /* Listen usiing LwIP socket */
  ret = lwip_listen(lwip_sock->lwip_fd, backlog);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static ssize_t
lwip_glue_recv(struct posix_socket_driver *d,
          void *sock, void *buf, size_t len, int flags)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Receive data to a buffer from a socket using LwIP */
  ret = lwip_recv(lwip_sock->lwip_fd, buf, len, flags);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
  return 0;
}

static ssize_t
lwip_glue_recvfrom(struct posix_socket_driver *d,
          void *sock, void *restrict buf, size_t len, int flags,
          struct sockaddr *from, socklen_t *restrict fromlen)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Recieve data to a buffer from a socket using LwIP */
  ret = lwip_recvfrom(lwip_sock->lwip_fd, buf, len, flags, from, fromlen);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static ssize_t
lwip_glue_recvmsg(struct posix_socket_driver *d,
          void *sock, struct msghdr *msg, int flags)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Receive a structured message from a socket using LwIP */
  ret = lwip_recvmsg(lwip_sock->lwip_fd, msg, flags);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static ssize_t
lwip_glue_send(struct posix_socket_driver *d,
          void *sock, const void *buf, size_t len, int flags)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Send data from a buffer to a socket using LwIP */
  ret = lwip_send(lwip_sock->lwip_fd, buf, len, flags);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static ssize_t
lwip_glue_sendmsg(struct posix_socket_driver *d,
          void *sock, const struct msghdr *msg, int flags)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Send a structured message over a socket using LwIP */
  ret = lwip_sendmsg(lwip_sock->lwip_fd, msg, flags);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static ssize_t
lwip_glue_sendto(struct posix_socket_driver *d,
          void *sock, const void *buf, size_t len, int flags,
          const struct sockaddr *dest_addr, socklen_t addrlen)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Send to an address over a socket using LwIP */
  ret = lwip_sendto(lwip_sock->lwip_fd, buf, len, flags, dest_addr, addrlen);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_read(struct posix_socket_driver *d,
          void *sock, void *buf, size_t count)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }
  
  /* Listen usiing LwIP socket */
  ret = lwip_readv(lwip_sock->lwip_fd, buf, count);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_write(struct posix_socket_driver *d,
          void *sock, const void *buf, size_t count)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }
  
  /* Write to an incomming connection using LwIP */
  ret = lwip_writev(lwip_sock->lwip_fd, buf, count);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_close(struct posix_socket_driver *d,
          void *sock)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Close an incoming connection using LwIP */
  ret = lwip_close(lwip_sock->lwip_fd);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static int
lwip_glue_ioctl(struct posix_socket_driver *d,
          void *sock, int request, void *argp)
{
  int ret = 0;
  struct lwip_socket *lwip_sock;

  /* Transform the socket descriptor to the lwip_socket pointer. */
  lwip_sock = (struct lwip_socket *)sock;
  if (lwip_sock->lwip_fd < 0) {
    ret = -1;
    SOCKET_LIB_ERR(d, ret, "failed to identify socket descriptor");
    goto EXIT;
  }

  /* Close an incoming connection using LwIP */
  ret = lwip_ioctl(lwip_sock->lwip_fd, request, argp);
  if (ret < 0)
    ret = -1;

EXIT:
  return ret;
}

static struct posix_socket_ops lwip_socket_ops = {
  /* The initialization function on socket registration. */
  .init        = lwip_lib_socket_init,
  /* POSIX interfaces */
  .create      = lwip_glue_create,
  .accept      = lwip_glue_accept,
  .bind        = lwip_glue_bind,
  .shutdown    = lwip_glue_shutdown,
  .getpeername = lwip_glue_getpeername,
  .getsockname = lwip_glue_getsockname,
  .getsockopt  = lwip_glue_getsockopt,
  .setsockopt  = lwip_glue_setsockopt,
  .connect     = lwip_glue_connect,
  .listen      = lwip_glue_listen,
  .recv        = lwip_glue_recv,
  .recvfrom    = lwip_glue_recvfrom,
  .recvmsg     = lwip_glue_recvmsg,
  .send        = lwip_glue_send,
  .sendmsg     = lwip_glue_sendmsg,
  .sendto      = lwip_glue_sendto,
  /* vfscore ops */
  .read        = lwip_glue_read,
  .write       = lwip_glue_write,
  .close       = lwip_glue_close,
  .ioctl       = lwip_glue_ioctl,
};

POSIX_SOCKET_FAMILY_REGISTER(AF_INET,  &lwip_socket_ops, NULL);

#ifdef CONFIG_LWIP_IPV6
POSIX_SOCKET_FAMILY_REGISTER(AF_INET6, &lwip_socket_ops, NULL);
#endif /* CONFIG_LWIP_IPV6 */