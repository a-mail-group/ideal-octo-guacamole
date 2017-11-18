/*
 *  Copyright (C) 2017 Simon Schmidt
 *
 *	This code is public domain; you can redistribute it and/or modify
 *	it under the terms of the Creative Commons "CC0" license. See LICENSE.CC0
 *	or <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 *	Alternatively, you can use this software under the terms of the
 *	GNU General Public License version 2, as published by the
 *	Free Software Foundation.
 *
**/

/* for malloc() */
#include <linux/slab.h>

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/socket.h>
#include <linux/net.h>

#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"

#define IGNORE { return 0; }

int dropkin_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNIX, E_ABORT);
	return 0;
}
int dropkin_unix_may_send(struct socket *sock, struct socket *other) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNIX, E_ABORT);
	return 0;
}

int dropkin_socket_create(int family, int type, int protocol, int kern) {
	passnocred(current->cred,0);
	
	switch(family){
	case AF_INET6:
	caseof(AF_INET,
		switch(type){
		caseof(SOCK_DGRAM, passpledge(PLEDGE_INET|PLEDGE_UDPDNS, E_ABORT));
		default: passpledge(PLEDGE_INET, E_ABORT);
		});
	caseof(AF_UNIX, passpledge(PLEDGE_UNIX, E_ABORT));
	default: passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	}
	return 0;
}

#define PLEDGE_SOCKETS (PLEDGE_INET|PLEDGE_UNIX|PLEDGE_UDPDNS)

int dropkin_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern) IGNORE

int dropkin_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_listen(struct socket *sock, int backlog) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_accept(struct socket *sock, struct socket *newsock) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size) IGNORE
int dropkin_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags) IGNORE
int dropkin_socket_getsockname(struct socket *sock) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_getpeername(struct socket *sock) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_getsockopt(struct socket *sock, int level, int optname) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_setsockopt(struct socket *sock, int level, int optname) {
	passnocred(current->cred,0);
	
	passpledge(PLEDGE_SOCKETS, E_ABORT);
	
	return 0;
}
int dropkin_socket_shutdown(struct socket *sock, int how) IGNORE
int dropkin_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb) IGNORE
int dropkin_socket_getpeersec_stream(struct socket *sock, char __user *optval, int __user *optlen, unsigned len) IGNORE
int dropkin_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid) IGNORE
