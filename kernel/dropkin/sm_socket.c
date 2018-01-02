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
#include <net/sock.h>

#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"
#include "secureflags.h"

#define IGNORE { return 0; }

#define PASS_UNIX { \
	passnocred(current->cred,0); \
	passpledge(PLEDGE_UNIX, E_ABORT); \
	return 0; \
}

typedef DROPKIN_socket_t *DROPKIN_socket_P;

int dropkin_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk) {
	DROPKIN_socket_P srcf,dstf,newf;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNIX, E_ABORT);
	
	pt = current->cred->security;
	
	srcf = sock->sk_security;
	dstf = other->sk_security;
	newf = newsk->sk_security;
	
	if(!srcf) return 0;
	if(!dstf) return 0;
	
	if(pt->secure_flags&SECF_RESPECT_SKMLS)
		passmls(srcf->owner,dstf->owner,-EACCES);
	
	if(newf) *newf = *dstf;
	
	return 0;
}

int dropkin_unix_may_send(struct socket *sock, struct socket *other) {
	DROPKIN_socket_P srcf,dstf;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNIX, E_ABORT);
	
	pt = current->cred->security;
	
	srcf = sock->sk->sk_security;
	dstf = other->sk->sk_security;
	
	if(!srcf) return 0;
	if(!dstf) return 0;
	
	if(pt->secure_flags&SECF_RESPECT_SKMLS)
		passmls(srcf->owner,dstf->owner,-EACCES);
	
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
	
	switch(family){
	caseof(AF_NETLINK, passsecflags(SECF_NO_CHANGENET,-EACCES) );
	}
	return 0;
}

#define PLEDGE_SOCKETS (PLEDGE_INET|PLEDGE_UNIX|PLEDGE_UDPDNS)

int  dropkin_sk_alloc_security(struct sock *sk, int family, gfp_t priority){
	DROPKIN_socket_t *ski;
	ski = kzalloc(sizeof(DROPKIN_socket_t),GFP_KERNEL);
	if(!ski) return -ENOMEM;
	sk->sk_security = ski;
	return 0;
}
void dropkin_sk_free_security(struct sock *sk){
	DROPKIN_socket_t *ski;
	ski = sk->sk_security;
	if(ski)kfree(ski);
}
void dropkin_sk_clone_security(const struct sock *sk, struct sock *newsk){
	DROPKIN_socket_P ski,newski;
	ski = sk->sk_security;
	newski = newsk->sk_security;
	if(ski&&newski) *newski = *ski;
}

int dropkin_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern) {
	DROPKIN_socket_t *ski;
	DROPKIN_credx_t *pt;
	if(unlikely(!sock->sk)) return 0;
	
	if(kern==1) return 0;
	
	passnosock(sock->sk,0);
	ski = sock->sk->sk_security;
	
	passnocred(current->cred,0);
	
	pt = current->cred->security;
	ski->secure_flags = pt->secure_flags;
	
	return 0;
}

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

int dropkin_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb) {
	DROPKIN_socket_t *ski;
	passnosock(sk,0);
	ski = sk->sk_security;
	
	/* No networking is supported for this socket. */
	if(ski->secure_flags&SECF_NO_NETWORKING) return -EACCES;
	
	return 0;
}
