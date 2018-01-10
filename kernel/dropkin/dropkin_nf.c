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
/*
 * Include:
 *	header <linux/netfilter.h>
 *	macro NF_IP_PRI_SELINUX_FIRST
 */
//#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>

#include <linux/netdevice.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#include <linux/lsm_hooks.h>
#include "macros.h"
#include "structs.h"
#include "secureflags.h"

/*
 * This Netfilter-Hook is essentially the output-version of the Dropkin's LSM-socket_sock_rcv_skb()-hook.
 */
static unsigned int dropkin_nf_sockout(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	DROPKIN_socket_t *ski;
	struct sock *sk;
	
	sk = skb_to_full_sk(skb);
	
	pass0(sk,NF_ACCEPT);
	passnosock(sk,NF_ACCEPT);
	
	ski = sk->sk_security;
	
	/* No networking is supported for this socket. */
	if((ski->secure_flags) & SECF_NO_NETWORKING) return NF_DROP;
	
	return NF_ACCEPT;
}

static struct nf_hook_ops dropkin_nf_hooks[] = {
	/* IPv4 and IPv6 Hook. NFPROTO_IPV4 and NFPROTO_IPV6 by using NFPROTO_INET. */
	{
		.hook     = dropkin_nf_sockout,
		.pf       = NFPROTO_INET,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = 0,
	},
	/* Adding DECnet. Just in case someone uses it. */
	{
		.hook     = dropkin_nf_sockout,
		.pf       = NFPROTO_DECNET,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = 0,
	},
	
	/*
	 * Not Hooked:
	 *	NFPROTO_UNSPEC - because, i think, this is a Wildcard-Dummy.
	 *	NFPROTO_ARP    - A socket wouldn't send ARPs
	 *	NFPROTO_NETDEV - A socket wouldn't send this directly (i think)
	 *	NFPROTO_BRIDGE - A socket wouldn't bridge
	 */
};

static __net_init int dropkin_nf_enter(struct net* net) {
	return nf_register_net_hooks(net,dropkin_nf_hooks,ARRAY_SIZE(dropkin_nf_hooks));
	//return 0;
}

static __net_exit void dropkin_nf_leave(struct net* net) {
	nf_unregister_net_hooks(net,dropkin_nf_hooks,ARRAY_SIZE(dropkin_nf_hooks));
}

static struct pernet_operations dropkin_net_hooks = {
	.init = dropkin_nf_enter,
	.exit = dropkin_nf_leave,
};

static __init int dropkin_nf_init(void) {
	if(!security_module_enable("dropkin")) return 0;
	return register_pernet_subsys(&dropkin_net_hooks);
}

/* Initialization call */
__initcall(dropkin_nf_init);
