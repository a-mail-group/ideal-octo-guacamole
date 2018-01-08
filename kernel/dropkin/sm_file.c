/*
 *  Copyright (C) 2017-2018 Simon Schmidt
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
#include <linux/fs.h>
#ifdef CONFIG_NET
#include <linux/net.h>
#include <net/sock.h>
#endif

#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
//#include "mls.h"
#include "secureflags.h"

#define IGNORE { return 0; }

int dropkin_file_lock(struct file *file, unsigned int cmd) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_FLOCK, E_ABORT);
	return 0;
}

static void dropkin_x_transfer_proc2socket(struct file *file) {
	/*
	 * If Networking support is disabled, this could possibly cause an error.
	 */
#ifdef CONFIG_NET
	DROPKIN_socket_t *ski;
	DROPKIN_credx_t *pt;
	int err = 0;
	struct socket* sock;
	u32 oflag,nflag;
	
	sock = sock_from_file(file,&err);
	if(!sock)return;
	
	if(unlikely(!sock->sk)) return;
	
	passnosock(sock->sk,);
	ski = sock->sk->sk_security;
	
	passnocred(current->cred,);
	
	pt = current->cred->security;
	
	/*
	 * So, at this point, we only set flags, that the calling process has
	 * set, but without removing any flag, that isn't set for the process.
	 *
	 * XXX: This code contains a potential race condition: If two processes
	 * trigger dropkin_x_transfer_proc2socket simultaneously on a socket,
	 * the update of one of them will be lost. As this, however, is only
	 * intended, for processes to enable the SECF_NO_NETWORKING flag, this
	 * is not critical.
	 *
	 * XXX: This code potentially destroys the cache-line. This (and the
	 * race condition, of course) should have been mitigated using RCU,
	 * but this case is too minor to be considered critical.
	 */
	oflag = ski->secure_flags;
	nflag = oflag | (pt->secure_flags);
	if(oflag!=nflag) ski->secure_flags = nflag;
	
	return;
#endif
}

int dropkin_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_FLOCK|PLEDGE_STDIO, E_ABORT);
	switch(cmd){
	case SIOCSPGRP:
	case FIOSETOWN:
		dropkin_x_transfer_proc2socket(file);
		break;
	}
	return 0;
}

static bool dropkin_x_ioctl_alter_network(struct file *file, unsigned int cmd, unsigned long arg) {
	/*
	 * If Networking support is disabled, this could possibly cause an error.
	 */
#ifdef CONFIG_NET
	int err = 0;
	if(!sock_from_file(file,&err))return false; // No DENY.
	switch(cmd) {
	case SIOCADDRT:
	case SIOCDELRT:
	case SIOCRTMSG:

	case SIOCSIFLINK:
	case SIOCSIFFLAGS:
	case SIOCSIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFBRDADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFMETRIC:
	case SIOCSIFMEM:
	case SIOCSIFMTU:
	case SIOCSIFNAME:
	case SIOCSIFHWADDR:
	case SIOCGIFENCAP:
	case SIOCSIFENCAP:
	case SIOCSIFSLAVE:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCGIFINDEX:
	case SIOCSIFPFLAGS:
	case SIOCDIFADDR:
	case SIOCSIFHWBROADCAST:
	
	case SIOCSIFBR:
	case SIOCSIFTXQLEN:
	case 0x8945: /*Set frame diversion options */
	
	case SIOCETHTOOL:
	case SIOCSMIIREG:
	
	case SIOCWANDEV:
	
	case SIOCOUTQNSD:
	
	// Deprecated range
	case 0x8950 ... 0x8952:
	
	// ARP
	case SIOCDARP:
	case SIOCSARP:
	
	// RARP
	case SIOCDRARP:
	case SIOCSRARP:
	
	// Driver configuration
	case SIOCSIFMAP:
	
	// DLCI configuration
	case SIOCADDDLCI:
	case SIOCDELDLCI:
	case SIOCGIFVLAN:
	case SIOCSIFVLAN:
	
	// bonding calls
	case SIOCBONDENSLAVE:
	case SIOCBONDRELEASE:
	case SIOCBONDSETHWADDR:
	case SIOCBONDCHANGEACTIVE:
	
	/* bridge calls */
	case SIOCBRADDBR:
	case SIOCBRDELBR:
	case SIOCBRADDIF:
	case SIOCBRDELIF:
	
	/* hardware time stamping: parameters in linux/net_tstamp.h */
	case SIOCSHWTSTAMP:
	case 0x89F0 ... 0x89FF: //SIOCDEVPRIVATE
	case 0x89E0 ... 0x89EF: //SIOCPROTOPRIVATE
	
		return true;
	}
#endif
	return false;
}


int dropkin_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	if(
		dropkin_check_secureflags(SECF_NO_CHANGENET) &&
		dropkin_x_ioctl_alter_network(file,cmd,arg)
	) return -EACCES;
	switch(cmd){
	case SIOCSPGRP:
	case FIOSETOWN:
		dropkin_x_transfer_proc2socket(file);
		break;
	}
	return 0;
}
int dropkin_file_receive(struct file *file) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_RECVFD, E_ABORT);
	return 0;
}

int dropkin_sb_statfs(struct dentry *dentry) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	return 0;
}
int dropkin_sb_mount(const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passsecflags(SECF_NO_MOUNT,-EACCES);
	return 0;
}
int dropkin_sb_umount(struct vfsmount *mnt, int flags) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passsecflags(SECF_NO_MOUNT,-EACCES);
	return 0;
}
int dropkin_sb_pivotroot(const struct path *old_path, const struct path *new_path) {
	passnocred(current->cred,0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passsecflags(SECF_NO_MOUNT,-EACCES);
	return 0;
}

