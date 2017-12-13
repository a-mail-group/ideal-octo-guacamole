#pragma once
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
#include <linux/lsm_hooks.h>

// SM_TASK

int  dropkin_cred_alloc_blank(struct cred *cred, gfp_t gfp);
int  dropkin_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
void dropkin_cred_free (struct cred *cred);

int  dropkin_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

int  dropkin_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid);

int  dropkin_task_getsid(struct task_struct *p);
int  dropkin_task_setnice(struct task_struct *p, int nice);
int  dropkin_task_setioprio(struct task_struct *p, int ioprio);
int  dropkin_task_getioprio(struct task_struct *p);

int  dropkin_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);
int  dropkin_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags);
int  dropkin_bprm_check_security(struct linux_binprm *bprm);
void dropkin_bprm_committed_creds(struct linux_binprm *bprm);
int  dropkin_task_fix_setuid(struct cred *new, const struct cred *old,int flags);

// SM_IO

int  dropkin_inode_alloc_security(struct inode *inode);
void dropkin_inode_free_security(struct inode *inode);
int  dropkin_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len);

int  dropkin_inode_permission(struct inode *inode, int mask);
int  dropkin_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode);
int  dropkin_inode_mknod (struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev);

int  dropkin_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
int  dropkin_inode_unlink(struct inode *dir, struct dentry *dentry);
int  dropkin_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name);
int  dropkin_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
int  dropkin_inode_rmdir(struct inode *dir, struct dentry *dentry);
int  dropkin_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);

int  dropkin_inode_setattr(struct dentry *dentry, struct iattr *attr);
int  dropkin_inode_getattr(const struct path *path);
void dropkin_task_to_inode(struct task_struct *p, struct inode *inode);

int dropkin_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc);
int dropkin_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags);
int dropkin_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size);

// SM_SYSV

int  dropkin_shm_alloc_security(struct shmid_kernel *shp);
void dropkin_shm_free_security(struct shmid_kernel *shp);
int  dropkin_shm_associate(struct shmid_kernel *shp, int shmflg);
int  dropkin_shm_shmctl(struct shmid_kernel *shp, int cmd);
int  dropkin_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,int shmflg);

int  dropkin_sem_alloc_security(struct sem_array *sma);
void dropkin_sem_free_security(struct sem_array *sma);
int  dropkin_sem_associate(struct sem_array *sma, int semflg);
int  dropkin_sem_semctl(struct sem_array *sma, int cmd);
int  dropkin_sem_semop(struct sem_array *sma, struct sembuf *sops, unsigned nsops, int alter);


int  dropkin_msg_queue_alloc_security(struct msg_queue *msq);
void dropkin_msg_queue_free_security(struct msg_queue *msq);
int  dropkin_msg_queue_associate(struct msg_queue *msq, int msqflg);
int  dropkin_msg_queue_msgctl(struct msg_queue *msq, int cmd);
int  dropkin_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg);
int  dropkin_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg, struct task_struct *target, long type, int mode);

// SM_SOCKET

#ifdef CONFIG_SECURITY_NETWORK
int dropkin_unix_stream_connect(struct sock *sock, struct sock *other, struct sock *newsk);
int dropkin_unix_may_send(struct socket *sock, struct socket *other);

int dropkin_socket_create(int family, int type, int protocol, int kern);
int dropkin_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern);
int dropkin_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
int dropkin_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
int dropkin_socket_listen(struct socket *sock, int backlog);
int dropkin_socket_accept(struct socket *sock, struct socket *newsock);
int dropkin_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);
int dropkin_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags);
int dropkin_socket_getsockname(struct socket *sock);
int dropkin_socket_getpeername(struct socket *sock);
int dropkin_socket_getsockopt(struct socket *sock, int level, int optname);
int dropkin_socket_setsockopt(struct socket *sock, int level, int optname);
int dropkin_socket_shutdown(struct socket *sock, int how);
int dropkin_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb);
int dropkin_socket_getpeersec_stream(struct socket *sock, char __user *optval, int __user *optlen, unsigned len);
int dropkin_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid);
#endif

// SM_FILE

int dropkin_file_lock(struct file *file, unsigned int cmd);
int dropkin_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
int dropkin_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int dropkin_file_receive(struct file *file);
int dropkin_sb_statfs(struct dentry *dentry);
int dropkin_sb_mount(const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data);
int dropkin_sb_umount(struct vfsmount *mnt, int flags);
int dropkin_sb_pivotroot(const struct path *old_path, const struct path *new_path);

//
