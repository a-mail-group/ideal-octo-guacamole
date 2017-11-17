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
#include <linux/msg.h>

#include "entry_points.h"
#include "structs.h"
#include "prctl_numbers.h"
#include "macros.h"
#include "pledge.h"
#include "mls.h"

#define REQ_CPATH { passnocred(current->cred,0); passpledge(PLEDGE_CPATH, E_ABORT); return 0; }
//#define UNSUPPORTED { passnocred(current->cred,0); passpledge(PLEDGE_UNSUPPORTED, E_ABORT); return 0; }

int  dropkin_shm_alloc_security(struct shmid_kernel *shp){
	DROPKIN_sysv_t *t;
	
	t = kzalloc(sizeof(DROPKIN_sysv_t),GFP_KERNEL);
	if(!t)return -ENOMEM;
	shp->shm_perm.security = t;
	return 0;
}

void dropkin_shm_free_security(struct shmid_kernel *shp){
	DROPKIN_sysv_t *t;
	t = shp->shm_perm.security;
	if(t)kfree(t);
}
int  dropkin_shm_associate(struct shmid_kernel *shp, int shmflg){
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	passnocred(current->cred, 0);
	passnoshm(shp,0);
	t = shp->shm_perm.security;
	pt = current->cred->security;
	if(t->associated)return 0;
	t->subject = pt->subject;
	t->associated = true;
	return 0;
}
int  dropkin_shm_shmctl(struct shmid_kernel *shp, int cmd){
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnoshm(shp,0);
	
	t = shp->shm_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}
int  dropkin_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,int shmflg){
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnoshm(shp,0);
	
	t = shp->shm_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}

int  dropkin_sem_alloc_security(struct sem_array *sma) {
	DROPKIN_sysv_t *t;
	
	t = kzalloc(sizeof(DROPKIN_sysv_t),GFP_KERNEL);
	if(!t)return -ENOMEM;
	sma->sem_perm.security = t;
	return 0;
}
void dropkin_sem_free_security(struct sem_array *sma) {
	DROPKIN_sysv_t *t;
	t = sma->sem_perm.security;
	if(t)kfree(t);
}
int  dropkin_sem_associate(struct sem_array *sma, int semflg) {
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	passnocred(current->cred, 0);
	passnosma(sma,0);
	t = sma->sem_perm.security;
	pt = current->cred->security;
	if(t->associated)return 0;
	t->subject = pt->subject;
	t->associated = true;
	return 0;
}
int  dropkin_sem_semctl(struct sem_array *sma, int cmd) {
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnosma(sma,0);
	
	t = sma->sem_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}
int  dropkin_sem_semop(struct sem_array *sma, struct sembuf *sops, unsigned nsops, int alter) {
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnosma(sma,0);
	
	t = sma->sem_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}

int  dropkin_msg_queue_alloc_security(struct msg_queue *msq) {
	DROPKIN_sysv_t *t;
	
	t = kzalloc(sizeof(DROPKIN_sysv_t),GFP_KERNEL);
	if(!t)return -ENOMEM;
	msq->q_perm.security = t;
	return 0;
}
void dropkin_msg_queue_free_security(struct msg_queue *msq) {
	DROPKIN_sysv_t *t;
	t = msq->q_perm.security;
	if(t)kfree(t);
}
int  dropkin_msg_queue_associate(struct msg_queue *msq, int msqflg) {
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	passnocred(current->cred, 0);
	passnomsq(msq,0);
	t = msq->q_perm.security;
	pt = current->cred->security;
	if(t->associated)return 0;
	t->subject = pt->subject;
	t->associated = true;
	return 0;
}
int  dropkin_msg_queue_msgctl(struct msg_queue *msq, int cmd) {
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnomsq(msq,0);
	
	t = msq->q_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}
int  dropkin_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg) {
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnomsq(msq,0);
	
	t = msq->q_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}
int  dropkin_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg, struct task_struct *target, long type, int mode){
	DROPKIN_sysv_t *t;
	DROPKIN_credx_t *pt;
	
	passnocred(current->cred, 0);
	passpledge(PLEDGE_UNSUPPORTED, E_ABORT);
	passnomsq(msq,0);
	
	t = msq->q_perm.security;
	pt = current->cred->security;
	
	passmls(pt->subject,t->subject, -EPERM);
	
	return 0;
}

