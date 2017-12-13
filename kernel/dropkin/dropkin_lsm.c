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
#include "entry_points.h"

static struct security_hook_list dropkin_hooks[] __lsm_ro_after_init = {
	/* SM_TASKS */
	LSM_HOOK_INIT(cred_alloc_blank  , dropkin_cred_alloc_blank  ),
	LSM_HOOK_INIT(cred_prepare      , dropkin_cred_prepare      ),
	LSM_HOOK_INIT(cred_free         , dropkin_cred_free         ),
	LSM_HOOK_INIT(task_prctl        , dropkin_task_prctl        ),
	LSM_HOOK_INIT(task_kill         , dropkin_task_kill         ),
	
	LSM_HOOK_INIT(task_getsid       , dropkin_task_getsid       ),
	LSM_HOOK_INIT(task_setnice      , dropkin_task_setnice      ),
	LSM_HOOK_INIT(task_setioprio    , dropkin_task_setioprio    ),
	LSM_HOOK_INIT(task_getioprio    , dropkin_task_getioprio    ),
	
	LSM_HOOK_INIT(file_mprotect     , dropkin_file_mprotect     ),
	LSM_HOOK_INIT(mmap_file         , dropkin_mmap_file         ),
	
	LSM_HOOK_INIT(bprm_check_security , dropkin_bprm_check_security ),
	LSM_HOOK_INIT(bprm_committed_creds, dropkin_bprm_committed_creds),
	LSM_HOOK_INIT(task_fix_setuid     , dropkin_task_fix_setuid),
	
	/* SM_IO */
	LSM_HOOK_INIT(inode_alloc_security, dropkin_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security , dropkin_inode_free_security ),
	LSM_HOOK_INIT(inode_init_security , dropkin_inode_init_security ),
	
	LSM_HOOK_INIT(inode_permission  , dropkin_inode_permission  ),
	LSM_HOOK_INIT(inode_create      , dropkin_inode_create      ),
	LSM_HOOK_INIT(inode_mknod       , dropkin_inode_mknod       ),
	
	LSM_HOOK_INIT(inode_link        , dropkin_inode_link        ),
	LSM_HOOK_INIT(inode_unlink      , dropkin_inode_unlink      ),
	LSM_HOOK_INIT(inode_symlink     , dropkin_inode_symlink     ),
	LSM_HOOK_INIT(inode_mkdir       , dropkin_inode_mkdir       ),
	LSM_HOOK_INIT(inode_rmdir       , dropkin_inode_rmdir       ),
	LSM_HOOK_INIT(inode_rename      , dropkin_inode_rename      ),
	LSM_HOOK_INIT(inode_setattr     , dropkin_inode_setattr     ),
	LSM_HOOK_INIT(inode_getattr     , dropkin_inode_getattr     ),
	LSM_HOOK_INIT(task_to_inode     , dropkin_task_to_inode     ),
	
	LSM_HOOK_INIT(inode_getsecurity , dropkin_inode_getsecurity ),
	LSM_HOOK_INIT(inode_setsecurity , dropkin_inode_setsecurity ),
	LSM_HOOK_INIT(inode_listsecurity, dropkin_inode_listsecurity),
	
	/* SM_SYSV */
	LSM_HOOK_INIT(shm_alloc_security, dropkin_shm_alloc_security),
	LSM_HOOK_INIT(shm_free_security , dropkin_shm_free_security ),
	LSM_HOOK_INIT(shm_associate     , dropkin_shm_associate     ),
	LSM_HOOK_INIT(shm_shmctl        , dropkin_shm_shmctl        ),
	LSM_HOOK_INIT(shm_shmat         , dropkin_shm_shmat         ),
	
	LSM_HOOK_INIT(sem_alloc_security, dropkin_sem_alloc_security),
	LSM_HOOK_INIT(sem_free_security , dropkin_sem_free_security ),
	LSM_HOOK_INIT(sem_associate     , dropkin_sem_associate     ),
	LSM_HOOK_INIT(sem_semctl        , dropkin_sem_semctl        ),
	LSM_HOOK_INIT(sem_semop         , dropkin_sem_semop         ),
	
	LSM_HOOK_INIT(msg_queue_alloc_security, dropkin_msg_queue_alloc_security),
	LSM_HOOK_INIT(msg_queue_free_security , dropkin_msg_queue_free_security ),
	LSM_HOOK_INIT(msg_queue_associate     , dropkin_msg_queue_associate     ),
	LSM_HOOK_INIT(msg_queue_msgctl        , dropkin_msg_queue_msgctl        ),
	LSM_HOOK_INIT(msg_queue_msgsnd        , dropkin_msg_queue_msgsnd        ),
	LSM_HOOK_INIT(msg_queue_msgrcv        , dropkin_msg_queue_msgrcv        ),
	
	/* SM_SOCKET */
#ifdef CONFIG_SECURITY_NETWORK
	LSM_HOOK_INIT(unix_stream_connect     , dropkin_unix_stream_connect     ),
	LSM_HOOK_INIT(unix_may_send           , dropkin_unix_may_send           ),
	
	LSM_HOOK_INIT(socket_create           , dropkin_socket_create           ),
	LSM_HOOK_INIT(socket_post_create      , dropkin_socket_post_create      ),
	LSM_HOOK_INIT(socket_bind             , dropkin_socket_bind             ),
	LSM_HOOK_INIT(socket_connect          , dropkin_socket_connect          ),
	LSM_HOOK_INIT(socket_listen           , dropkin_socket_listen           ),
	LSM_HOOK_INIT(socket_accept           , dropkin_socket_accept           ),
	LSM_HOOK_INIT(socket_sendmsg          , dropkin_socket_sendmsg          ),
	LSM_HOOK_INIT(socket_recvmsg          , dropkin_socket_recvmsg          ),
	LSM_HOOK_INIT(socket_getsockname      , dropkin_socket_getsockname      ),
	LSM_HOOK_INIT(socket_getpeername      , dropkin_socket_getpeername      ),
	
	LSM_HOOK_INIT(socket_getsockopt       , dropkin_socket_getsockopt       ),
	LSM_HOOK_INIT(socket_setsockopt       , dropkin_socket_setsockopt       ),
	LSM_HOOK_INIT(socket_setsockopt       , dropkin_socket_setsockopt       ),
	LSM_HOOK_INIT(socket_shutdown         , dropkin_socket_shutdown         ),
	LSM_HOOK_INIT(socket_sock_rcv_skb     , dropkin_socket_sock_rcv_skb     ),
	LSM_HOOK_INIT(socket_getpeersec_stream, dropkin_socket_getpeersec_stream),
	LSM_HOOK_INIT(socket_getpeersec_dgram , dropkin_socket_getpeersec_dgram ),
#endif
	
	/* SM_FILE */
	LSM_HOOK_INIT(file_lock         , dropkin_file_lock         ),
	LSM_HOOK_INIT(file_fcntl        , dropkin_file_fcntl        ),
	LSM_HOOK_INIT(file_ioctl        , dropkin_file_ioctl        ),
	LSM_HOOK_INIT(file_receive      , dropkin_file_receive      ),
	LSM_HOOK_INIT(sb_statfs         , dropkin_sb_statfs         ),
	LSM_HOOK_INIT(sb_mount          , dropkin_sb_mount          ),
	LSM_HOOK_INIT(sb_umount         , dropkin_sb_umount         ),
	LSM_HOOK_INIT(sb_pivotroot      , dropkin_sb_pivotroot      ),
	
};

static __init int dropkin_init(void) {
	if(!security_module_enable("dropkin")) return 0;
	security_add_hooks(dropkin_hooks, ARRAY_SIZE(dropkin_hooks), "dropkin");
	return 0;
}

/* Dropkin requires to register LSM hooks. */
security_initcall(dropkin_init);
