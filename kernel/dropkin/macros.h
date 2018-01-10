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

#define passnocred(cred,x) if(!((cred)->security)) return x

#define caseof(x,action) case x: action; break

#define bcast(x) ((x)?true:false)

// IO
#define passnoino(inode,x) if(!(inode)->i_security) return x

// System V IPC
#define passnoshm(shp,x) if(!(shp)->shm_perm.security) return x
#define passnosma(sma,x) if(!(sma)->sem_perm.security) return x
#define passnomsq(msq,x) if(!(msq)->q_perm.security  ) return x

// FILE
#define passnofile(file,x) if(!(file)->f_security) return x

// Sockets

#define passnosock(sock,x) if(!(sock)->sk_security) return x

#define pass0(it,x) if(!(it)) return x

