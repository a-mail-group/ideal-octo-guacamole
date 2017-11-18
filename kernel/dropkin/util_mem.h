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
#include <linux/types.h>

/*
 * I don't know, where memcpy is defined, so i implement my own!
 */
static inline void dropkin_mcopy(char* __restrict__ dst, const char* __restrict__ src, size_t n) {
	size_t i;
	for(i=0; i<n ;++i) dst[i] = src[i];
}

static inline bool dropkin_streq(const char* a,const char* b){
	/*
	 * This function has no memory bug:
	 *  If len(a)>len(b), then:
	 *   bool(*a) = true BUT (*a!=*b) = true, so return false.
	 *  If len(a)<len(b), then:
	 *   bool(*a) = false AND (*a==*b) = false, so return false.
	 *  If len(a)==len(b), but !equal(a,b), then:
	 *   (*a!=*b) = true, so return false.
	 *  If len(a)==len(b) and equal(a,b), then:
	 *   bool(*a*) = true at the end of the string; and (*a==*b) = true, so return true.
	 */
	for(;*a;a++,b++) if(*a!=*b) return false;
	return *a==*b;
}

