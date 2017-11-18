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
#include <linux/slab.h>
#include "parsenum.h"
#include "util_mem.h"

u32 dropkin_parse_securly(const void *value, size_t size) {
	size_t i;
	u32 res;
	char c;
	const char* str = (const char*)value;
	res = 0;
	for(i=0;i<size;++i){
		c = str[i];
		if(c<'0'||c>'9')continue;
		res *= 10;
		res += (u32)(c)-'0';
	}
	return res;
}

void *dropkin_serialize_securely(u32 data, size_t *size) {
	char* rbuf;
	char buffer[17];
	size_t i;
	
	i = 16;
	buffer[0] = 0;
	while(data&&i){
		i--;
		buffer[i] = (char)(data%10)+'0';
		data /= 10;
	}
	*size = sizeof(buffer)-i;
	rbuf = kzalloc(*size,GFP_KERNEL);
	if(rbuf)dropkin_mcopy(rbuf,buffer,*size);
	return (void*)rbuf;
}

size_t dropkin_decimal_length(u32 data) {
	size_t n = 0;
	do {
		n++;
		data /= 10;
	} while(data);
	return n;
}

