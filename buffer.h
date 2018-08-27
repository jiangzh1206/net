#ifndef _BUFFER_H_
#define _BUFFER_H_

/*******************************************************************************
		-----------------------------------------
 bufer: |		|				|				|
		-----------------------------------------
			   read            write            len
	write-read --> head
*******************************************************************************/


#ifdef __cplusplus
extern "C"{
#endif // __cplusplus

#include <stdbool.h>
#include <stdint.h>

struct buffer_s;

struct buffer_s* ox_buffer_new(size_t data_size);
void ox_buffer_delete(struct buffer_s* self);
void ox_buffer_ajustto_head(struct buffer_s* self);
void ox_buffer_init(struct buffer_s* self);

size_t ox_buffer_getwritepos(struct buffer_s* self);
size_t ox_buffer_getreadpos(struct buffer_s* self);

void ox_buffer_addwritepos(struct buffer_s* self, size_t value);
void ox_buffer_addreadpos(struct buffer_s* self, size_t value);

size_t ox_buffer_getreadvalidcount(struct buffer_s* self);		// 可读的数量(剩余)
size_t ox_buffer_getwritevalidcount(struct buffer_s* self);		// 可写的数量
size_t ox_buffer_getsize(struct buffer_s* self);

char* ox_buffer_getwriteptr(struct buffer_s* self);
char* ox_buffer_getreadptr(struct buffer_s* self);

bool ox_buffer_write(struct buffer_s* self, const char* data, size_t len);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // !_BUFFER_H_



