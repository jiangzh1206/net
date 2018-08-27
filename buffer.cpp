#include "buffer.h"

#include <string.h>
#include <stdlib.h>

struct buffer_s
{
	char*	data;
	size_t	data_len;

	size_t	write_pos;
	size_t	read_pos;
};

struct buffer_s * ox_buffer_new(size_t data_size)
{
	struct buffer_s* ret = (struct buffer_s*)malloc(sizeof(struct buffer_s));
	if (ret == NULL) {
		return NULL;
	}

	char* data = (char*)malloc(sizeof(char) * data_size);
	if (data != NULL) {
		ret->data = data;
		ret->data_len = data_size;
		ret->read_pos = 0;
		ret->write_pos = 0;
	} else {
		ox_buffer_delete(ret);
		ret = NULL;
	}

	return ret;
}

void ox_buffer_delete(struct buffer_s * self)
{
	if (NULL == self) {
		return;
	}
	if (self->data != NULL) {
		free(self->data);
		self->data = NULL;
	}
	free(self);
	self = NULL;
}

void ox_buffer_ajustto_head(struct buffer_s * self)
{
	if (self->read_pos <= 0) {
		return;
	}
	size_t not_read = self->write_pos - self->read_pos;
	if (not_read > 0) {
		memmove(self->data, self->data + not_read, not_read); // 重叠
	}
	// move to head


	self->write_pos = not_read;
	self->read_pos = 0;
}

void ox_buffer_init(struct buffer_s * self)
{
	self->read_pos = 0;
	self->write_pos = 0;
}

size_t ox_buffer_getwritepos(buffer_s * self)
{
	return self->write_pos;
}

size_t ox_buffer_getreadpos(buffer_s * self)
{
	return self->read_pos;
}

void ox_buffer_addwritepos(buffer_s * self, size_t value)
{
	size_t temp = self->write_pos + value;
	if (temp <= self->data_len) {
		self->write_pos = temp;
	}
}

void ox_buffer_addreadpos(buffer_s * self, size_t value)
{
	size_t temp = self->read_pos + value;
	if (temp <= self->data_len) {
		self->read_pos = temp;
	}
}

size_t ox_buffer_getreadvalidcount(buffer_s * self)
{
	return self->write_pos - self->read_pos;
}

size_t ox_buffer_getwritevalidcount(buffer_s * self)
{
	return self->data_len - self->write_pos;
}

size_t ox_buffer_getsize(buffer_s * self)
{
	return self->data_len;
}

char * ox_buffer_getwriteptr(buffer_s * self)
{
	if (self->write_pos < self->data_len) {
		return self->data + self->write_pos;
	} else {
		return NULL;
	}
}

char * ox_buffer_getreadptr(buffer_s * self)
{
	if (self->read_pos < self->data_len) {
		return self->data + self->read_pos;
	} else {
		return NULL;
	}
}

bool ox_buffer_write(buffer_s * self, const char * data, size_t len)
{
	if (!self || !data) {
		return false;
	}

	bool ret = false;

	if (ox_buffer_getwritevalidcount(self) > len) {
		memcpy(self->data, data, len);		// 直接写入
		ox_buffer_addwritepos(self, len);
	} else {
		size_t left_len = self->data_len - ox_buffer_getreadvalidcount(self);	// 可写的数量
		if (left_len > len) {
			ox_buffer_ajustto_head(self);
			ox_buffer_write(self, data, len);
		} else {
			ret = false;
		}
	}

	return ret;
}
