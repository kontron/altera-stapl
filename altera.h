/*
 * altera.h
 *
 * altera FPGA driver
 *
 * Copyright (C) Altera Corporation 1998-2001
 * Copyright (C) 2010 NetUP Inc.
 * Copyright (C) 2010 Igor M. Liplianin <liplianin@netup.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _ALTERA_H_
#define _ALTERA_H_

#include <stdint.h>

struct altera_config {
	void *dev;
	uint8_t *action;
	int (*jtag_io) (void *dev, int tms, int tdi, int tdo);
};

struct altera_procinfo {
	char			*name;
	uint8_t			attrs;
	struct altera_procinfo	*next;
};

struct altera_varinit {
	char *name;
	uint32_t value;
};

enum {
	ALTERA_SUCCESS = 0,
	ALTERA_STACK_OVERFLOW,
	ALTERA_OUT_OF_MEMORY,
	ALTERA_BOUNDS_ERROR,
	ALTERA_IO_ERROR,
	ALTERA_CRC_ERROR,
	ALTERA_ACTION_NOT_FOUND,
	ALTERA_ILLEGAL_OPCODE,
	ALTERA_UNEXPECTED_END,
	ALTERA_INTERNAL_ERROR,
	ALTERA_MAX_ERROR
};

int altera_check_crc(uint8_t *p, int32_t program_size);
int altera_get_file_info(uint8_t *p, int32_t program_size,
		int *format_version, int *action_count, int *procedure_count);
int altera_get_note(uint8_t *p, int32_t program_size, int32_t *offset,
		char *key, char *value, int length);
int altera_get_act_info(uint8_t *p, int32_t program_size, int index,
		char **name, char **description,
		struct altera_procinfo **proc_list);
int altera_execute(uint8_t *p, int32_t program_size, char *action,
		struct altera_varinit **init_list, int32_t *error_address,
		int *exit_code, int *format_version);

void altera_message(char *message_text);
void altera_export_int(char *key, int32_t value);
void altera_export_bool_array(char *key, uint8_t *data, int32_t count);
int altera_jtag_io(int tms, int tdi, int read_tdo);

uint32_t altera_shrink(uint8_t *in, uint32_t in_length, uint8_t *out, uint32_t out_length, int32_t version);
//extern int altera_init(struct altera_config *config, const struct firmware *fw);

#endif /* _ALTERA_H_ */
