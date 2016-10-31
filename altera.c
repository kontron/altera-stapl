/*
 * altera.c
 *
 * altera FPGA driver
 *
 * Copyright (C) Altera Corporation 1998-2001
 * Copyright (C) 2010,2011 NetUP Inc.
 * Copyright (C) 2010,2011 Igor M. Liplianin <liplianin@netup.ru>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "altera.h"
#include "altera-jtag.h"

enum altera_fpga_opcode {
	OP_NOP = 0,
	OP_DUP,
	OP_SWP,
	OP_ADD,
	OP_SUB,
	OP_MULT,
	OP_DIV,
	OP_MOD,
	OP_SHL,
	OP_SHR,
	OP_NOT,
	OP_AND,
	OP_OR,
	OP_XOR,
	OP_INV,
	OP_GT,
	OP_LT,
	OP_RET,
	OP_CMPS,
	OP_PINT,
	OP_PRNT,
	OP_DSS,
	OP_DSSC,
	OP_ISS,
	OP_ISSC,
	OP_DPR = 0x1c,
	OP_DPRL,
	OP_DPO,
	OP_DPOL,
	OP_IPR,
	OP_IPRL,
	OP_IPO,
	OP_IPOL,
	OP_PCHR,
	OP_EXIT,
	OP_EQU,
	OP_POPT,
	OP_ABS = 0x2c,
	OP_BCH0,
	OP_PSH0 = 0x2f,
	OP_PSHL = 0x40,
	OP_PSHV,
	OP_JMP,
	OP_CALL,
	OP_NEXT,
	OP_PSTR,
	OP_SINT = 0x47,
	OP_ST,
	OP_ISTP,
	OP_DSTP,
	OP_SWPN,
	OP_DUPN,
	OP_POPV,
	OP_POPE,
	OP_POPA,
	OP_JMPZ,
	OP_DS,
	OP_IS,
	OP_DPRA,
	OP_DPOA,
	OP_IPRA,
	OP_IPOA,
	OP_EXPT,
	OP_PSHE,
	OP_PSHA,
	OP_DYNA,
	OP_EXPV = 0x5c,
	OP_COPY = 0x80,
	OP_REVA,
	OP_DSC,
	OP_ISC,
	OP_WAIT,
	OP_VS,
	OP_CMPA = 0xc0,
	OP_VSC,
};

#define S(x) [x] = #x
const char *op_str[] = {
	S(OP_NOP),
	S(OP_DUP),
	S(OP_SWP),
	S(OP_ADD),
	S(OP_SUB),
	S(OP_MULT),
	S(OP_DIV),
	S(OP_MOD),
	S(OP_SHL),
	S(OP_SHR),
	S(OP_NOT),
	S(OP_AND),
	S(OP_OR),
	S(OP_XOR),
	S(OP_INV),
	S(OP_GT),
	S(OP_LT),
	S(OP_RET),
	S(OP_CMPS),
	S(OP_PINT),
	S(OP_PRNT),
	S(OP_DSS),
	S(OP_DSSC),
	S(OP_ISS),
	S(OP_ISSC),
	S(OP_DPR),
	S(OP_DPRL),
	S(OP_DPO),
	S(OP_DPOL),
	S(OP_IPR),
	S(OP_IPRL),
	S(OP_IPO),
	S(OP_IPOL),
	S(OP_PCHR),
	S(OP_EXIT),
	S(OP_EQU),
	S(OP_POPT),
	S(OP_ABS),
	S(OP_BCH0),
	S(OP_PSH0),
	S(OP_PSHL),
	S(OP_PSHV),
	S(OP_JMP),
	S(OP_CALL),
	S(OP_NEXT),
	S(OP_PSTR),
	S(OP_SINT),
	S(OP_ST),
	S(OP_ISTP),
	S(OP_DSTP),
	S(OP_SWPN),
	S(OP_DUPN),
	S(OP_POPV),
	S(OP_POPE),
	S(OP_POPA),
	S(OP_JMPZ),
	S(OP_DS),
	S(OP_IS),
	S(OP_DPRA),
	S(OP_DPOA),
	S(OP_IPRA),
	S(OP_IPOA),
	S(OP_EXPT),
	S(OP_PSHE),
	S(OP_PSHA),
	S(OP_DYNA),
	S(OP_EXPV),
	S(OP_COPY),
	S(OP_REVA),
	S(OP_DSC),
	S(OP_ISC),
	S(OP_WAIT),
	S(OP_VS),
	S(OP_CMPA),
	S(OP_VSC),
};
#undef S

static inline uint16_t get_unaligned_be16(const uint8_t *p)
{
	return p[0] << 8 | p[1];
}

static inline uint32_t get_unaligned_be32(const uint8_t *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline uint16_t get_unaligned_le16(const uint8_t *p)
{
	return p[0] | p[1] << 8;
}

static inline uint32_t get_unaligned_le32(const uint8_t *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline void put_unaligned_le32(uint32_t val, uint8_t *p)
{
	*p++ = val;
	*p++ = val >> 8;
	*p++ = val >> 16;
	*p++ = val >> 24;
}

size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}


/* This function checks if enough parameters are available on the stack. */
static int altera_check_stack(int stack_ptr, int count, int *status)
{
	if (stack_ptr < count) {
		*status = ALTERA_STACK_OVERFLOW;
		return 0;
	}

	return 1;
}

int altera_execute(uint8_t *p, int32_t program_size, char *action,
		struct altera_varinit *init_list, int32_t *error_address,
		int *exit_code, int *format_version)
{
	char msg_buff[ALTERA_MESSAGE_LENGTH + 1] = {0};
	int32_t stack[ALTERA_STACK_SIZE] = {0};
	struct altera_jtag _js, *js = &_js;
	int status = 0;
	uint32_t first_word = 0;
	uint32_t action_table = 0;
	uint32_t proc_table = 0;
	uint32_t str_table = 0;
	uint32_t sym_table = 0;
	uint32_t data_sect = 0;
	uint32_t code_sect = 0;
	uint32_t debug_sect = 0;
	uint32_t action_count = 0;
	uint32_t proc_count = 0;
	uint32_t sym_count = 0;
	intptr_t *vars = NULL;
	int32_t *var_size = NULL;
	char *attrs = NULL;
	uint8_t *proc_attributes = NULL;
	uint32_t pc;
	uint32_t opcode_address;
	uint32_t args[3];
	uint32_t opcode;
	uint32_t name_id;
	uint8_t charbuf[4];
	int32_t tmp;
	uint32_t variable_id;
	uint8_t *charptr_tmp;
	uint8_t *charptr_tmp2;
	int32_t *ptr_tmp;
	int version = 0;
	int delta = 0;
	int stack_ptr = 0;
	uint32_t arg_count;
	int done = 0;
	int bad_opcode = 0;
	uint32_t count;
	uint32_t idx;
	uint32_t idx2;
	uint32_t i;
	uint32_t uncomp_size;
	uint32_t offset;
	uint32_t value;
	int current_proc = 0;
	int reverse;

	char *name;

	/* Read header information */
	if (program_size > 52) {
		first_word    = get_unaligned_be32(&p[0]);
		version = (first_word & 1);
		*format_version = version + 1;
		delta = version * 8;

		action_table  = get_unaligned_be32(&p[4]);
		proc_table    = get_unaligned_be32(&p[8]);
		str_table  = get_unaligned_be32(&p[4 + delta]);
		sym_table  = get_unaligned_be32(&p[16 + delta]);
		data_sect  = get_unaligned_be32(&p[20 + delta]);
		code_sect  = get_unaligned_be32(&p[24 + delta]);
		debug_sect = get_unaligned_be32(&p[28 + delta]);
		action_count  = get_unaligned_be32(&p[40 + delta]);
		proc_count    = get_unaligned_be32(&p[44 + delta]);
		sym_count  = get_unaligned_be32(&p[48 + (2 * delta)]);
	}

	if ((first_word != 0x4A414D00) && (first_word != 0x4A414D01)) {
		done = 1;
		status = ALTERA_IO_ERROR;
		goto exit_done;
	}

	if (sym_count <= 0)
		goto exit_done;

	vars = calloc(1, sym_count * sizeof(intptr_t));

	if (vars == NULL)
		status = ALTERA_OUT_OF_MEMORY;

	if (status == 0) {
		var_size = calloc(1, sym_count * sizeof(int32_t));

		if (var_size == NULL)
			status = ALTERA_OUT_OF_MEMORY;
	}

	if (status == 0) {
		attrs = calloc(1, sym_count);

		if (attrs == NULL)
			status = ALTERA_OUT_OF_MEMORY;
	}

	if ((status == 0) && (version > 0)) {
		proc_attributes = calloc(1, proc_count);

		if (proc_attributes == NULL)
			status = ALTERA_OUT_OF_MEMORY;
	}

	if (status != 0)
		goto exit_done;

	delta = version * 2;

	for (i = 0; i < sym_count; ++i) {
		offset = (sym_table + ((11 + delta) * i));

		value = get_unaligned_be32(&p[offset + 3 + delta]);

		attrs[i] = p[offset];

		/*
		 * use bit 7 of attribute byte to indicate that
		 * this buffer was dynamically allocated
		 * and should be freed later
		 */
		attrs[i] &= 0x7f;

		var_size[i] = get_unaligned_be32(&p[offset + 7 + delta]);

		/*
		 * Attribute bits:
		 * bit 0: 0 = read-only, 1 = read-write
		 * bit 1: 0 = not compressed, 1 = compressed
		 * bit 2: 0 = not initialized, 1 = initialized
		 * bit 3: 0 = scalar, 1 = array
		 * bit 4: 0 = Boolean, 1 = integer
		 * bit 5: 0 = declared variable,
		 *	1 = compiler created temporary variable
		 */

		if ((attrs[i] & 0x0c) == 0x04)
			/* initialized scalar variable */
			vars[i] = value;
		else if ((attrs[i] & 0x1e) == 0x0e) {
			/* initialized compressed Boolean array */
			uncomp_size = get_unaligned_le32(&p[data_sect + value]);

			/* allocate a buffer for the uncompressed data */
			vars[i] = (intptr_t)calloc(1, uncomp_size);
			if (vars[i] == 0)
				status = ALTERA_OUT_OF_MEMORY;
			else {
				/* set flag so buffer will be freed later */
				attrs[i] |= 0x80;

				/* uncompress the data */
				if (altera_shrink(&p[data_sect + value],
						var_size[i],
						(uint8_t *)vars[i],
						uncomp_size,
						version) != uncomp_size)
					/* decompression failed */
					status = ALTERA_IO_ERROR;
				else
					var_size[i] = uncomp_size * 8;

			}
		} else if ((attrs[i] & 0x1e) == 0x0c) {
			/* initialized Boolean array */
			vars[i] = value + data_sect + (intptr_t)p;
		} else if ((attrs[i] & 0x1c) == 0x1c) {
			/* initialized integer array */
			vars[i] = value + data_sect;
		} else if ((attrs[i] & 0x0c) == 0x08) {
			/* uninitialized array */

			/* flag attrs so that memory is freed */
			attrs[i] |= 0x80;

			if (var_size[i] > 0) {
				uint32_t size;

				if (attrs[i] & 0x10)
					/* integer array */
					size = (var_size[i] * sizeof(int32_t));
				else
					/* Boolean array */
					size = ((var_size[i] + 7) / 8);

				vars[i] = (intptr_t)calloc(1, size);

				if (vars[i] == 0) {
					status = ALTERA_OUT_OF_MEMORY;
				}
			} else
				vars[i] = 0;

		} else
			vars[i] = 0;

		if (trace) {
			name_id = (version == 0)
						? get_unaligned_be16(&p[offset + 1])
						: get_unaligned_be32(&p[offset + 1]);
			name = &p[str_table + name_id];
			fprintf(stderr, "Variable #%d (%s) attrs=%x value=%08lx var_size=%d orig_value=%08x\n",
					i, name, attrs[i], vars[i], var_size[i], value);
		}
	}

	if (status != 0)
		goto exit_done;

	/* Initialize variables listed in init_list */
	if (init_list) {
		struct altera_varinit *iter = init_list;
		do {
			for (i = 0; i < sym_count; ++i) {
				offset = (sym_table + ((11 + delta) * i));
				name_id = (version == 0)
							? get_unaligned_be16(&p[offset + 1])
							: get_unaligned_be32(&p[offset + 1]);
				name = &p[str_table + name_id];

				if (strncasecmp(iter->name, name, strlen(name)) == 0)
					vars[i] = iter->value;
			}
		} while ((iter = iter->next));
	}

exit_done:
	if (status != 0)
		done = 1;

	altera_jinit(js);

	pc = code_sect;
	msg_buff[0] = '\0';

	/*
	 * For JBC version 2, we will execute the procedures corresponding to
	 * the selected ACTION
	 */
	if (version > 0) {
		if (action == NULL) {
			status = ALTERA_ACTION_NOT_FOUND;
			done = 1;
		} else {
			int action_found = 0;
			for (i = 0; (i < action_count) && !action_found; ++i) {
				name_id = get_unaligned_be32(&p[action_table +
								(12 * i)]);

				name = &p[str_table + name_id];

				if (strncasecmp(action, name, strlen(name)) == 0) {
					action_found = 1;
					current_proc =
						get_unaligned_be32(&p[action_table +
								(12 * i) + 8]);
				}
			}

			if (!action_found) {
				status = ALTERA_ACTION_NOT_FOUND;
				done = 1;
			}
		}

		if (status == 0) {
			int first_time = 1;
			i = current_proc;
			while ((i != 0) || first_time) {
				first_time = 0;
				/* check procedure attribute byte */
				proc_attributes[i] = (p[proc_table + (13 * i) + 8] & 0x03);

				/*
				 * BIT0 - OPTIONAL
				 * BIT1 - RECOMMENDED
				 * BIT6 - FORCED OFF
				 * BIT7 - FORCED ON
				 */
				if (init_list) {
					struct altera_varinit *iter = init_list;
					name_id = get_unaligned_be32(&p[proc_table + (13 * i)]);
					name = &p[str_table + name_id];

					do {
						if (strncasecmp(iter->name, name, strlen(name)) == 0)
							proc_attributes[i] |= iter->value ? 0x80 : 0x40;
					} while ((iter = iter->next));
				}

				i = get_unaligned_be32(&p[proc_table + (13 * i) + 4]);
			}

			/*
			 * Set current_proc to the first procedure
			 * to be executed
			 */
			i = current_proc;
			while ((i != 0) && ((proc_attributes[i] == 1)
					|| ((proc_attributes[i] & 0xc0) == 0x40))) {
				i = get_unaligned_be32(&p[proc_table + (13 * i) + 4]);
			}

			if ((i != 0) || ((i == 0) && (current_proc == 0)
						&& ((proc_attributes[0] != 1)
						&& ((proc_attributes[0] & 0xc0) != 0x40)))) {
				current_proc = i;
				pc = code_sect + get_unaligned_be32(&p[proc_table + (13 * i) + 9]);
				if ((pc < code_sect) || (pc >= debug_sect))
					status = ALTERA_BOUNDS_ERROR;
			} else
				/* there are no procedures to execute! */
				done = 1;

		}
	}

	msg_buff[0] = '\0';

	while (!done) {
		opcode = (p[pc] & 0xff);
		opcode_address = pc;
		++pc;

		if (trace)
			fprintf(stderr, "%06x: %-7s ", pc, op_str[opcode]);

		arg_count = (opcode >> 6) & 3;
		for (i = 0; i < arg_count; ++i) {
			args[i] = get_unaligned_be32(&p[pc]);
			pc += 4;
		}

		if (trace)
			for (i = 0; i < arg_count; i++)
				fprintf(stderr, "arg%d=%08x ", i, (uint32_t)args[i]);

		switch (opcode) {
		case OP_NOP:
			break;
		case OP_DUP:
			if (altera_check_stack(stack_ptr, 1, &status)) {
				stack[stack_ptr] = stack[stack_ptr - 1];
				++stack_ptr;
			}
			break;
		case OP_SWP:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				tmp = stack[stack_ptr - 2];
				stack[stack_ptr - 2] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}
			break;
		case OP_ADD:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] += stack[stack_ptr];
			}
			break;
		case OP_SUB:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] -= stack[stack_ptr];
			}
			break;
		case OP_MULT:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] *= stack[stack_ptr];
			}
			break;
		case OP_DIV:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] /= stack[stack_ptr];
			}
			break;
		case OP_MOD:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] %= stack[stack_ptr];
			}
			break;
		case OP_SHL:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] <<= stack[stack_ptr];
			}
			break;
		case OP_SHR:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] >>= stack[stack_ptr];
			}
			break;
		case OP_NOT:
			if (altera_check_stack(stack_ptr, 1, &status))
				stack[stack_ptr - 1] ^= -1;

			break;
		case OP_AND:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] &= stack[stack_ptr];
			}
			break;
		case OP_OR:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] |= stack[stack_ptr];
			}
			break;
		case OP_XOR:
			if (altera_check_stack(stack_ptr, 2, &status)) {
				--stack_ptr;
				stack[stack_ptr - 1] ^= stack[stack_ptr];
			}
			break;
		case OP_INV:
			if (!altera_check_stack(stack_ptr, 1, &status))
				break;
			stack[stack_ptr - 1] = stack[stack_ptr - 1] ? 0 : 1;
			break;
		case OP_GT:
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			--stack_ptr;
			stack[stack_ptr - 1] =
				(stack[stack_ptr - 1] > stack[stack_ptr]) ?
									1 : 0;

			break;
		case OP_LT:
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			--stack_ptr;
			stack[stack_ptr - 1] =
				(stack[stack_ptr - 1] < stack[stack_ptr]) ?
									1 : 0;

			break;
		case OP_RET:
			if ((version > 0) && (stack_ptr == 0)) {
				/*
				 * We completed one of the main procedures
				 * of an ACTION.
				 * Find the next procedure
				 * to be executed and jump to it.
				 * If there are no more procedures, then EXIT.
				 */
				i = get_unaligned_be32(&p[proc_table +
						(13 * current_proc) + 4]);
				while ((i != 0) &&
					((proc_attributes[i] == 1) ||
					((proc_attributes[i] & 0xc0) == 0x40)))
					i = get_unaligned_be32(&p[proc_table +
								(13 * i) + 4]);

				if (i == 0) {
					/* no procedures to execute! */
					done = 1;
					*exit_code = 0;	/* success */
				} else {
					if (trace) {
						name_id = get_unaligned_be32(&p[proc_table + (13 * i)]);
						name = &p[str_table + name_id];
						fprintf(stderr, "PROC#%d[%s] ", i, name);
					}
					current_proc = i;
					pc = code_sect + get_unaligned_be32(
								&p[proc_table +
								(13 * i) + 9]);
					if ((pc < code_sect) ||
					    (pc >= debug_sect))
						status = ALTERA_BOUNDS_ERROR;
				}

			} else
				if (altera_check_stack(stack_ptr, 1, &status)) {
					pc = stack[--stack_ptr] + code_sect;
					if ((pc <= code_sect) ||
					    (pc >= debug_sect))
						status = ALTERA_BOUNDS_ERROR;

				}

			break;
		case OP_CMPS:
			/*
			 * Array short compare
			 * ...stack 0 is source 1 value
			 * ...stack 1 is source 2 value
			 * ...stack 2 is mask value
			 * ...stack 3 is count
			 */
			if (altera_check_stack(stack_ptr, 4, &status)) {
				int32_t a = stack[--stack_ptr];
				int32_t b = stack[--stack_ptr];
				tmp = stack[--stack_ptr];
				count = stack[stack_ptr - 1];

				if ((count < 1) || (count > 32))
					status = ALTERA_BOUNDS_ERROR;
				else {
					tmp &= ((-1) >> (32 - count));

					stack[stack_ptr - 1] =
					((a & tmp) == (b & tmp))
								? 1 : 0;
				}
			}
			break;
		case OP_PINT:
			/*
			 * PRINT add integer
			 * ...stack 0 is integer value
			 */
			if (!altera_check_stack(stack_ptr, 1, &status))
				break;
			sprintf(&msg_buff[strlen(msg_buff)],
					"%d", stack[--stack_ptr]);
			break;
		case OP_PRNT:
			/* PRINT finish */
			altera_message(msg_buff);
			msg_buff[0] = '\0';
			break;
		case OP_DSS:
			/*
			 * DRSCAN short
			 * ...stack 0 is scan data
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			tmp = stack[--stack_ptr];
			count = stack[--stack_ptr];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_drscan(js, count, charbuf, 0);
			break;
		case OP_DSSC:
			/*
			 * DRSCAN short with capture
			 * ...stack 0 is scan data
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			tmp = stack[--stack_ptr];
			count = stack[stack_ptr - 1];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_swap_dr(js, count, charbuf,
							0, charbuf, 0);
			stack[stack_ptr - 1] = get_unaligned_le32(&charbuf[0]);
			break;
		case OP_ISS:
			/*
			 * IRSCAN short
			 * ...stack 0 is scan data
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			tmp = stack[--stack_ptr];
			count = stack[--stack_ptr];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_irscan(js, count, charbuf, 0);
			break;
		case OP_ISSC:
			/*
			 * IRSCAN short with capture
			 * ...stack 0 is scan data
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			tmp = stack[--stack_ptr];
			count = stack[stack_ptr - 1];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_swap_ir(js, count, charbuf,
							0, charbuf, 0);
			stack[stack_ptr - 1] = get_unaligned_le32(&charbuf[0]);
			break;
		case OP_DPR:
			if (!altera_check_stack(stack_ptr, 1, &status))
				break;
			count = stack[--stack_ptr];
			status = altera_set_dr_pre(js, count, 0, NULL);
			break;
		case OP_DPRL:
			/*
			 * DRPRE with literal data
			 * ...stack 0 is count
			 * ...stack 1 is literal data
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			count = stack[--stack_ptr];
			tmp = stack[--stack_ptr];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_set_dr_pre(js, count, 0,
						charbuf);
			break;
		case OP_DPO:
			/*
			 * DRPOST
			 * ...stack 0 is count
			 */
			if (altera_check_stack(stack_ptr, 1, &status)) {
				count = stack[--stack_ptr];
				status = altera_set_dr_post(js, count,
								0, NULL);
			}
			break;
		case OP_DPOL:
			/*
			 * DRPOST with literal data
			 * ...stack 0 is count
			 * ...stack 1 is literal data
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			count = stack[--stack_ptr];
			tmp = stack[--stack_ptr];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_set_dr_post(js, count, 0,
							charbuf);
			break;
		case OP_IPR:
			if (altera_check_stack(stack_ptr, 1, &status)) {
				count = stack[--stack_ptr];
				status = altera_set_ir_pre(js, count,
								0, NULL);
			}
			break;
		case OP_IPRL:
			/*
			 * IRPRE with literal data
			 * ...stack 0 is count
			 * ...stack 1 is literal data
			 */
			if (altera_check_stack(stack_ptr, 2, &status)) {
				count = stack[--stack_ptr];
				tmp = stack[--stack_ptr];
				put_unaligned_le32(tmp, &charbuf[0]);
				status = altera_set_ir_pre(js, count,
							0, charbuf);
			}
			break;
		case OP_IPO:
			/*
			 * IRPOST
			 * ...stack 0 is count
			 */
			if (altera_check_stack(stack_ptr, 1, &status)) {
				count = stack[--stack_ptr];
				status = altera_set_ir_post(js, count,
							0, NULL);
			}
			break;
		case OP_IPOL:
			/*
			 * IRPOST with literal data
			 * ...stack 0 is count
			 * ...stack 1 is literal data
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			count = stack[--stack_ptr];
			tmp = stack[--stack_ptr];
			put_unaligned_le32(tmp, &charbuf[0]);
			status = altera_set_ir_post(js, count, 0,
							charbuf);
			break;
		case OP_PCHR:
			if (altera_check_stack(stack_ptr, 1, &status)) {
				uint8_t ch;
				count = strlen(msg_buff);
				ch = (char) stack[--stack_ptr];
				if ((ch < 1) || (ch > 127)) {
					/*
					 * character code out of range
					 * instead of flagging an error,
					 * force the value to 127
					 */
					ch = 127;
				}
				msg_buff[count] = ch;
				msg_buff[count + 1] = '\0';
			}
			break;
		case OP_EXIT:
			if (altera_check_stack(stack_ptr, 1, &status))
				*exit_code = stack[--stack_ptr];

			done = 1;
			break;
		case OP_EQU:
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			--stack_ptr;
			stack[stack_ptr - 1] =
				(stack[stack_ptr - 1] == stack[stack_ptr]) ?
									1 : 0;
			break;
		case OP_POPT:
			if (altera_check_stack(stack_ptr, 1, &status))
				--stack_ptr;

			break;
		case OP_ABS:
			if (!altera_check_stack(stack_ptr, 1, &status))
				break;
			if (stack[stack_ptr - 1] < 0)
				stack[stack_ptr - 1] = 0 - stack[stack_ptr - 1];

			break;
		case OP_BCH0:
			/*
			 * Batch operation 0
			 * SWP
			 * SWPN 7
			 * SWP
			 * SWPN 6
			 * DUPN 8
			 * SWPN 2
			 * SWP
			 * DUPN 6
			 * DUPN 6
			 */

			/* SWP  */
			if (altera_check_stack(stack_ptr, 2, &status)) {
				tmp = stack[stack_ptr - 2];
				stack[stack_ptr - 2] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}

			/* SWPN 7 */
			idx = 7 + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				tmp = stack[stack_ptr - idx];
				stack[stack_ptr - idx] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}

			/* SWP  */
			if (altera_check_stack(stack_ptr, 2, &status)) {
				tmp = stack[stack_ptr - 2];
				stack[stack_ptr - 2] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}

			/* SWPN 6 */
			idx = 6 + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				tmp = stack[stack_ptr - idx];
				stack[stack_ptr - idx] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}

			/* DUPN 8 */
			idx = 8 + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				stack[stack_ptr] = stack[stack_ptr - idx];
				++stack_ptr;
			}

			/* SWPN 2 */
			idx = 2 + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				tmp = stack[stack_ptr - idx];
				stack[stack_ptr - idx] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}

			/* SWP  */
			if (altera_check_stack(stack_ptr, 2, &status)) {
				tmp = stack[stack_ptr - 2];
				stack[stack_ptr - 2] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}

			/* DUPN 6 */
			idx = 6 + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				stack[stack_ptr] = stack[stack_ptr - idx];
				++stack_ptr;
			}

			/* DUPN 6 */
			idx = 6 + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				stack[stack_ptr] = stack[stack_ptr - idx];
				++stack_ptr;
			}
			break;
		case OP_PSH0:
			stack[stack_ptr++] = 0;
			break;
		case OP_PSHL:
			stack[stack_ptr++] = (int32_t) args[0];
			break;
		case OP_PSHV:
			stack[stack_ptr++] = vars[args[0]];
			break;
		case OP_JMP:
			pc = args[0] + code_sect;
			if ((pc < code_sect) || (pc >= debug_sect))
				status = ALTERA_BOUNDS_ERROR;
			break;
		case OP_CALL:
			stack[stack_ptr++] = pc;
			pc = args[0] + code_sect;
			if ((pc < code_sect) || (pc >= debug_sect))
				status = ALTERA_BOUNDS_ERROR;
			break;
		case OP_NEXT:
			/*
			 * Process FOR / NEXT loop
			 * ...argument 0 is variable ID
			 * ...stack 0 is step value
			 * ...stack 1 is end value
			 * ...stack 2 is top address
			 */
			if (altera_check_stack(stack_ptr, 3, &status)) {
				int32_t step = stack[stack_ptr - 1];
				int32_t end = stack[stack_ptr - 2];
				int32_t top = stack[stack_ptr - 3];
				int32_t iterator = vars[args[0]];
				int break_out = 0;

				if (step < 0) {
					if (iterator <= end)
						break_out = 1;
				} else if (iterator >= end)
					break_out = 1;

				if (break_out) {
					stack_ptr -= 3;
				} else {
					vars[args[0]] = iterator + step;
					pc = top + code_sect;
					if ((pc < code_sect) ||
					    (pc >= debug_sect))
						status = ALTERA_BOUNDS_ERROR;
				}
			}
			break;
		case OP_PSTR:
			/*
			 * PRINT add string
			 * ...argument 0 is string ID
			 */
			count = strlen(msg_buff);
			strlcpy(&msg_buff[count],
				&p[str_table + args[0]],
				ALTERA_MESSAGE_LENGTH - count);
			break;
		case OP_SINT:
			/*
			 * STATE intermediate state
			 * ...argument 0 is state code
			 */
			status = altera_goto_jstate(js, args[0]);
			break;
		case OP_ST:
			/*
			 * STATE final state
			 * ...argument 0 is state code
			 */
			status = altera_goto_jstate(js, args[0]);
			break;
		case OP_ISTP:
			/*
			 * IRSTOP state
			 * ...argument 0 is state code
			 */
			status = altera_set_irstop(js, args[0]);
			break;
		case OP_DSTP:
			/*
			 * DRSTOP state
			 * ...argument 0 is state code
			 */
			status = altera_set_drstop(js, args[0]);
			break;

		case OP_SWPN:
			/*
			 * Exchange top with Nth stack value
			 * ...argument 0 is 0-based stack entry
			 * to swap with top element
			 */
			idx = (args[0]) + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				tmp = stack[stack_ptr - idx];
				stack[stack_ptr - idx] = stack[stack_ptr - 1];
				stack[stack_ptr - 1] = tmp;
			}
			break;
		case OP_DUPN:
			/*
			 * Duplicate Nth stack value
			 * ...argument 0 is 0-based stack entry to duplicate
			 */
			idx = (args[0]) + 1;
			if (altera_check_stack(stack_ptr, idx, &status)) {
				stack[stack_ptr] = stack[stack_ptr - idx];
				++stack_ptr;
			}
			break;
		case OP_POPV:
			/*
			 * Pop stack into scalar variable
			 * ...argument 0 is variable ID
			 * ...stack 0 is value
			 */
			if (altera_check_stack(stack_ptr, 1, &status))
				vars[args[0]] = stack[--stack_ptr];

			break;
		case OP_POPE:
			/*
			 * Pop stack into integer array element
			 * ...argument 0 is variable ID
			 * ...stack 0 is array index
			 * ...stack 1 is value
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			variable_id = args[0];

			/*
			 * If variable is read-only,
			 * convert to writable array
			 */
			if ((version > 0) &&
				((attrs[variable_id] & 0x9c) == 0x1c)) {
				/* Allocate a writable buffer for this array */
				count = var_size[variable_id];
				tmp = vars[variable_id];
				ptr_tmp = calloc(1, count * sizeof(int32_t));
				vars[variable_id] = (intptr_t)ptr_tmp;

				if (vars[variable_id] == 0) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				/* copy previous contents into buffer */
				for (i = 0; i < count; ++i) {
					ptr_tmp[i] =
						get_unaligned_be32(&p[tmp]);
					tmp += sizeof(int32_t);
				}

				/*
				 * set bit 7 - buffer was
				 * dynamically allocated
				 */
				attrs[variable_id] |= 0x80;

				/* clear bit 2 - variable is writable */
				attrs[variable_id] &= ~0x04;
				attrs[variable_id] |= 0x01;

			}

			/* check that variable is a writable integer array */
			if ((attrs[variable_id] & 0x1c) != 0x18)
				status = ALTERA_BOUNDS_ERROR;
			else {
				ptr_tmp = (int32_t *)vars[variable_id];

				/* pop the array index */
				idx = stack[--stack_ptr];

				/* pop the value and store it into the array */
				ptr_tmp[idx] = stack[--stack_ptr];
			}

			break;
		case OP_POPA:
			/*
			 * Pop stack into Boolean array
			 * ...argument 0 is variable ID
			 * ...stack 0 is count
			 * ...stack 1 is array index
			 * ...stack 2 is value
			 */
			if (!altera_check_stack(stack_ptr, 3, &status))
				break;
			variable_id = args[0];

			/*
			 * If variable is read-only,
			 * convert to writable array
			 */
			if ((version > 0) &&
				((attrs[variable_id] & 0x9c) == 0x0c)) {
				/* Allocate a writable buffer for this array */
				tmp = (var_size[variable_id] + 7) >> 3;
				charptr_tmp2 = (uint8_t *)vars[variable_id];
				charptr_tmp = calloc(1, tmp);
				vars[variable_id] = (intptr_t)charptr_tmp;

				if (vars[variable_id] == 0) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				/* copy previous contents into buffer */
				memcpy(charptr_tmp, charptr_tmp2, tmp);

				/*
				 * set bit 7 - buffer was
				 * dynamically allocated
				 */
				attrs[variable_id] |= 0x80;

				/* clear bit 2 - variable is writable */
				attrs[variable_id] &= ~0x04;
				attrs[variable_id] |= 0x01;

			}

			/*
			 * check that variable is
			 * a writable Boolean array
			 */
			if ((attrs[variable_id] & 0x1c) != 0x08) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			charptr_tmp = (uint8_t *)vars[variable_id];

			/* pop the count (number of bits to copy) */
			count = stack[--stack_ptr];

			/* pop the array index */
			idx = stack[--stack_ptr];

			reverse = 0;

			if (version > 0) {
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 */

				if (idx > count) {
					reverse = 1;
					tmp = count;
					count = 1 + idx -
								count;
					idx = tmp;

					/* reverse POPA is not supported */
					status = ALTERA_BOUNDS_ERROR;
					break;
				} else
					count = 1 + count -
								idx;

			}

			/* pop the data */
			tmp = stack[--stack_ptr];

			if (count < 1) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			for (i = 0; i < count; ++i) {
				if (tmp & (1 << (int32_t) i))
					charptr_tmp[idx >> 3] |=
						(1 << (idx & 7));
				else
					charptr_tmp[idx >> 3] &=
						~(1 << (idx & 7));

				++idx;
			}

			break;
		case OP_JMPZ:
			/*
			 * Pop stack and branch if zero
			 * ...argument 0 is address
			 * ...stack 0 is condition value
			 */
			if (altera_check_stack(stack_ptr, 1, &status)) {
				if (stack[--stack_ptr] == 0) {
					pc = args[0] + code_sect;
					if ((pc < code_sect) ||
					    (pc >= debug_sect))
						status = ALTERA_BOUNDS_ERROR;
				}
			}
			break;
		case OP_DS:
		case OP_IS:
			/*
			 * DRSCAN
			 * IRSCAN
			 * ...argument 0 is scan data variable ID
			 * ...stack 0 is array index
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			idx = stack[--stack_ptr];
			count = stack[--stack_ptr];
			reverse = 0;
			if (version > 0) {
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 * stack 2 = count
				 */
				tmp = count;
				count = stack[--stack_ptr];

				if (idx > tmp) {
					reverse = 1;
					idx = tmp;
				}
			}

			charptr_tmp = (uint8_t *)vars[args[0]];

			if (reverse) {
				/*
				 * allocate a buffer
				 * and reverse the data order
				 */
				charptr_tmp2 = charptr_tmp;
				charptr_tmp = calloc(1, (count >> 3) + 1);
				if (charptr_tmp == NULL) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				tmp = idx + count - 1;
				idx2 = 0;
				while (idx2 < count) {
					if (charptr_tmp2[tmp >> 3] &
							(1 << (tmp & 7)))
						charptr_tmp[idx2 >> 3] |=
							(1 << (idx2 & 7));
					else
						charptr_tmp[idx2 >> 3] &=
							~(1 << (idx2 & 7));

					--tmp;
					++idx2;
				}
			}

			if (opcode == 0x51) /* DS */
				status = altera_drscan(js, count,
						charptr_tmp, idx);
			else /* IS */
				status = altera_irscan(js, count,
						charptr_tmp, idx);

			if (reverse)
				free(charptr_tmp);

			break;
		case OP_DPRA:
			/*
			 * DRPRE with array data
			 * ...argument 0 is variable ID
			 * ...stack 0 is array index
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			idx = stack[--stack_ptr];
			count = stack[--stack_ptr];

			if (version > 0)
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 */
				count = 1 + count - idx;

			charptr_tmp = (uint8_t *)vars[args[0]];
			status = altera_set_dr_pre(js, count, idx,
							charptr_tmp);
			break;
		case OP_DPOA:
			/*
			 * DRPOST with array data
			 * ...argument 0 is variable ID
			 * ...stack 0 is array index
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			idx = stack[--stack_ptr];
			count = stack[--stack_ptr];

			if (version > 0)
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 */
				count = 1 + count - idx;

			charptr_tmp = (uint8_t *)vars[args[0]];
			status = altera_set_dr_post(js, count, idx,
							charptr_tmp);
			break;
		case OP_IPRA:
			/*
			 * IRPRE with array data
			 * ...argument 0 is variable ID
			 * ...stack 0 is array index
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			idx = stack[--stack_ptr];
			count = stack[--stack_ptr];

			if (version > 0)
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 */
				count = 1 + count - idx;

			charptr_tmp = (uint8_t *)vars[args[0]];
			status = altera_set_ir_pre(js, count, idx,
							charptr_tmp);

			break;
		case OP_IPOA:
			/*
			 * IRPOST with array data
			 * ...argument 0 is variable ID
			 * ...stack 0 is array index
			 * ...stack 1 is count
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			idx = stack[--stack_ptr];
			count = stack[--stack_ptr];

			if (version > 0)
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 */
				count = 1 + count - idx;

			charptr_tmp = (uint8_t *)vars[args[0]];
			status = altera_set_ir_post(js, count, idx,
							charptr_tmp);

			break;
		case OP_EXPT:
			/*
			 * EXPORT
			 * ...argument 0 is string ID
			 * ...stack 0 is integer expression
			 */
			if (altera_check_stack(stack_ptr, 1, &status)) {
				name = &p[str_table + args[0]];
				tmp = stack[--stack_ptr];
				altera_export_int(name, tmp);
			}
			break;
		case OP_PSHE:
			/*
			 * Push integer array element
			 * ...argument 0 is variable ID
			 * ...stack 0 is array index
			 */
			if (!altera_check_stack(stack_ptr, 1, &status))
				break;
			variable_id = args[0];
			idx = stack[stack_ptr - 1];

			/* check variable type */
			if ((attrs[variable_id] & 0x1f) == 0x19) {
				/* writable integer array */
				ptr_tmp = (int32_t *)vars[variable_id];
				stack[stack_ptr - 1] = ptr_tmp[idx];
			} else if ((attrs[variable_id] & 0x1f) == 0x1c) {
				/* read-only integer array */
				tmp = vars[variable_id] +
						(idx * sizeof(int32_t));
				stack[stack_ptr - 1] =
					get_unaligned_be32(&p[tmp]);
			} else
				status = ALTERA_BOUNDS_ERROR;

			break;
		case OP_PSHA:
			/*
			 * Push Boolean array
			 * ...argument 0 is variable ID
			 * ...stack 0 is count
			 * ...stack 1 is array index
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			variable_id = args[0];

			/* check that variable is a Boolean array */
			if ((attrs[variable_id] & 0x18) != 0x08) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			charptr_tmp = (uint8_t *)vars[variable_id];

			/* pop the count (number of bits to copy) */
			count = stack[--stack_ptr];

			/* pop the array index */
			idx = stack[stack_ptr - 1];

			if (version > 0)
				/*
				 * stack 0 = array right index
				 * stack 1 = array left index
				 */
				count = 1 + count - idx;

			if ((count < 1) || (count > 32)) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			tmp = 0;

			for (i = 0; i < count; ++i)
				if (charptr_tmp[(i + idx) >> 3] &
						(1 << ((i + idx) & 7)))
					tmp |= (1 << i);

			stack[stack_ptr - 1] = tmp;

			break;
		case OP_DYNA:
			/*
			 * Dynamically change size of array
			 * ...argument 0 is variable ID
			 * ...stack 0 is new size
			 */
			if (!altera_check_stack(stack_ptr, 1, &status))
				break;
			variable_id = args[0];
			tmp = stack[--stack_ptr];

			if (tmp > var_size[variable_id]) {
				var_size[variable_id] = tmp;

				if (attrs[variable_id] & 0x10)
					/* allocate integer array */
					tmp *= sizeof(int32_t);
				else
					/* allocate Boolean array */
					tmp = (tmp + 7) >> 3;

				/*
				 * If the buffer was previously allocated,
				 * free it
				 */
				if (attrs[variable_id] & 0x80) {
					free((void *)vars[variable_id]);
					vars[variable_id] = 0;
				}

				/*
				 * Allocate a new buffer
				 * of the requested size
				 */
				vars[variable_id] = (intptr_t)calloc(1, tmp);

				if (vars[variable_id] == 0) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				/*
				 * Set the attribute bit to indicate that
				 * this buffer was dynamically allocated and
				 * should be freed later
				 */
				attrs[variable_id] |= 0x80;
			}

			break;
		case OP_EXPV:
			/*
			 * Export Boolean array
			 * ...argument 0 is string ID
			 * ...stack 0 is variable ID
			 * ...stack 1 is array right index
			 * ...stack 2 is array left index
			 */
			if (!altera_check_stack(stack_ptr, 3, &status))
				break;
			if (version == 0) {
				/* EXPV is not supported in JBC 1.0 */
				bad_opcode = 1;
				break;
			}
			name = &p[str_table + args[0]];
			variable_id = stack[--stack_ptr];
			idx = stack[--stack_ptr];/* right indx */
			idx2 = stack[--stack_ptr];/* left indx */

			if (idx > idx2) {
				/* reverse indices not supported */
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			count = 1 + idx2 - idx;

			charptr_tmp = (uint8_t *)vars[variable_id];
			charptr_tmp2 = NULL;

			if ((idx & 7) != 0) {
				int32_t k = idx;
				charptr_tmp2 =
					calloc(1, ((count + 7) / 8));
				if (charptr_tmp2 == NULL) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				for (i = 0; i < count; ++i) {
					if (charptr_tmp[k >> 3] &
							(1 << (k & 7)))
						charptr_tmp2[i >> 3] |=
								(1 << (i & 7));
					else
						charptr_tmp2[i >> 3] &=
								~(1 << (i & 7));

					++k;
				}
				charptr_tmp = charptr_tmp2;

			} else if (idx != 0)
				charptr_tmp = &charptr_tmp[idx >> 3];

			altera_export_bool_array(name, charptr_tmp,
							count);

			/* free allocated buffer */
			if ((idx & 7) != 0)
				free(charptr_tmp2);

			break;
		case OP_COPY: {
			/*
			 * Array copy
			 * ...argument 0 is dest ID
			 * ...argument 1 is source ID
			 * ...stack 0 is count
			 * ...stack 1 is dest index
			 * ...stack 2 is source index
			 */
			int32_t copy_count;
			int32_t copy_index;
			int32_t copy_idx2;
			int32_t destleft;
			int32_t src_count;
			int32_t dest_count;
			int src_reverse = 0;
			int dest_reverse = 0;

			if (!altera_check_stack(stack_ptr, 3, &status))
				break;

			copy_count = stack[--stack_ptr];
			copy_index = stack[--stack_ptr];
			copy_idx2 = stack[--stack_ptr];
			reverse = 0;

			if (version > 0) {
				/*
				 * stack 0 = source right index
				 * stack 1 = source left index
				 * stack 2 = destination right index
				 * stack 3 = destination left index
				 */
				destleft = stack[--stack_ptr];

				if (copy_count > copy_index) {
					src_reverse = 1;
					reverse = 1;
					src_count = 1 + copy_count - copy_index;
					/* copy_index = source start index */
				} else {
					src_count = 1 + copy_index - copy_count;
					/* source start index */
					copy_index = copy_count;
				}

				if (copy_idx2 > destleft) {
					dest_reverse = 1;
					reverse = !reverse;
					dest_count = 1 + copy_idx2 - destleft;
					/* destination start index */
					copy_idx2 = destleft;
				} else
					dest_count = 1 + destleft - copy_idx2;

				copy_count = (src_count < dest_count) ?
							src_count : dest_count;

				if ((src_reverse || dest_reverse) &&
					(src_count != dest_count))
					/*
					 * If either the source or destination
					 * is reversed, we can't tolerate
					 * a length mismatch, because we
					 * "left justify" arrays when copying.
					 * This won't work correctly
					 * with reversed arrays.
					 */
					status = ALTERA_BOUNDS_ERROR;

			}

			count = copy_count;
			idx = copy_index;
			idx2 = copy_idx2;

			/*
			 * If destination is a read-only array,
			 * allocate a buffer and convert it to a writable array
			 */
			variable_id = args[1];
			if ((version > 0) &&
				((attrs[variable_id] & 0x9c) == 0x0c)) {
				/* Allocate a writable buffer for this array */
				tmp = (var_size[variable_id] + 7) >> 3;
				charptr_tmp2 = (uint8_t *)vars[variable_id];
				charptr_tmp = calloc(1, tmp);
				vars[variable_id] = (intptr_t)charptr_tmp;

				if (vars[variable_id] == 0) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				/* copy previous contents into buffer */
				memcpy(charptr_tmp, charptr_tmp2, tmp);

				/*
				set bit 7 - buffer was dynamically allocated */
				attrs[variable_id] |= 0x80;

				/* clear bit 2 - variable is writable */
				attrs[variable_id] &= ~0x04;
				attrs[variable_id] |= 0x01;
			}

			charptr_tmp = (uint8_t *)vars[args[1]];
			charptr_tmp2 = (uint8_t *)vars[args[0]];

			/* check if destination is a writable Boolean array */
			if ((attrs[args[1]] & 0x1c) != 0x08) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			if (count < 1) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			if (reverse)
				idx2 += (count - 1);

			for (i = 0; i < count; ++i) {
				if (charptr_tmp2[idx >> 3] &
							(1 << (idx & 7)))
					charptr_tmp[idx2 >> 3] |=
							(1 << (idx2 & 7));
				else
					charptr_tmp[idx2 >> 3] &=
						~(1 << (idx2 & 7));

				++idx;
				if (reverse)
					--idx2;
				else
					++idx2;
			}

			break;
		}
		case OP_DSC:
		case OP_ISC: {
			/*
			 * DRSCAN with capture
			 * IRSCAN with capture
			 * ...argument 0 is scan data variable ID
			 * ...argument 1 is capture variable ID
			 * ...stack 0 is capture index
			 * ...stack 1 is scan data index
			 * ...stack 2 is count
			 */
			int32_t scan_right, scan_left;
			int32_t capture_count = 0;
			int32_t scan_count = 0;
			int32_t capture_index;
			int32_t scan_index;

			if (!altera_check_stack(stack_ptr, 3, &status))
				break;

			capture_index = stack[--stack_ptr];
			scan_index = stack[--stack_ptr];

			if (version > 0) {
				/*
				 * stack 0 = capture right index
				 * stack 1 = capture left index
				 * stack 2 = scan right index
				 * stack 3 = scan left index
				 * stack 4 = count
				 */
				scan_right = stack[--stack_ptr];
				scan_left = stack[--stack_ptr];
				capture_count = 1 + scan_index - capture_index;
				scan_count = 1 + scan_left - scan_right;
				scan_index = scan_right;
			}

			count = stack[--stack_ptr];
			/*
			 * If capture array is read-only, allocate a buffer
			 * and convert it to a writable array
			 */
			variable_id = args[1];
			if ((version > 0) &&
				((attrs[variable_id] & 0x9c) == 0x0c)) {
				/* Allocate a writable buffer for this array */
				tmp = (var_size[variable_id] + 7) >> 3;
				charptr_tmp2 = (uint8_t *)vars[variable_id];
				charptr_tmp = calloc(1, tmp);
				vars[variable_id] = (intptr_t)charptr_tmp;

				if (vars[variable_id] == 0) {
					status = ALTERA_OUT_OF_MEMORY;
					break;
				}

				/* copy previous contents into buffer */
				memcpy(charptr_tmp, charptr_tmp2, tmp);

				/*
				 * set bit 7 - buffer was
				 * dynamically allocated
				 */
				attrs[variable_id] |= 0x80;

				/* clear bit 2 - variable is writable */
				attrs[variable_id] &= ~0x04;
				attrs[variable_id] |= 0x01;

			}

			charptr_tmp = (uint8_t *)vars[args[0]];
			charptr_tmp2 = (uint8_t *)vars[args[1]];

			if ((version > 0) &&
					((count > capture_count) ||
					(count > scan_count))) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			/*
			 * check that capture array
			 * is a writable Boolean array
			 */
			if ((attrs[args[1]] & 0x1c) != 0x08) {
				status = ALTERA_BOUNDS_ERROR;
				break;
			}

			if (status == 0) {
				if (opcode == 0x82) /* DSC */
					status = altera_swap_dr(js,
							count,
							charptr_tmp,
							scan_index,
							charptr_tmp2,
							capture_index);
				else /* ISC */
					status = altera_swap_ir(js,
							count,
							charptr_tmp,
							scan_index,
							charptr_tmp2,
							capture_index);

			}

			break;
		}
		case OP_WAIT:
			/*
			 * WAIT
			 * ...argument 0 is wait state
			 * ...argument 1 is end state
			 * ...stack 0 is cycles
			 * ...stack 1 is microseconds
			 */
			if (!altera_check_stack(stack_ptr, 2, &status))
				break;
			tmp = stack[--stack_ptr];

			if (tmp != 0)
				status = altera_wait_cycles(js, tmp,
								args[0]);

			tmp = stack[--stack_ptr];

			if ((status == 0) && (tmp != 0))
				status = altera_wait_msecs(js,
								tmp,
								args[0]);

			if ((status == 0) && (args[1] != args[0]))
				status = altera_goto_jstate(js,
								args[1]);

			if (version > 0) {
				--stack_ptr; /* throw away MAX cycles */
				--stack_ptr; /* throw away MAX microseconds */
			}
			break;
		case OP_CMPA: {
			/*
			 * Array compare
			 * ...argument 0 is source 1 ID
			 * ...argument 1 is source 2 ID
			 * ...argument 2 is mask ID
			 * ...stack 0 is source 1 index
			 * ...stack 1 is source 2 index
			 * ...stack 2 is mask index
			 * ...stack 3 is count
			 */
			int32_t a, b;
			uint8_t *source1 = (uint8_t *)vars[args[0]];
			uint8_t *source2 = (uint8_t *)vars[args[1]];
			uint8_t *mask = (uint8_t *)vars[args[2]];
			uint32_t mask_index;

			if (!altera_check_stack(stack_ptr, 4, &status))
				break;

			idx = stack[--stack_ptr];
			idx2 = stack[--stack_ptr];
			mask_index = stack[--stack_ptr];
			count = stack[--stack_ptr];

			if (version > 0) {
				/*
				 * stack 0 = source 1 right index
				 * stack 1 = source 1 left index
				 * stack 2 = source 2 right index
				 * stack 3 = source 2 left index
				 * stack 4 = mask right index
				 * stack 5 = mask left index
				 */
				int32_t mask_right = stack[--stack_ptr];
				int32_t mask_left = stack[--stack_ptr];
				/* source 1 count */
				a = 1 + idx2 - idx;
				/* source 2 count */
				b = 1 + count - mask_index;
				a = (a < b) ? a : b;
				/* mask count */
				b = 1 + mask_left - mask_right;
				a = (a < b) ? a : b;
				/* source 2 start index */
				idx2 = mask_index;
				/* mask start index */
				mask_index = mask_right;
				count = a;
			}

			tmp = 1;

			if (count < 1)
				status = ALTERA_BOUNDS_ERROR;
			else {
				for (i = 0; i < count; ++i) {
					if (mask[mask_index >> 3] &
						(1 << (mask_index & 7))) {
						a = source1[idx >> 3] &
							(1 << (idx & 7))
								? 1 : 0;
						b = source2[idx2 >> 3] &
							(1 << (idx2 & 7))
								? 1 : 0;

						if (a != b) /* failure */
							tmp = 0;
					}
					++idx;
					++idx2;
					++mask_index;
				}
			}

			stack[stack_ptr++] = tmp;

			break;
		}
		default:
			/* Unrecognized opcode -- ERROR! */
			bad_opcode = 1;
			break;
		}

		if (trace) {
			fprintf(stderr, "stack=[");
			for (i = 0; i < stack_ptr; i++)
				fprintf(stderr, "%08x ", (uint32_t)stack[stack_ptr-i-1]);
			fprintf(stderr, "]\n");
		}

		if (bad_opcode)
			status = ALTERA_ILLEGAL_OPCODE;

		if ((stack_ptr < 0) || (stack_ptr >= ALTERA_STACK_SIZE))
			status = ALTERA_STACK_OVERFLOW;

		if (status != 0) {
			done = 1;
			*error_address = (int32_t)(opcode_address - code_sect);
		}
	}

	altera_free_buffers(js);

	/* Free all dynamically allocated arrays */
	if ((attrs != NULL) && (vars != NULL))
		for (i = 0; i < sym_count; ++i)
			if (attrs[i] & 0x80)
				free((void *)vars[i]);

	free(vars);
	free(var_size);
	free(attrs);
	free(proc_attributes);

	return status;
}

int altera_get_note(uint8_t *p, int32_t program_size, int32_t *offset,
		char *key, char *value, int length)
/*
 * Gets key and value of NOTE fields in the JBC file.
 * Can be called in two modes:  if offset pointer is NULL,
 * then the function searches for note fields which match
 * the key string provided.  If offset is not NULL, then
 * the function finds the next note field of any key,
 * starting at the offset specified by the offset pointer.
 * Returns 0 for success, else appropriate error code
 */
{
	int status = ALTERA_UNEXPECTED_END;
	uint32_t note_strings = 0;
	uint32_t note_table = 0;
	uint32_t note_count = 0;
	uint32_t first_word = 0;
	int version = 0;
	int delta = 0;
	char *key_ptr;
	char *value_ptr;
	int i;

	/* Read header information */
	if (program_size > 52) {
		first_word    = get_unaligned_be32(&p[0]);
		version = (first_word & 1);
		delta = version * 8;

		note_strings  = get_unaligned_be32(&p[8 + delta]);
		note_table    = get_unaligned_be32(&p[12 + delta]);
		note_count    = get_unaligned_be32(&p[44 + (2 * delta)]);
	}

	if ((first_word != 0x4A414D00) && (first_word != 0x4A414D01))
		return ALTERA_IO_ERROR;

	if (note_count <= 0)
		return status;

	if (offset == NULL) {
		/*
		 * We will search for the first note with a specific key,
		 * and return only the value
		 */
		for (i = 0; (i < note_count) &&
						(status != 0); ++i) {
			key_ptr = &p[note_strings +
					get_unaligned_be32(
					&p[note_table + (8 * i)])];
			if ((strncasecmp(key, key_ptr, strlen(key_ptr)) == 0) &&
						(key != NULL)) {
				status = 0;

				value_ptr = &p[note_strings +
						get_unaligned_be32(
						&p[note_table + (8 * i) + 4])];

				if (value != NULL)
					strlcpy(value, value_ptr, length);

			}
		}
	} else {
		/*
		 * We will search for the next note, regardless of the key,
		 * and return both the value and the key
		 */

		i = *offset;

		if ((i >= 0) && (i < note_count)) {
			status = 0;

			if (key != NULL)
				strlcpy(key, &p[note_strings +
						get_unaligned_be32(
						&p[note_table + (8 * i)])],
					length);

			if (value != NULL)
				strlcpy(value, &p[note_strings +
						get_unaligned_be32(
						&p[note_table + (8 * i) + 4])],
					length);

			*offset = i + 1;
		}
	}

	return status;
}

int altera_check_crc(uint8_t *p, int32_t program_size)
{
	int status = 0;
	uint16_t local_expected = 0,
	    local_actual = 0,
	    shift_reg = 0xffff;
	int bit, feedback;
	uint8_t databyte;
	uint32_t i;
	uint32_t crc_section = 0;
	uint32_t first_word = 0;
	int version = 0;
	int delta = 0;

	if (program_size > 52) {
		first_word  = get_unaligned_be32(&p[0]);
		version = (first_word & 1);
		delta = version * 8;

		crc_section = get_unaligned_be32(&p[32 + delta]);
	}

	if ((first_word != 0x4A414D00) && (first_word != 0x4A414D01))
		status = ALTERA_IO_ERROR;

	if (crc_section >= program_size)
		status = ALTERA_IO_ERROR;

	if (status == 0) {
		local_expected = (uint16_t)get_unaligned_be16(&p[crc_section]);

		for (i = 0; i < crc_section; ++i) {
			databyte = p[i];
			for (bit = 0; bit < 8; bit++) {
				feedback = (databyte ^ shift_reg) & 0x01;
				shift_reg >>= 1;
				if (feedback)
					shift_reg ^= 0x8408;

				databyte >>= 1;
			}
		}

		local_actual = (uint16_t)~shift_reg;

		if (local_expected != local_actual)
			status = ALTERA_CRC_ERROR;

	}

	return status;
}

int altera_get_file_info(uint8_t *p, int32_t program_size,
		int *format_version, int *action_count, int *procedure_count)
{
	int status = ALTERA_IO_ERROR;
	uint32_t first_word = 0;
	int version = 0;

	if (program_size <= 52)
		return status;

	first_word = get_unaligned_be32(&p[0]);

	if ((first_word == 0x4A414D00) || (first_word == 0x4A414D01)) {
		status = 0;

		version = (first_word & 1);
		*format_version = version + 1;

		if (version > 0) {
			*action_count = get_unaligned_be32(&p[48]);
			*procedure_count = get_unaligned_be32(&p[52]);
		}
	}

	return status;
}

int altera_get_act_info(uint8_t *p, int32_t program_size, int index,
		char **name, char **description,
		struct altera_procinfo **proc_list)
{
	int status = ALTERA_IO_ERROR;
	struct altera_procinfo *procptr = NULL;
	struct altera_procinfo *tmpptr = NULL;
	uint32_t first_word = 0;
	uint32_t action_table = 0;
	uint32_t proc_table = 0;
	uint32_t str_table = 0;
	uint32_t note_strings = 0;
	uint32_t action_count = 0;
	uint32_t proc_count = 0;
	uint32_t act_name_id = 0;
	uint32_t act_desc_id = 0;
	uint32_t act_proc_id = 0;
	uint32_t act_proc_name = 0;
	uint8_t act_proc_attribute = 0;

	if (program_size <= 52)
		return status;
	/* Read header information */
	first_word = get_unaligned_be32(&p[0]);

	if (first_word != 0x4A414D01)
		return status;

	action_table = get_unaligned_be32(&p[4]);
	proc_table   = get_unaligned_be32(&p[8]);
	str_table = get_unaligned_be32(&p[12]);
	note_strings = get_unaligned_be32(&p[16]);
	action_count = get_unaligned_be32(&p[48]);
	proc_count   = get_unaligned_be32(&p[52]);

	if (index >= action_count)
		return status;

	act_name_id = get_unaligned_be32(&p[action_table + (12 * index)]);
	act_desc_id = get_unaligned_be32(&p[action_table + (12 * index) + 4]);
	act_proc_id = get_unaligned_be32(&p[action_table + (12 * index) + 8]);

	*name = &p[str_table + act_name_id];

	if (act_desc_id < (note_strings - str_table))
		*description = &p[str_table + act_desc_id];

	do {
		act_proc_name = get_unaligned_be32(
					&p[proc_table + (13 * act_proc_id)]);
		act_proc_attribute =
			(p[proc_table + (13 * act_proc_id) + 8] & 0x03);

		procptr = calloc(1, sizeof(struct altera_procinfo));

		if (procptr == NULL)
			status = ALTERA_OUT_OF_MEMORY;
		else {
			procptr->name = &p[str_table + act_proc_name];
			procptr->attrs = act_proc_attribute;
			procptr->next = NULL;

			/* add record to end of linked list */
			if (*proc_list == NULL)
				*proc_list = procptr;
			else {
				tmpptr = *proc_list;
				while (tmpptr->next != NULL)
					tmpptr = tmpptr->next;
				tmpptr->next = procptr;
			}
		}

		act_proc_id = get_unaligned_be32(
				&p[proc_table + (13 * act_proc_id) + 4]);
	} while ((act_proc_id != 0) && (act_proc_id < proc_count));

	return status;
}
