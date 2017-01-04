/*
    fs.h

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2015,2016 Peter Popovec, popovec.peter@gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    filesystem function headre file

*/
#ifndef CS_FS_H
#define CS_FS_H

/* fs.c */
uint16_t fs_change_pin (uint8_t * message);
uint16_t fs_verify_pin (uint8_t * message);
uint16_t fs_reset_retry_count (uint8_t * message);
uint16_t fs_initialize_pin (uint8_t * message);

void fs_reset_security (void);
void fs_init (void);
uint16_t fs_erase_card (uint8_t * acl);

uint16_t fs_get_selected (void);

void fs_set_lifecycle(void);

uint16_t fs_select_parent (struct iso7816_response *r);
uint16_t fs_select_by_name (uint8_t * buffer, struct iso7816_response *r);
uint16_t fs_select_0 (uint16_t id, struct iso7816_response *r);
uint16_t fs_select_mf (struct iso7816_response *r);
uint16_t fs_select_df (uint16_t id, struct iso7816_response *r);
uint16_t fs_select_ef (uint16_t id, struct iso7816_response *r);
uint16_t fs_select_by_path_from_mf (uint8_t * buffer,
				    struct iso7816_response *r);
uint16_t fs_select_by_path_from_df (uint8_t * buffer,
				    struct iso7816_response *r);


uint16_t fs_key_read_part (uint8_t * key, uint8_t type);

// 1st byte = key type, 2nd key part size, rest key part
uint16_t fs_key_write_part (uint8_t * key);

uint16_t fs_read_binary (uint16_t offset, uint16_t dlen,
			 struct iso7816_response *r);
uint16_t fs_update_binary (uint8_t * buffer, uint16_t offset);

uint16_t fs_erase_binary(uint16_t offset);

uint16_t fs_delete_file (void);

int16_t fs_create_file (uint8_t * buffer);
uint16_t fs_list_files (uint8_t type, struct iso7816_response *r);

uint16_t fs_get_file_size ();
uint8_t fs_get_file_type ();
#ifndef NIST_ONLY
// temp function to allow change file type for EC key to 0x23
uint16_t fs_key_change_type ();
#endif
#endif
