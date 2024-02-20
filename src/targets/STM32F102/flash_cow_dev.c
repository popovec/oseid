/*
    flash_cow_dev.c

    This is part of OsEID (Open source Electronic ID)

    Copyright (C) 2024 Peter Popovec, popovec.peter@gmail.com

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

    flash memory helper


*/
/*
OsEID specific: changecounter:

The state of the filesystem is maintained in a log that has numbered
transactions.  This information is maintained in the variable "generation".
The transaction number is used for information that the OsEID card publishes
as a "changecounter" that is used in OpenSC to maintain the validity of the
file cache.

Changes concerning objects such as PIN and PUK maintained in "sec_mem" do
not represent a change in changecounter information.  For OsEID, the mapping
of "generation" to changecounter is changed.  Generation is incremented by 1
for changes in objects of the PIN/PUK type, but for a normal filesystem,
"generation" is changed by 256.  This makes it possible to use the
"generation >> 8" as "changecounter".  Of course, with 256 changes in
PIN/PUK type objects, the changecounter will be incremented ..  but that's
not a problem.

*/

#include <stdint.h>
#include <string.h>
#include "flash_cow_dev.h"
#include "STM32F10x_flash.device.h"

//#define FLASH_DEVICE_TEST

// flash page size and how many pages we have available
// (real capacity is FLASH_PAGE_SIZE * (FLASH_PAGE_COUNT - 1)
#define FLASH_PAGE_SIZE 1024U
#define FLASH_PAGE_COUNT 66

// map is in flash but on another device maybe in another flash/eeprom
// map page size, and how many pages we have available
#define FLASH_MAP_PAGE_SIZE 1024U
#define FLASH_MAP_PAGE_COUNT 4

#ifndef FLASH_BASE
uint8_t *flash_hw_get_base(void);
#define FLASH_BASE	flash_hw_get_base()
#endif
#ifndef FLASH_MAP_BASE
uint8_t *flash_hw_get_map_base(void);
#define FLASH_MAP_BASE	flash_hw_get_map_base()
#endif
////////////////////////////////////////////////////////////////
//
// checks

#if FLASH_PAGE_COUNT > 255
#error allowed only 255 pages
#endif

#if FLASH_MAP_PAGE_COUNT < 2
#error minimum for FLASH_MAP_PAGE_COUNT is 2
#endif

// TODO check for minimal space in page map ..

//
#define FS_COW_ENOSPC	10
#define FS_COW_EINV	20
#define FS_COW_FLASH	30

struct flash_page_map_entry {
	uint8_t page;		// where the page is placed
	uint16_t life;		// counter - page erase cycles, decremented after erase
} __attribute__((aligned(1), packed));

struct flash_page_map {
	struct flash_page_map_entry entry[FLASH_PAGE_COUNT];
#ifdef OsEID
	uint32_t generation;
#else
	uint16_t generation;	// decrement for new page map
#endif
} __attribute__((aligned(2), packed));

#ifdef FLASH_DEVICE_TEST

#include <stdio.h>
static void __attribute__((unused)) hex_debug(uint8_t * data, uint16_t len)
{
	uint8_t c;
	uint8_t wrap = 0;
	while (len--) {
		c = *(data++);
		printf("%02x ", c);
		wrap++;
		if (wrap == 32) {
			printf("\n");
			wrap = 0;
		}
	}
}

uint8_t flash_device_write_block(void *buffer, uint32_t offset, uint32_t size);
uint8_t flash_device_read_block(void *buffer, uint32_t offset, uint32_t size);
uint16_t flash_device_get_changecounter();
uint8_t testflashx[FLASH_PAGE_SIZE * FLASH_PAGE_COUNT];
uint8_t testflashmapx[FLASH_MAP_PAGE_SIZE * FLASH_MAP_PAGE_COUNT];
uint8_t checkflash[FLASH_PAGE_SIZE * FLASH_PAGE_COUNT];
#undef FLASH_BASE
#undef FLASH_MAP_BASE
#define FLASH_BASE	(testflashx)
#define FLASH_MAP_BASE	(testflashmapx)
uint8_t compare_whole_flash()
{
	int ret;
	int buffer[FLASH_PAGE_SIZE * FLASH_PAGE_COUNT];
	flash_device_read_block(buffer, 0, FLASH_PAGE_SIZE * (FLASH_PAGE_COUNT - 1));
	ret = memcmp(buffer, checkflash, FLASH_PAGE_SIZE * (FLASH_PAGE_COUNT - 1));
	if (ret != 0) {
		FILE *f;
		f = fopen("test_read.bin", "wb");
		fwrite(buffer, FLASH_PAGE_SIZE, FLASH_PAGE_COUNT, f);
		fclose(f);
		f = fopen("internal_flash.bin", "wb");
		fwrite(FLASH_BASE, FLASH_PAGE_SIZE, FLASH_PAGE_COUNT, f);
		fclose(f);
		f = fopen("reference.bin", "wb");
		fwrite(checkflash, FLASH_PAGE_SIZE, FLASH_PAGE_COUNT, f);
		fclose(f);
		f = fopen("map.bin", "wb");
		fwrite(FLASH_MAP_BASE, FLASH_MAP_PAGE_SIZE, FLASH_MAP_PAGE_COUNT, f);
		fclose(f);
	}
	return ret;
}

uint8_t test_write_flash(void *buffer, uint32_t offset, uint32_t size)
{
	memcpy(checkflash + offset, buffer, size);
	return flash_device_write_block(buffer, offset, size);
}

int main()
{

	uint8_t buffer[65536];
	FILE *rnd_gen;
	int testcount;
	uint16_t length;
	uint16_t offset;
	uint32_t maxaddress;
	if (NULL == (rnd_gen = fopen("/dev/urandom", "rb")))
		return 1;
	memset(FLASH_BASE, 0xff, FLASH_PAGE_SIZE * FLASH_PAGE_COUNT);
	memset(FLASH_MAP_BASE, 0xff, FLASH_MAP_PAGE_SIZE * FLASH_MAP_PAGE_COUNT);
	memset(checkflash, 0xff, FLASH_PAGE_SIZE * FLASH_PAGE_COUNT);
	testcount = 1600;
	while (testcount--) {

		fread(&length, 2, 1, rnd_gen);
		length &= 0xff;
		fread(&offset, 2, 1, rnd_gen);
		if (offset + length > FLASH_PAGE_SIZE * (FLASH_PAGE_COUNT - 1)) {
			testcount++;
			continue;
		}
		maxaddress = FLASH_PAGE_SIZE * FLASH_PAGE_COUNT - 1;
		maxaddress -= offset;
		if (length > maxaddress + 1)
			length = maxaddress;
		printf("offset = %d, length=%d\n", offset, length);
		fread(buffer, length, 1, rnd_gen);
		if (FS_COW_ENOSPC == test_write_flash(buffer, offset, length)) {
			printf("FS_COW_ENOSPC\n");
			return 3;
//                      break;
		}
		if (0 != compare_whole_flash()) {
			printf("compare fail\n");
			return 2;
		}
		printf("all ok\n");
	}
//      hex_debug(testflashmap, FLASH_MAP_PAGE_SIZE * FLASH_MAP_PAGE_COUNT);
	return 0;
}

// 0 OK
static int flash_hw_erase_page(void *flash_address)
{
	memset(flash_address, 0xff, FLASH_MAP_PAGE_SIZE);
	return 0;
}

// O = OK
static int flash_hw_write_data(void *dst, void *src, uint16_t size)
{
	uint16_t i;
	uint16_t *d = (uint16_t *) dst;
	uint16_t *s = (uint16_t *) src;
	for (i = 0; i < size / 2; i++, d++, s++) {
		if (*d != *s)
			*d = *s;
	}
	return 0;
}
#endif

#ifndef FLASH_BASE
#error Missing flash start address
#endif
#ifndef FLASH_MAP_BASE
#error Missing flash map start address
#endif

static struct flash_page_map *flash_map_next(struct flash_page_map *page)
{
	page++;
	// check loop end...
	if (((uint8_t *) page + sizeof(struct flash_page_map)) >=
	    ((uint8_t *) FLASH_MAP_BASE + FLASH_MAP_PAGE_COUNT * FLASH_MAP_PAGE_SIZE)) {
		page = (struct flash_page_map *)FLASH_MAP_BASE;
	}
	return page;
}

// search for actual map
// return pointer to blank map or last active map.
static struct flash_page_map *flash_map_find_actual(void)
{
	struct flash_page_map *map;
	struct flash_page_map *active_map = (struct flash_page_map *)FLASH_MAP_BASE;

#ifdef DISABLE_MAP_ROTATION
	return (struct flash_page_map *)FLASH_MAP_BASE;
#else
	for (;;) {
		map = flash_map_next(active_map);
		if (active_map->generation < map->generation)
			return active_map;
		// no active page, after full loop? - flash is blank
		if (active_map > map)
			return map;
		active_map = map;
	}
#endif
}

static int
    __attribute__((warn_unused_result)) flash_write_new_active_page(struct flash_page_map
								    *map, struct flash_page_map
								    *newmap)
{

#ifdef DISABLE_MAP_ROTATION
	memcpy(FLASH_MAP_BASE, newmap, sizeof(struct flash_page_map));
#else
	uint8_t *test;
	uint32_t offset;
	// here write new page:
	map = flash_map_next(map);
	// let's test, and the record exceeds the page boundary
	test = (uint8_t *) map;
	test += sizeof(struct flash_page_map) - 1;
	offset = test - (uint8_t *) FLASH_MAP_BASE;
	if ((offset % FLASH_MAP_PAGE_SIZE) < sizeof(struct flash_page_map)) {
		// erase page pointed by test
		{
			int erase_start = ((uint8_t *) test - (uint8_t *) FLASH_MAP_BASE);
			erase_start /= FLASH_MAP_PAGE_SIZE;
			if (flash_hw_erase_page(FLASH_MAP_BASE + erase_start * FLASH_MAP_PAGE_SIZE))
				return FS_COW_FLASH;
		}
	}
	if (flash_hw_write_data(map, newmap, sizeof(struct flash_page_map)))
		return FS_COW_FLASH;
#endif
	return 0;
}

// 0xff = no page allocated
static uint8_t flash_get_page_index(struct flash_page_map *map, uint32_t offset)
{
	uint8_t index = offset / FLASH_PAGE_SIZE;
	uint8_t i;
	for (i = 0; i < FLASH_PAGE_COUNT; i++) {
		if (index == map->entry[i].page)
			return i;
	}
	return 0xff;
}

// 0xff = fail
static uint8_t flash_allocate(struct flash_page_map *map)
{
	uint8_t i, ret = 0xff;
	uint16_t life = 0;
	if (map)
		for (i = 0; i < FLASH_PAGE_COUNT; i++) {
			if (0xff == map->entry[i].page) {
				if (life < map->entry[i].life) {
					life = map->entry[i].life;
					ret = i;
				}
			}
		}
	return ret;
}

// public
uint16_t flash_device_get_changecounter()
{
	struct flash_page_map *page_map = flash_map_find_actual();
#ifdef OsEID
	return ~(page_map->generation >> 8);
#else
	return ~(page_map->generation);
#endif
}

// public
uint8_t flash_device_read_block(void *buffer, uint32_t offset, uint32_t size)
{
	uint8_t *dest = (uint8_t *) buffer;
	uint8_t *src;
	uint8_t index;
	struct flash_page_map *page_map = flash_map_find_actual();
	if (offset + size > FLASH_PAGE_SIZE * FLASH_PAGE_COUNT)
		return FS_COW_EINV;
	while (size) {
		index = flash_get_page_index(page_map, offset);
		src = (uint8_t *) FLASH_BASE + index * FLASH_PAGE_SIZE + offset % FLASH_PAGE_SIZE;
		while (size) {
			// no allocated page, simulate read
			if (index < FLASH_PAGE_COUNT)
				*(dest++) = *(src++);
			else
				*(dest++) = 0xff;
			offset++;
			size--;
			if ((offset % FLASH_PAGE_SIZE) == 0)
				break;;
		}
	}
	return 0;
}

// public
uint8_t flash_device_write_block(void *buffer, uint32_t offset, uint32_t size)
{
	uint8_t *src;
	uint8_t page_buffer[FLASH_PAGE_SIZE];
	struct flash_page_map newmap;
	uint8_t erase_index;
	uint16_t page_offset;;
	uint8_t index;
	uint16_t i;
	uint8_t reuse;
	uint8_t *dest;
	uint16_t trim;
	if (offset + size > FLASH_PAGE_SIZE * FLASH_PAGE_COUNT)
		return FS_COW_EINV;
	src = (uint8_t *) buffer;
	while (size) {
		erase_index = 0xff;
		page_offset = offset / FLASH_PAGE_SIZE;
		struct flash_page_map *page_map = flash_map_find_actual();
		memcpy(&newmap, page_map, sizeof(struct flash_page_map));
		index = flash_get_page_index(page_map, offset);
		// if page is already allocated, copy data.. or "reset" page_buffer
		if (index < FLASH_PAGE_COUNT)
			memcpy(page_buffer,
			       (uint8_t *) FLASH_BASE + index * FLASH_PAGE_SIZE, FLASH_PAGE_SIZE);
		else
			memset(page_buffer, 0xff, FLASH_PAGE_SIZE);
		// update page, test if there is any change
		reuse = 1;
		dest = page_buffer + offset % FLASH_PAGE_SIZE;
		while (size) {
			if (*dest != *src)
				reuse = 0;
			*(dest++) = *(src++);
			offset++;
			size--;
			if ((offset % FLASH_PAGE_SIZE) == 0)
				break;;
		}
		// Flash already contains the data that should be written there.
		if (reuse)
			continue;
		// test if already allocated page can be reused
		uint16_t *d = (uint16_t *) ((uint8_t *) FLASH_BASE + index * FLASH_PAGE_SIZE);
		uint16_t *s = (uint16_t *) page_buffer;
		uint16_t c;
		for (trim = 0xffff, reuse = 1, i = 0; i < FLASH_PAGE_SIZE / 2; i++, d++, s++) {
			trim &= *s;
			// STM32F specific...
			if (*s == 0)
				continue;
			c = 0xffff;
			if (index < FLASH_PAGE_COUNT)
				c = *d;
			else
				reuse = 0;
			if (c == *s)
				continue;
			if (c == 0xffff)
				continue;
			reuse = 0;
		}

		if (!reuse) {
			// save old page index
			erase_index = index;
			// do not occupy blank page..
			if (trim != 0xffff) {
				// allocate new page
				index = flash_allocate(&newmap);
				if (index >= FLASH_PAGE_COUNT)
					return FS_COW_ENOSPC;
				newmap.entry[index].page = page_offset;
			} else
				index = 0xff;
			// deallocate old page
			if (erase_index < FLASH_PAGE_COUNT) {
				newmap.entry[erase_index].page = 0xff;
				newmap.entry[erase_index].life--;
			}
		}
		// write new page
		if (index < FLASH_PAGE_COUNT) {
			if (flash_hw_write_data((FLASH_BASE + index * FLASH_PAGE_SIZE),
						page_buffer, FLASH_PAGE_SIZE))
				return FS_COW_FLASH;
		}
		// write metadata
#ifdef OsEID
		if (page_offset != 0) {
			// Changes (from PIN/PUK changes) are not essential, we will cancel them.
			newmap.generation |= 0xff;
			newmap.generation -= 256;
		} else
			newmap.generation--;
#else
		newmap.generation--;
#endif
		if (flash_write_new_active_page(page_map, &newmap))
			return FS_COW_FLASH;
		// the page that has become free will be erased
		if (erase_index < FLASH_PAGE_COUNT) {
			if (flash_hw_erase_page(FLASH_BASE + erase_index * FLASH_PAGE_SIZE))
				return FS_COW_FLASH;
		}
	}
	return 0;
}
