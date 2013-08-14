/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $DragonFly: src/sbin/hammer/cmd_blockmap.c,v 1.4 2008/07/19 18:48:14 dillon Exp $
 */

#include "hammer.h"

typedef struct collect {
	struct collect	*hnext;
	hammer_off_t	phys_offset;
	struct hammer_blockmap_layer2 *track2;
	struct hammer_blockmap_layer2 *layer2;
} *collect_t;

collect_t CollectHash[COLLECT_HSIZE];

static void dump_blockmap(const char *label, int zone);
static void check_btree_node(hammer_off_t node_offset, int depth);
static void collect_btree_elm(hammer_btree_elm_t elm);
static struct hammer_blockmap_layer2 *collect_get_track(
	collect_t collect, hammer_off_t offset,
	struct hammer_blockmap_layer2 *layer2);
static collect_t collect_get(hammer_off_t phys_offset);
static void dump_collect_table(void);
static void dump_collect(collect_t collect);

void
hammer_cmd_blockmap(void)
{
	dump_blockmap("btree", HAMMER_ZONE_FREEMAP_INDEX);
}

static
void
dump_blockmap(const char *label, int zone)
{
	struct volume_info *root_volume;
	hammer_blockmap_t rootmap;
	struct hammer_blockmap_layer1 *layer1;
	struct hammer_blockmap_layer2 *layer2;
	struct buffer_info *buffer1 = NULL;
	struct buffer_info *buffer2 = NULL;
	hammer_off_t layer1_offset;
	hammer_off_t layer2_offset;
	hammer_off_t scan1;
	hammer_off_t scan2;
	int xerr;

	assert(RootVolNo >= 0);
	root_volume = get_volume(RootVolNo);
	rootmap = &root_volume->ondisk->vol0_blockmap[zone];
	assert(rootmap->phys_offset != 0);

	printf("zone %-16s next %016jx alloc %016jx\n",
		label,
		(uintmax_t)rootmap->next_offset,
		(uintmax_t)rootmap->alloc_offset);

	for (scan1 = HAMMER_ZONE_ENCODE(zone, 0);
	     scan1 < HAMMER_ZONE_ENCODE(zone, HAMMER_OFF_LONG_MASK);
	     scan1 += HAMMER_BLOCKMAP_LAYER2) {
		/*
		 * Dive layer 1.
		 */
		layer1_offset = rootmap->phys_offset +
				HAMMER_BLOCKMAP_LAYER1_OFFSET(scan1);
		layer1 = get_buffer_data(layer1_offset, &buffer1, 0);
		xerr = ' ';
		if (layer1->layer1_crc != crc32(layer1, HAMMER_LAYER1_CRCSIZE))
			xerr = 'B';
		if (xerr == ' ' &&
		    layer1->phys_offset == HAMMER_BLOCKMAP_UNAVAIL) {
			continue;
		}
		printf("%c layer1 %016jx @%016jx blocks-free %jd\n",
			xerr,
			(uintmax_t)scan1,
			(uintmax_t)layer1->phys_offset,
			(intmax_t)layer1->blocks_free);
		if (layer1->phys_offset == HAMMER_BLOCKMAP_FREE)
			continue;
		for (scan2 = scan1;
		     scan2 < scan1 + HAMMER_BLOCKMAP_LAYER2;
		     scan2 += HAMMER_LARGEBLOCK_SIZE
		) {
			/*
			 * Dive layer 2, each entry represents a large-block.
			 */
			layer2_offset = layer1->phys_offset +
					HAMMER_BLOCKMAP_LAYER2_OFFSET(scan2);
			layer2 = get_buffer_data(layer2_offset, &buffer2, 0);
			xerr = ' ';
			if (layer2->entry_crc != crc32(layer2, HAMMER_LAYER2_CRCSIZE))
				xerr = 'B';
			printf("%c       %016jx zone=%d app=%-7d free=%-7d\n",
				xerr,
				(uintmax_t)scan2,
				layer2->zone,
				layer2->append_off,
				layer2->bytes_free);
		}
	}
	if (buffer1)
		rel_buffer(buffer1);
	if (buffer2)
		rel_buffer(buffer2);
	rel_volume(root_volume);
}

void
hammer_cmd_checkmap(void)
{
	struct volume_info *volume;
	hammer_off_t node_offset;

	volume = get_volume(RootVolNo);
	node_offset = volume->ondisk->vol0_btree_root;
	if (QuietOpt < 3) {
		printf("Volume header\trecords=%jd next_tid=%016jx\n",
		       (intmax_t)volume->ondisk->vol0_stat_records,
		       (uintmax_t)volume->ondisk->vol0_next_tid);
		printf("\t\tbufoffset=%016jx\n",
		       (uintmax_t)volume->ondisk->vol_buf_beg);
	}
	rel_volume(volume);

	printf("Collecting allocation info from B-Tree: ");
	fflush(stdout);
	check_btree_node(node_offset, 0);
	printf("done\n");
	dump_collect_table();
}

static void
check_btree_node(hammer_off_t node_offset, int depth)
{
	struct buffer_info *buffer = NULL;
	hammer_node_ondisk_t node;
	hammer_btree_elm_t elm;
	int i;
	char badc;

	node = get_node(node_offset, &buffer);

	if (crc32(&node->crc + 1, HAMMER_BTREE_CRCSIZE) == node->crc)
		badc = ' ';
	else
		badc = 'B';

	if (badc != ' ') {
		printf("B    NODE %016jx cnt=%02d p=%016jx "
		       "type=%c depth=%d",
		       (uintmax_t)node_offset, node->count,
		       (uintmax_t)node->parent,
		       (node->type ? node->type : '?'), depth);
		printf(" mirror %016jx", (uintmax_t)node->mirror_tid);
		printf(" {\n");
	}

	for (i = 0; i < node->count; ++i) {
		elm = &node->elms[i];

		switch(node->type) {
		case HAMMER_BTREE_TYPE_INTERNAL:
			if (elm->internal.subtree_offset) {
				check_btree_node(elm->internal.subtree_offset,
						 depth + 1);
			}
			break;
		case HAMMER_BTREE_TYPE_LEAF:
			if (elm->leaf.data_offset)
				collect_btree_elm(elm);
			break;
		default:
			assert(0);
		}
	}
	rel_buffer(buffer);
}

static
void
collect_btree_elm(hammer_btree_elm_t elm)
{
	struct hammer_blockmap_layer1 layer1;
	struct hammer_blockmap_layer2 layer2;
	struct hammer_blockmap_layer2 *track2;
	hammer_off_t offset = elm->leaf.data_offset;
	collect_t collect;
	int error;

	blockmap_lookup(offset, &layer1, &layer2, &error);
	collect = collect_get(layer1.phys_offset);
	track2 = collect_get_track(collect, offset, &layer2);
	track2->bytes_free -= (elm->leaf.data_len + 15) & ~15;
}

static
collect_t
collect_get(hammer_off_t phys_offset)
{
	int hv = crc32(&phys_offset, sizeof(phys_offset)) & COLLECT_HMASK;
	collect_t collect;

	for (collect = CollectHash[hv]; collect; collect = collect->hnext) {
		if (collect->phys_offset == phys_offset)
			return(collect);
	}
	collect = calloc(sizeof(*collect), 1);
	collect->track2 = malloc(HAMMER_LARGEBLOCK_SIZE);
	collect->layer2 = malloc(HAMMER_LARGEBLOCK_SIZE);
	collect->phys_offset = phys_offset;
	collect->hnext = CollectHash[hv];
	CollectHash[hv] = collect;
	bzero(collect->track2, HAMMER_LARGEBLOCK_SIZE);
	bzero(collect->layer2, HAMMER_LARGEBLOCK_SIZE);

	return (collect);
}

static
struct hammer_blockmap_layer2 *
collect_get_track(collect_t collect, hammer_off_t offset,
		  struct hammer_blockmap_layer2 *layer2)
{
	struct hammer_blockmap_layer2 *track2;
	size_t i;

	i = HAMMER_BLOCKMAP_LAYER2_OFFSET(offset) / sizeof(*track2);
	track2 = &collect->track2[i];
	if (track2->entry_crc == 0) {
		collect->layer2[i] = *layer2;
		track2->bytes_free = HAMMER_LARGEBLOCK_SIZE;
		track2->entry_crc = 1;	/* steal field to tag track load */
	}
	return (track2);
}

static
void
dump_collect_table(void)
{
	collect_t collect;
	int i;

	for (i = 0; i < COLLECT_HSIZE; ++i) {
		for (collect = CollectHash[i];
		     collect;
		     collect = collect->hnext) {
			dump_collect(collect);
		}
	}
}

static
void
dump_collect(collect_t collect)
{
	struct hammer_blockmap_layer2 *track2;
	struct hammer_blockmap_layer2 *layer2;
	size_t i;

	for (i = 0; i < HAMMER_BLOCKMAP_RADIX2; ++i) {
		track2 = &collect->track2[i];
		layer2 = &collect->layer2[i];

		/*
		 * Currently just check bigblocks referenced by data
		 * or B-Tree nodes.
		 */
		if (track2->entry_crc == 0)
			continue;

		if (track2->bytes_free != layer2->bytes_free) {
			printf("BM\tblock=%016jx calc %d free, got %d\n",
				(intmax_t)(collect->phys_offset +
					   i * HAMMER_LARGEBLOCK_SIZE),
				track2->bytes_free,
				layer2->bytes_free);
		} else if (VerboseOpt) {
			printf("\tblock=%016jx %d free (correct)\n",
				(intmax_t)(collect->phys_offset +
					   i * HAMMER_LARGEBLOCK_SIZE),
				track2->bytes_free);
		}
	}
}
