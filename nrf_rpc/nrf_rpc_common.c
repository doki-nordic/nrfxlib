/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#define NRF_RPC_LOG_MODULE NRF_RPC
#include <nrf_rpc_log.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <nrf_rpc_errno.h>
#include <nrf_rpc_common.h>

#ifdef CONFIG_NRF_RPC_AUTO_ARR_CONSTRUCTOR

static struct _nrf_rpc_auto_arr_item *first_item;
static void** auto_arr;

void _nrf_rpc_auto_arr_item_init(struct _nrf_rpc_auto_arr_item *item, const void *data, const char *key, bool is_array)
{
	item->data = data;
	item->key = key;
	item->is_array = is_array;
	item->next = first_item;
	first_item = item;
}

static int auto_arr_cmp(const void *a, const void *b)
{
	struct _nrf_rpc_auto_arr_item **l = (struct _nrf_rpc_auto_arr_item **)a;
	struct _nrf_rpc_auto_arr_item **r = (struct _nrf_rpc_auto_arr_item **)b;

	return strcmp((*l)->key, (*r)->key);
}

int nrf_rpc_auto_arr_init(void)
{
	size_t i;
	size_t j;
	size_t count = 0;
	struct _nrf_rpc_auto_arr_item **items;
	struct _nrf_rpc_auto_arr_item *item;

	if (auto_arr != NULL) {
		NRF_RPC_ASSERT(first_item == NULL);
		return 0;
	}

	item = first_item;
	while (item != NULL) {
		count++;
		item = item->next;
	}

	items = malloc(sizeof(void *) * (count + 1));
	if (items == NULL) {
		return -NRF_ENOMEM;
	}

	auto_arr = (void **)items;
	
	i = 0;
	item = first_item;
	while (item != NULL) {
		items[i] = item;
		i++;
		item = item->next;
	}
	items[i] = NULL;

	first_item = NULL;

	qsort(items, count, sizeof(struct _nrf_rpc_auto_arr_item *), auto_arr_cmp);

	NRF_RPC_DBG("AUTO_ARR items:");

	j = 0;
	for (i = 0; i < count; i++) {
		item = items[i];
		if (item->is_array) {
			auto_arr[i] = NULL;
			*(void ***)item->data = &auto_arr[i + 1];
			NRF_RPC_DBG("%03d array: %s", (int)i, item->key);
			j = 0;
		} else {
			auto_arr[i] = (void *)item->data;
			NRF_RPC_DBG("%03d        [%d] %s", (int)i, (int)j, item->key);
			j++;
		}
	}

	return 0;
}

#endif /* CONFIG_NRF_RPC_AUTO_ARR_CONSTRUCTOR */
