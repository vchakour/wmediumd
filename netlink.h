/*
 * Path Selection Daemon for open80211s
 * Copyright (c) 2010, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See README and COPYING for more details.
 *
 * Functions from this file have been liberally copied from wpa_supplicant,
 * which is licensed under GPL as well but has the following copyrights:
 *
 *  * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *  * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 *  * Copyright (c) 2005-2006, Devicescape Software, Inc.
 *  * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 *  * Copyright (c) 2009-2010, Atheros Communications
 */

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <errno.h>

//#include <linux/nl80211.h>
#include "nl80211.h"

int netlink_init();
int register_read_socket(int sock);

struct netlink_config_s {
	struct nl_sock *nl_sock;
	struct nl_sock *nl_sock_event;
	struct nl_sock *nl_sock_preq;
	struct nl_cache *nl_cache;
	struct nl_cache *nl_cache_event;
	struct nl_cache *nl_cache_preq;
	struct nl_cb *nl_cb;
	struct genl_family *nl80211;
};

extern struct netlink_config_s nlcfg;
