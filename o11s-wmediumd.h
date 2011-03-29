#ifndef __O11S_WMEDIUMD_H
#define __O11S_WMEDIUMD_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* These enums need to be kept in sync with userspace */
enum hwsim_testmode_attr {
	__HWSIM_TM_ATTR_INVALID = 0,
	HWSIM_TM_ATTR_CMD = 1,
	HWSIM_TM_ATTR_PS = 2,
	HWSIM_TM_ATTR_FRAME = 3,
	HWSIM_TM_ATTR_STATUS = 4,
	HWSIM_TM_ATTR_REGISTER = 5,

	/* keep last */
	__HWSIM_TM_ATTR_AFTER_LAST,
	HWSIM_TM_ATTR_MAX	= __HWSIM_TM_ATTR_AFTER_LAST - 1
};

enum hwsim_testmode_cmd {
	HWSIM_TM_CMD_SET_PS = 0,
	HWSIM_TM_CMD_GET_PS = 1,
	HWSIM_TM_CMD_FRAME = 2,
	HWSIM_TM_CMD_REGISTER = 3,
};

#define MAC80211_TX_MAX_RATES 5

struct mac80211_hwsim_tx_rate {
	__s8 idx;
	__u8 count;
	__u8 flags;
} __attribute__((packed));

/* This structure is passed from userspace to indicate Tx status */
struct mac80211_hwsim_tx_header {
	unsigned long cookie; /* skb */
	__u64 group;
	__u32 flags;
	__u16 freq;
	__u8 hw_addr[6]; /* local hw mac address */
	__u8 drop;	/* the frame should be dropped */
	__u8 band;
	__s8 signal;
	__u8 ack_signal;
	__u8 rate_idx;
	struct mac80211_hwsim_tx_rate rates[MAC80211_TX_MAX_RATES];
} __attribute__((packed));

const char *o11s_wmediumd_version = "o11s_wmediumd v" VERSION_STR "\n"
"Copyright (c) 2011, cozybit Inc.";

#endif /* __O11S_WMEDIUMD_H */

