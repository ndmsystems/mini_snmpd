/*
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 * Copyright (C) 2011       Javier Palacios <javiplx@gmail.com>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */

#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>		/* intptr_t/uintptr_t */
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>

#include "mini_snmpd.h"

/*
 * Module variables
 *
 * To extend the MIB, add the definition of the SNMP table here. Note that the
 * variables use OIDs that have two subids more, which both are specified in the
 * mib_build_entry() and mib_build_entries() function calls. For example, the
 * system table uses the OID .1.3.6.1.2.1.1, the first system table variable,
 * system.sysDescr.0 (using OID .1.3.6.1.2.1.1.1.0) is appended to the MIB using
 * the function call mib_build_entry(&m_system_oid, 1, 0, ...).
 *
 * The first parameter is the array containing the list of subids (up to 14 here),
 * the next is the number of subids. The last parameter is the length that this
 * OID will need encoded in SNMP packets (including the BER type and length fields).
 */

static const oid_t m_system_oid         = { { 1, 3, 6, 1, 2, 1, 1               },  7, 8  };
static const oid_t m_if_1_oid           = { { 1, 3, 6, 1, 2, 1, 2               },  7, 8  };
static const oid_t m_if_2_oid           = { { 1, 3, 6, 1, 2, 1, 2, 2, 1         },  9, 10 };
static const oid_t m_ip_oid             = { { 1, 3, 6, 1, 2, 1, 4               },  7, 8  };
static const oid_t m_tcp_oid            = { { 1, 3, 6, 1, 2, 1, 6               },  7, 8  };
static const oid_t m_udp_oid            = { { 1, 3, 6, 1, 2, 1, 7               },  7, 8  };
static const oid_t m_host_oid           = { { 1, 3, 6, 1, 2, 1, 25, 1           },  8, 9  };
static const oid_t m_if_ext_oid         = { { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1     }, 10, 11 };
static const oid_t m_memory_oid         = { { 1, 3, 6, 1, 4, 1, 2021, 4,        },  8, 10 };
static const oid_t m_disk_oid           = { { 1, 3, 6, 1, 4, 1, 2021, 9, 1      },  9, 11 };
static const oid_t m_load_oid           = { { 1, 3, 6, 1, 4, 1, 2021, 10, 1     },  9, 11 };
static const oid_t m_cpu_oid            = { { 1, 3, 6, 1, 4, 1, 2021, 11        },  8, 10 };
#ifdef CONFIG_ENABLE_DEMO
static const oid_t m_demo_oid           = { { 1, 3, 6, 1, 4, 1, 99999           },  7, 10 };
#endif

static const int m_load_avg_times[3] = { 1, 5, 15 };

static int oid_build  (oid_t *oid, const oid_t *prefix, int column, int row);
static int encode_oid_len (oid_t *oid);

static int data_alloc (data_t *data, int type);
static int data_set   (data_t *data, int type, const void *arg);


static int encode_integer(data_t *data, int integer_value)
{
	unsigned char *buffer;
	int length;

	buffer = data->buffer;
	if (integer_value < -8388608 || integer_value > 8388607)
		length = 4;
	else if (integer_value < -32768 || integer_value > 32767)
		length = 3;
	else if (integer_value < -128 || integer_value > 127)
		length = 2;
	else
		length = 1;

	*buffer++ = BER_TYPE_INTEGER;
	*buffer++ = length;
	while (length--)
		*buffer++ = ((unsigned int)integer_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_ipaddress(data_t *data, int ipaddress)
{
	unsigned char *buffer;
	int length = 4;

	buffer = data->buffer;

	*buffer++ = BER_TYPE_IP_ADDRESS;
	*buffer++ = length;
	while (length--)
		*buffer++ = (ipaddress >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_string(data_t *data, const char *string)
{
	size_t len;
	unsigned char *buffer;

	if (!string)
		return 2;

	len = strlen(string);
	if ((len + 4) > data->max_length) {
		data->max_length = len + 4;
		data->buffer = realloc(data->buffer, data->max_length);
		if (!data->buffer)
			return 2;
	}

	if (len > 0xFFFF) {
		lprintf(LOG_ERR, "Failed encoding '%s': string overflow\n", string);
		return -1;
	}

	buffer    = data->buffer;
	*buffer++ = BER_TYPE_OCTET_STRING;
	if (len > 255) {
		*buffer++ = 0x82;
		*buffer++ = (len >> 8) & 0xFF;
		*buffer++ = len & 0xFF;
	} else if (len > 127) {
		*buffer++ = 0x81;
		*buffer++ = len & 0xFF;
	} else {
		*buffer++ = len & 0x7F;
	}

	while (*string)
		*buffer++ = (unsigned char)(*string++);

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_string_mac(data_t *data, const char *string)
{
	const size_t len = 6; // length of MAC
	int ctr = len;
	unsigned char *buffer;

	if (!string)
		return 2;

	if ((len + 4) > data->max_length) {
		data->max_length = len + 4;
		data->buffer = realloc(data->buffer, data->max_length);
		if (!data->buffer)
			return 2;
	}

	buffer    = data->buffer;
	*buffer++ = BER_TYPE_OCTET_STRING;
	*buffer++ = len & 0x7F;

	while (--ctr >= 0)
		*buffer++ = (unsigned char)(*string++);

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_oid(data_t *data, const oid_t *oid)
{
	size_t i, len = 1;
	unsigned char *buffer = data->buffer;

	if (!oid)
		return 2;

	for (i = 2; i < oid->subid_list_length; i++) {
		if (oid->subid_list[i] >= (1 << 28))
			len += 5;
		else if (oid->subid_list[i] >= (1 << 21))
			len += 4;
		else if (oid->subid_list[i] >= (1 << 14))
			len += 3;
		else if (oid->subid_list[i] >= (1 << 7))
			len += 2;
		else
			len += 1;
	}

	if (len > 0xFFFF) {
		lprintf(LOG_ERR, "Failed encoding '%s': OID overflow\n", oid_ntoa(oid));
		return -1;
	}

	*buffer++ = BER_TYPE_OID;
	if (len > 0xFF) {
		*buffer++ = 0x82;
		*buffer++ = (len >> 8) & 0xFF;
		*buffer++ = len & 0xFF;
	} else if (len > 0x7F) {
		*buffer++ = 0x81;
		*buffer++ = len & 0xFF;
	} else {
		*buffer++ = len & 0x7F;
	}

	*buffer++ = oid->subid_list[0] * 40 + oid->subid_list[1];
	for (i = 2; i < oid->subid_list_length; i++) {
		if (oid->subid_list[i] >= (1 << 28))
			len = 5;
		else if (oid->subid_list[i] >= (1 << 21))
			len = 4;
		else if (oid->subid_list[i] >= (1 << 14))
			len = 3;
		else if (oid->subid_list[i] >= (1 << 7))
			len = 2;
		else
			len = 1;

		while (len--) {
			if (len)
				*buffer++ = ((oid->subid_list[i] >> (7 * len)) & 0x7F) | 0x80;
			else
				*buffer++ = (oid->subid_list[i] >> (7 * len)) & 0x7F;
		}
	}

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_unsigned(data_t *data, int type, unsigned int ticks_value)
{
	unsigned char *buffer;
	int length;

	buffer = data->buffer;
	if (ticks_value & 0xFF800000)
		length = 4;
	else if (ticks_value & 0x007F8000)
		length = 3;
	else if (ticks_value & 0x00007F80)
		length = 2;
	else
		length = 1;

	*buffer++ = type;
	*buffer++ = length;
	while (length--)
		*buffer++ = (ticks_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_unsigned64(data_t *data, int type, uint64_t ticks_value)
{
	unsigned char *buffer;
	int length;

	buffer = data->buffer;
	if (ticks_value & 0xFF80000000000000ULL)
		length = 8;
	else if (ticks_value & 0x007F800000000000ULL)
		length = 7;
	else if (ticks_value & 0x00007F8000000000ULL)
		length = 6;
	else if (ticks_value & 0x0000007F80000000ULL)
		length = 5;
	else if (ticks_value & 0x000000007F800000ULL)
		length = 4;
	else if (ticks_value & 0x00000000007F8000ULL)
		length = 3;
	else if (ticks_value & 0x0000000000007F80ULL)
		length = 2;
	else
		length = 1;

	*buffer++ = type;
	*buffer++ = length;
	while (length--)
		*buffer++ = (ticks_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int mib_build_ip_entry(const oid_t *prefix, int type, const void *arg)
{
	int ret;
	value_t *value;
	const char *msg = "Failed creating MIB entry";
	const char *msg2 = "Failed assigning value to OID";

	/* Create a new entry in the MIB table */
	if (g_mib_length >= MAX_NR_VALUES) {
		lprintf(LOG_ERR, "%s '%s': table overflow\n", msg, oid_ntoa(prefix));
		return -1;
	}

	value = &g_mib[g_mib_length++];
	memcpy(&value->oid, prefix, sizeof(value->oid));

	ret  = encode_oid_len(&value->oid);
	ret += data_alloc(&value->data, type);
	if (ret) {
		lprintf(LOG_ERR, "%s '%s': unsupported type %d\n", msg,
			oid_ntoa(&value->oid), type);
		return -1;
	}

	ret = data_set(&value->data, type, arg);
	if (ret) {
		if (ret == 1)
			lprintf(LOG_ERR, "%s '%s': unsupported type %d\n", msg2, oid_ntoa(&value->oid), type);
		else if (ret == 2)
			lprintf(LOG_ERR, "%s '%s': invalid default value\n", msg2, oid_ntoa(&value->oid));

		return -1;
	}

	return 0;
}

static value_t *mib_alloc_entry(const oid_t *prefix, int column, int row, int type)
{
	int ret;
	value_t *value;
	const char *msg = "Failed creating MIB entry";

	/* Create a new entry in the MIB table */
	if (g_mib_length >= MAX_NR_VALUES) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': table overflow\n", msg, oid_ntoa(prefix), column, row);
		return NULL;
	}

	value = &g_mib[g_mib_length++];
	memcpy(&value->oid, prefix, sizeof(value->oid));

	/* Create the OID from the prefix, the column and the row */
	if (oid_build(&value->oid, prefix, column, row)) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': oid overflow\n", msg, oid_ntoa(prefix), column, row);
		return NULL;
	}

	ret  = encode_oid_len(&value->oid);
	ret += data_alloc(&value->data, type);
	if (ret) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': unsupported type %d\n", msg,
			oid_ntoa(&value->oid), column, row, type);
		return NULL;
	}

	return value;
}

static int mib_data_set(const oid_t *oid, data_t *data, int column, int row, int type, const void *arg);

static int mib_build_entry(const oid_t *prefix, int column, int row, int type, const void *arg)
{
	value_t *value;

	value = mib_alloc_entry(prefix, column, row, type);
	if (!value)
		return -1;

	return mib_data_set(&value->oid, &value->data, column, row, type, arg);
}

static int mib_data_set(const oid_t *oid, data_t *data, int column, int row, int type, const void *arg)
{
	int ret;
	const char *msg = "Failed assigning value to OID";

	ret = data_set(data, type, arg);
	if (ret) {
		if (ret == 1)
			lprintf(LOG_ERR, "%s '%s.%d.%d': unsupported type %d\n", msg, oid_ntoa(oid), column, row, type);
		else if (ret == 2)
			lprintf(LOG_ERR, "%s '%s.%d.%d': invalid default value\n", msg, oid_ntoa(oid), column, row);

		return -1;
	}

	return 0;
}

/* Create OID from the given prefix, column, and row */
static int oid_build(oid_t *oid, const oid_t *prefix, int column, int row)
{
	memcpy(oid, prefix, sizeof(*oid));

	if (oid->subid_list_length >= MAX_NR_SUBIDS)
		return -1;

	oid->subid_list[oid->subid_list_length++] = column;

	if (oid->subid_list_length >= MAX_NR_SUBIDS)
		return -1;

	oid->subid_list[oid->subid_list_length++] = row;

	return 0;
 }

/*
 * Calculate the encoded length of the created OID (note: first the length
 * of the subid list, then the length of the length/type header!)
 */
static int encode_oid_len(oid_t *oid)
{
	uint32_t len = 1;
	size_t i;

	for (i = 2; i < oid->subid_list_length; i++) {
		if (oid->subid_list[i] >= (1 << 28))
			len += 5;
		else if (oid->subid_list[i] >= (1 << 21))
			len += 4;
		else if (oid->subid_list[i] >= (1 << 14))
			len += 3;
		else if (oid->subid_list[i] >= (1 << 7))
			len += 2;
		else
			len += 1;
	}

	if (len > 0xFFFF) {
		lprintf(LOG_ERR, "Failed encoding '%s': OID overflow\n", oid_ntoa(oid));
		oid->encoded_length = -1;
		return -1;
	}

	if (len > 0xFF)
		len += 4;
	else if (len > 0x7F)
		len += 3;
	else
		len += 2;

	oid->encoded_length = (short)len;

	return 0;
}

/* Create a data buffer for the value depending on the type:
 *
 * - strings and oids are assumed to be static or have the maximum allowed length
 * - integers are assumed to be dynamic and don't have more than 32 bits
 */
static int data_alloc(data_t *data, int type)
{
	switch (type) {
		case BER_TYPE_INTEGER:
			data->max_length = sizeof(int) + 2;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_IP_ADDRESS:
			data->max_length = sizeof(uint32_t) + 2;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OCTET_STRING:
			data->max_length = 4;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OCTET_STRING_MAC:
			data->max_length = 10;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OID:
			data->max_length = MAX_NR_SUBIDS * 5 + 4;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_COUNTER64:
			data->max_length = sizeof(uint64_t) + 2;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_COUNTER:
		case BER_TYPE_GAUGE:
		case BER_TYPE_TIME_TICKS:
			data->max_length = sizeof(unsigned int) + 2;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		default:
			return -1;
	}

	if (!data->buffer)
		return -1;

	data->buffer[0] = type;
	data->buffer[1] = 0;
	data->buffer[2] = 0;
	data->encoded_length = 3;

	return 0;
}

/*
 * Set data buffer to its new value, depending on the type.
 *
 * Note: we assume the buffer was allocated to hold the maximum possible
 *       value when the MIB was built.
 */
static int data_set(data_t *data, int type, const void *arg)
{
	/* Make sure to always initialize the buffer, in case of error below. */
	memset(data->buffer, 0, data->max_length);

	switch (type) {
		case BER_TYPE_INTEGER:
			return encode_integer(data, (intptr_t)arg);

		case BER_TYPE_IP_ADDRESS:
			return encode_ipaddress(data, (uintptr_t)arg);

		case BER_TYPE_OCTET_STRING:
			return encode_string(data, (const char *)arg);

		case BER_TYPE_OCTET_STRING_MAC:
			return encode_string_mac(data, (const char *)arg);

		case BER_TYPE_OID:
			return encode_oid(data, oid_aton((const char *)arg));

		case BER_TYPE_COUNTER64:
			return encode_unsigned64(data, type, *((uint64_t *)arg));

		case BER_TYPE_COUNTER:
		case BER_TYPE_GAUGE:
		case BER_TYPE_TIME_TICKS:
			return encode_unsigned(data, type, (uintptr_t)arg);

		default:
			break;	/* Fall through */
	}

	return 1;
}

static int mib_build_entries(const oid_t *prefix, int column, int row_from, int row_to, int type)
{
	int row;

	for (row = row_from; row <= row_to; row++) {
		if (!mib_alloc_entry(prefix, column, row, type))
			return -1;
	}

	return 0;
}

static int mib_update_entry(const oid_t *prefix, int column, int row, size_t *pos, int type, const void *arg)
{
	oid_t oid;
	value_t *value;
	const char *msg = "Failed updating OID";

	memcpy(&oid, prefix, sizeof(oid));

	/* Create the OID from the prefix, the column and the row */
	if (oid_build(&oid, prefix, column, row)) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': OID overflow\n", msg, oid_ntoa(prefix), column, row);
		return -1;
	}

	/* Search the MIB for the given OID beginning at the given position */
	value = mib_find(&oid, pos);
	if (!value) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': OID not found\n", msg, oid_ntoa(prefix), column, row);
		return -1;
	}

	return mib_data_set(prefix, &value->data, column, row, type, arg);
}


/* -----------------------------------------------------------------------------
 * Interface functions
 *
 * To extend the MIB, add the relevant mib_build_entry() calls (to add one MIB
 * variable) or mib_build_entries() calls (to add a column of a MIB table) in
 * the mib_build() function. Note that building the MIB must be done strictly in
 * ascending OID order or the SNMP getnext/getbulk functions will not work as
 * expected!
 *
 * To extend the MIB, add the relevant mib_update_entry() calls (to update one
 * MIB variable or one cell in a MIB table) in the mib_update() function. Note
 * that the MIB variables must be added in the correct order (i.e. ascending).
 * How to get the value for that variable is up to you, but bear in mind that
 * the mib_update() function is called between receiving the request from the
 * client and sending back the response; thus you should avoid time-consuming
 * actions!
 *
 * The variable types supported up to now are OCTET_STRING, INTEGER (32 bit
 * signed), COUNTER (32 bit unsigned), TIME_TICKS (32 bit unsigned, in 1/10s)
 * and OID.
 *
 * Note that the maximum number of MIB variables is restricted by the length of
 * the MIB array, (see mini_snmpd.h for the value of MAX_NR_VALUES).
 */

int mib_build(void)
{
	char hostname[MAX_STRING_SIZE];
	char name[16];
	size_t i;
	int sysServices;

#if NDM
	if ((g_ndmresp = ndm_core_request(g_ndmcore,
			NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
			"show system")) == NULL)
	{
		lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));

		exit(EXIT_SYSCALL);
	}

	if (!ndm_core_response_is_ok(g_ndmresp)) {
		lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);

		exit(EXIT_SYSCALL);
	} else
	{
		const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

		if (root == NULL) {
			lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);

			exit(EXIT_SYSCALL);
		} else {
			if( ndm_xml_node_type(root) == NDM_XML_NODE_TYPE_ELEMENT )
			{
				if( !strcmp(ndm_xml_node_name(root), "response") )
				{
					const struct ndm_xml_node_t* node =
						ndm_xml_node_first_child(root, NULL);

					while (node != NULL) {
						if( !strcmp(ndm_xml_node_name(node), "hostname") )
						{
							strncpy(hostname, ndm_xml_node_value(node), sizeof(hostname) - 2);
							hostname[sizeof(hostname) - 1] = '\0';

							break;
						}
						node = ndm_xml_node_next_sibling(node, NULL);
					}
				}
			}
		}
	}
	ndm_core_response_free(&g_ndmresp);
#else
	/* Determine some static values that are not known at compile-time */
	if (gethostname(hostname, sizeof(hostname)) == -1)
		hostname[0] = '\0';
	else if (hostname[sizeof(hostname) - 1] != '\0')
		hostname[sizeof(hostname) - 1] = '\0';
#endif

	/*
	 * The system MIB: basic info about the host (SNMPv2-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	sysServices = 1 /* Physical layer */ + 
				(1 << 1) /* L2 Datalink layer */ +
				(1 << 2) /* L3 IP Layer */ +
				(1 << 3) /* L4 TCP/UDP Layer */ +
				(1 << 6) /* Applications layer */;
	
	if (mib_build_entry(&m_system_oid, 1, 0, BER_TYPE_OCTET_STRING, g_description ?: "") == -1 ||
	    mib_build_entry(&m_system_oid, 2, 0, BER_TYPE_OID,          g_vendor )           == -1 ||
	   !mib_alloc_entry(&m_system_oid, 3, 0, BER_TYPE_TIME_TICKS)                              ||
	    mib_build_entry(&m_system_oid, 4, 0, BER_TYPE_OCTET_STRING, g_contact ?: "")     == -1 ||
	    mib_build_entry(&m_system_oid, 5, 0, BER_TYPE_OCTET_STRING, hostname)            == -1 ||
	    mib_build_entry(&m_system_oid, 6, 0, BER_TYPE_OCTET_STRING, g_location ?: "")    == -1 ||
	    mib_build_entry(&m_system_oid, 7, 0, BER_TYPE_INTEGER, (const void *)(intptr_t)sysServices) == -1)
		return -1;

	/*
	 * The interface MIB: network interfaces (IF-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
#ifdef NDM

	for(i = 0; i < MAX_NR_INTERFACES; ++i) {
		g_interface_name_list[i] = NULL;
		g_interface_list[i] = NULL;
		g_interface_descr_list[i] = NULL;
	}

	g_interface_list_length = 1;
	g_interface_list[NDM_LOOPBACK_INDEX_] = strdup(NDM_LOOPBACK_IFACE_);
	g_interface_name_list[NDM_LOOPBACK_INDEX_] = strdup("");
	g_interface_descr_list[NDM_LOOPBACK_INDEX_] = strdup("");
	g_interface_type[NDM_LOOPBACK_INDEX_] = 24; // softwareLoopback(24)
	g_interface_mtu[NDM_LOOPBACK_INDEX_] = NDM_LOOPBACK_MTU_;
	g_interface_mac[NDM_LOOPBACK_INDEX_] = strdup(NDM_EMPTY_MAC_);
	g_interface_ip_address[NDM_LOOPBACK_INDEX_] = 0x7F000001;
	g_interface_ip_mask[NDM_LOOPBACK_INDEX_] = 0xFF000000;

	if ((g_ndmresp = ndm_core_request(g_ndmcore,
			NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
			"show interface")) == NULL)
	{
		lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));
		ndm_core_response_free(&g_ndmresp);

		exit(EXIT_SYSCALL);
	}

	if (!ndm_core_response_is_ok(g_ndmresp)) {
		lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);
		ndm_core_response_free(&g_ndmresp);

		exit(EXIT_SYSCALL);
	} else
	{
		const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

		if (root == NULL) {
			lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		} else {
			if( ndm_xml_node_type(root) == NDM_XML_NODE_TYPE_ELEMENT )
			{
				if( !strcmp(ndm_xml_node_name(root), "response") )
				{
					const struct ndm_xml_node_t* node =
						ndm_xml_node_first_child(root, NULL);

					while (node != NULL) {
						if( !strcmp(ndm_xml_node_name(node), "interface") )
						{
							g_interface_list_length++;

							if( ndm_xml_node_type(node) == NDM_XML_NODE_TYPE_ELEMENT )
							{
								const struct ndm_xml_node_t* cnode =
									ndm_xml_node_first_child(node, NULL);
								int has_mac = 0;
								int has_ip = 0;
								int has_mask = 0;
								size_t j = g_interface_list_length - 1;
								g_interface_mtu[j] = NDM_MIN_MTU_;
								const struct ndm_xml_attr_t* nameattr = 
									ndm_xml_node_first_attr(node, "name");

								if (nameattr != NULL &&
									!strcmp(ndm_xml_attr_name(nameattr), "name") &&
									strlen(ndm_xml_attr_value(nameattr)) > 0 )
								{
									g_interface_name_list[j] = strdup(ndm_xml_attr_value(nameattr));
								} else
								{
									g_interface_name_list[j] = NULL;
								}

								while (cnode != NULL) {
									if( !strcmp(ndm_xml_node_name(cnode), "id") )
									{
										g_interface_list[j] =
											strdup(ndm_xml_node_value(cnode));
									}

									if( !strcmp(ndm_xml_node_name(cnode), "description") )
									{
										g_interface_descr_list[j] =
											strdup(ndm_xml_node_value(cnode));
									}

									if( !strcmp(ndm_xml_node_name(cnode), "type") )
									{
										if( !strcmp(ndm_xml_node_value(cnode), "FastEthernet") ||
											!strcmp(ndm_xml_node_value(cnode), "GigabitEthernet") ||
											!strcmp(ndm_xml_node_value(cnode), "AccessPoint") ||
											!strcmp(ndm_xml_node_value(cnode), "WifiStation") ||
											!strcmp(ndm_xml_node_value(cnode), "Port") ||
											!strcmp(ndm_xml_node_value(cnode), "AsixEthernet") ||
											!strcmp(ndm_xml_node_value(cnode), "Davicom") ||
											!strcmp(ndm_xml_node_value(cnode), "UsbLte") ||
											!strcmp(ndm_xml_node_value(cnode), "YotaOne") ||
											!strcmp(ndm_xml_node_value(cnode), "CdcEthernet") )
										{
											g_interface_type[j] = 6; // ethernetCsmacd(6),

											if( !strcmp(ndm_xml_node_value(cnode), "Port") )
											{
												g_interface_mtu[j] = NDM_ETH_MTU_;
											}

										} else
										if( !strcmp(ndm_xml_node_value(cnode), "L2TP") ||
											!strcmp(ndm_xml_node_value(cnode), "PPTP") || 
											!strcmp(ndm_xml_node_value(cnode), "PPPoE") ||
											!strcmp(ndm_xml_node_value(cnode), "L2TPoverIPsec") )
										{
											g_interface_type[j] = 23; // ppp(23),
										} else
										if( !strcmp(ndm_xml_node_value(cnode), "WiMax") )
										{
											g_interface_type[j] = 237; // ieee80216WMAN (237),
										} else
										if( !strcmp(ndm_xml_node_value(cnode), "UsbDsl") ||
											!strcmp(ndm_xml_node_value(cnode), "Adsl") )
										{
											g_interface_type[j] = 238; // adsl2plus (238),
										} else
										if( !strcmp(ndm_xml_node_value(cnode), "Bridge") )
										{
											g_interface_type[j] = 209; // bridge (209),
										} else
										if( !strcmp(ndm_xml_node_value(cnode), "Vlan") )
										{
											g_interface_type[j] = 135; // l2vlan (135),
										} else
										if( !strcmp(ndm_xml_node_value(cnode), "WifiMaster") )
										{
											g_interface_type[j] = 253; //capwapDot11Bss (253),
										} else
										{
											g_interface_type[j] = 1; //other(1),
										}
									}

									if( !strcmp(ndm_xml_node_name(cnode), "mtu") &&
										g_interface_mtu[j] == NDM_MIN_MTU_ )
									{
										int imtu = atoi(ndm_xml_node_value(cnode));

										if( imtu >= NDM_MIN_MTU_ && imtu <= NDM_MAX_MTU_ )
										{
											g_interface_mtu[j] = imtu;
										}
									}

									if( !strcmp(ndm_xml_node_name(cnode), "mac") )
									{
										has_mac = 1;
										g_interface_mac[j] = strdup(ndm_xml_node_value(cnode));
									}

									if( !strcmp(ndm_xml_node_name(cnode), "address") )
									{
										struct in_addr addr;

										if( inet_pton(AF_INET, ndm_xml_node_value(cnode), &addr) )
										{
											has_ip = 1;
											g_interface_ip_address[j] = ntohl(addr.s_addr);
										}
									}

									if( !strcmp(ndm_xml_node_name(cnode), "mask") )
									{
										struct in_addr mask;

										if( inet_pton(AF_INET, ndm_xml_node_value(cnode), &mask) )
										{
											has_mask = 1;
											g_interface_ip_mask[j] = ntohl(mask.s_addr);
										}
									}

									cnode = ndm_xml_node_next_sibling(cnode, NULL);
								}

								if( has_mac == 0 )
								{
									g_interface_mac[j] = strdup(NDM_EMPTY_MAC_);
								}

								if( has_ip == 0 )
								{
									g_interface_ip_address[j] = 0;
								}

								if( has_mask == 0 )
								{
									g_interface_ip_mask[j] = 0;
								}
							}
						}
						node = ndm_xml_node_next_sibling(node, NULL);
					}
				}
			}
		}
	}
	ndm_core_response_free(&g_ndmresp);

	if( g_interface_list_length == 0 ) {
		lprintf(LOG_ERR, "unable to acquire any interface");

		return -1;
	}

	for (i = 0; i < g_interface_list_length; ++i) {
		if (g_interface_list[i] == NULL) {
			lprintf(LOG_ERR, "unable to acquire interface %d", i);

			return -1;
		}
	}

	lprintf(LOG_INFO, "build IF-MIB for %d interfaces", g_interface_list_length);

	if (mib_build_entry(&m_if_1_oid, 1, 0, BER_TYPE_INTEGER, (const void *)(intptr_t)g_interface_list_length) == -1)
		return -1;

	/* ifIndex -- XXX: Should be system ifindex! */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
			return -1;
	}

	/* ifDescription */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 2, i + 1, BER_TYPE_OCTET_STRING, g_interface_list[i]) == -1)
			return -1;
	}

	/* ifType: ENUM  */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 3, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)g_interface_type[i]) == -1)
			return -1;
	}

	/* ifMtu */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 4, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)g_interface_mtu[i]) == -1)
			return -1;
	}

	/* ifSpeed (in bps) */
	for (i = 0; i < g_interface_list_length; i++) {
		if( g_interface_type[i] == 6 /* ethernet */ )
		{
			/* 100 Mbps by default */
			if (mib_build_entry(&m_if_2_oid, 5, i + 1, BER_TYPE_GAUGE, (const void *)(intptr_t)100000000) == -1)
				return -1;
		} else
		if( g_interface_type[i] == 23 /* ppp */ ||
			g_interface_type[i] == 237 /* wimax */ ||
			g_interface_type[i] == 238 /* adsl */ ||
			g_interface_type[i] == 209 /* bridge */ ||
			g_interface_type[i] == 135 /* vlan */ ||
			g_interface_type[i] == 253 /* wifimaster */ ||
			g_interface_type[i] == 24 /* softwareLoopback(24) */ ||
			g_interface_type[i] == 1 /* other */ )
		{
			/* unspecified */
			if (mib_build_entry(&m_if_2_oid, 5, i + 1, BER_TYPE_GAUGE, (const void *)(intptr_t)0) == -1)
				return -1;
		} else
		{
			if (mib_build_entry(&m_if_2_oid, 5, i + 1, BER_TYPE_GAUGE, (const void *)(intptr_t)0) == -1)
				return -1;
		}
	}

	/* ifPhysAddress */
	for (i = 0; i < g_interface_list_length; i++) {
		unsigned char mac[7] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		char *saveptr, *res, *ptr;
		size_t j;

		ptr = g_interface_mac[i];

		j = 0;
		while( (res = strtok_r(ptr, ":", &saveptr)) && (j < 6) )
		{
			ptr = NULL;
			long int val = strtol(res, NULL, 16);

			if( val > 255 )
			{
				lprintf(LOG_ERR, "incorrect mac address: %s", g_interface_mac[i]);
			} else
			{
				mac[j] = val & 0xFF;
				++j;
			} 
		}

		if( j < 6 )
		{
			lprintf(LOG_ERR, "too short mac address: %s", g_interface_mac[i]);
		}

		if (mib_build_entry(&m_if_2_oid, 6, i + 1, BER_TYPE_OCTET_STRING_MAC, mac) == -1)
			return -1;
	}

	/* ifAdminStatus: up(1), down(2), testing(3) */
	for (i = 0; i < g_interface_list_length; i++) {
		/* Down by default */
		if (mib_build_entry(&m_if_2_oid, 7, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)2) == -1)
			return -1;
	}

	/* ifOperStatus: up(1), down(2), testing(3), unknown(4), dormant(5), notPresent(6), lowerLayerDown(7) */
	for (i = 0; i < g_interface_list_length; i++) {
		/* Down by default */
		if (mib_build_entry(&m_if_2_oid, 8, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)2) == -1)
			return -1;
	}

	/* ifLastChange */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 9, i + 1, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)0) == -1)
			return -1;
	}

	if (mib_build_entries(&m_if_2_oid, 10, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 11, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 13, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 14, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 16, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 17, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 19, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries(&m_if_2_oid, 20, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1)
		return -1;

#else
	if (g_interface_list_length > 0) {
		if (mib_build_entry(&m_if_1_oid, 1, 0, BER_TYPE_INTEGER, (const void *)(intptr_t)g_interface_list_length) == -1)
			return -1;

		/* ifIndex -- XXX: Should be system ifindex! */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
				return -1;
		}

		/* ifDescription */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 2, i + 1, BER_TYPE_OCTET_STRING, g_interface_list[i]) == -1)
				return -1;
		}

		/* ifType: ENUM, ethernetCsmacd(6) <-- recommended for all types of Ethernets */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 3, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)6) == -1)
				return -1;
		}

		/* ifMtu */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 4, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1500) == -1)
				return -1;
		}

		/* ifSpeed (in bps) */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 5, i + 1, BER_TYPE_GAUGE, (const void *)(intptr_t)1000000000) == -1)
				return -1;
		}

		/* ifPhysAddress */
		for (i = 0; i < g_interface_list_length; i++) {
			unsigned char mac[] = { 0xc0, 0xff, 0xee, 0xde, 0xad, i + 1, 0x00 };

			if (mib_build_entry(&m_if_2_oid, 6, i + 1, BER_TYPE_OCTET_STRING_MAC, mac) == -1)
				return -1;
		}

		/* ifAdminStatus: up(1), down(2), testing(3) */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 7, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1) == -1)
				return -1;
		}

		/* ifOperStatus: up(1), down(2), testing(3), unknown(4), dormant(5), notPresent(6), lowerLayerDown(7) */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 8, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1) == -1)
				return -1;
		}

		/* ifLastChange */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 9, i + 1, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)0) == -1)
				return -1;
		}

		if (mib_build_entries(&m_if_2_oid, 10, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 11, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 13, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 14, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 16, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 17, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 19, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 20, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1)
			return -1;
	}
#endif

	/*
	 * The IP-MIB.
	 */

	if (!mib_alloc_entry(&m_ip_oid,  1, 0, BER_TYPE_INTEGER)   ||
	    !mib_alloc_entry(&m_ip_oid,  2, 0, BER_TYPE_INTEGER)   ||
	    !mib_alloc_entry(&m_ip_oid, 13, 0, BER_TYPE_INTEGER) )
		return -1;

	{
		size_t j;
		oid_t m_ip_adentryaddr_oid    = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 0, 0, 0, 0 },  14, 15  };
		oid_t m_ip_adentryifidx_oid   = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 2, 0, 0, 0, 0 },  14, 15  };
		oid_t m_ip_adentrynetmask_oid = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 3, 0, 0, 0, 0 },  14, 15  };
		oid_t m_ip_adentrybcaddr_oid  = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 4, 0, 0, 0, 0 },  14, 15  };

		for (i = 0; i < g_interface_list_length; ++i) {
			if( g_interface_ip_address[i] != 0 &&
				g_interface_ip_mask[i] != 0 ) {
				uint32_t ip = g_interface_ip_address[i];

				for (j = 0; j < 4; ++j) {
					m_ip_adentryaddr_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));
				}

				if (mib_build_ip_entry(&m_ip_adentryaddr_oid, BER_TYPE_IP_ADDRESS,
					(const void *)(intptr_t)(g_interface_ip_address[i])) == -1) {
					return -1;
				}
			}
		}

		for (i = 0; i < g_interface_list_length; ++i) {
			if( g_interface_ip_address[i] != 0 &&
				g_interface_ip_mask[i] != 0 ) {
				uint32_t ip = g_interface_ip_address[i];

				for (j = 0; j < 4; ++j) {
					m_ip_adentryifidx_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));
				}

				if (mib_build_ip_entry(&m_ip_adentryifidx_oid, BER_TYPE_INTEGER,
					(const void *)(intptr_t)(i)) == -1) {
					return -1;
				}
			}
		}

		for (i = 0; i < g_interface_list_length; ++i) {
			if( g_interface_ip_address[i] != 0 &&
				g_interface_ip_mask[i] != 0 ) {
				uint32_t ip = g_interface_ip_address[i];

				for (j = 0; j < 4; ++j) {
					m_ip_adentrynetmask_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));
				}

				if (mib_build_ip_entry(&m_ip_adentrynetmask_oid, BER_TYPE_IP_ADDRESS,
					(const void *)(intptr_t)(g_interface_ip_mask[i])) == -1) {
					return -1;
				}
			}
		}

		for (i = 0; i < g_interface_list_length; ++i) {
			if( g_interface_ip_address[i] != 0 &&
				g_interface_ip_mask[i] != 0 ) {
				uint32_t ip = g_interface_ip_address[i];

				for (j = 0; j < 4; ++j) {
					m_ip_adentrybcaddr_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));
				}

				if (mib_build_ip_entry(&m_ip_adentrybcaddr_oid, BER_TYPE_INTEGER,
					(const void *)(intptr_t)(1)) == -1) {
					return -1;
				}
			}
		}

	}

	/*
	 * The TCP-MIB.
	 */

	if (!mib_alloc_entry(&m_tcp_oid,  1, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  2, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  3, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  4, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  5, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  6, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  7, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  8, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  9, 0, BER_TYPE_GAUGE)    ||
	    !mib_alloc_entry(&m_tcp_oid, 10, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 11, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 12, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 14, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 15, 0, BER_TYPE_COUNTER) )
		return -1;

	/*
	 * The UDP-MIB.
	 */

	if (!mib_alloc_entry(&m_udp_oid,  1, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  2, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  3, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  4, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  8, 0, BER_TYPE_COUNTER64) ||
	    !mib_alloc_entry(&m_udp_oid,  9, 0, BER_TYPE_COUNTER64) ) {
		return -1;
	}

	/*
	 * The host MIB: additional host info (HOST-RESOURCES-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_host_oid, 1, 0, BER_TYPE_TIME_TICKS))
		return -1;

	/*
	 * IF-MIB continuation
	 * ifXTable
	 */

	if (g_interface_list_length > 0) {

		/* ifName */
		for (i = 0; i < g_interface_list_length; i++) {
			const char *ifname = NULL;

			if (g_interface_name_list[i] == NULL || !strcmp(g_interface_name_list[i], "")) {
				ifname = g_interface_list[i];
			} else {
				ifname = g_interface_name_list[i];
			}

			if (mib_build_entry(&m_if_ext_oid, 1, i + 1, BER_TYPE_OCTET_STRING, ifname) == -1)
				return -1;
		}

		/* Just a counters */

		if (mib_build_entries(&m_if_ext_oid, 2, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
			mib_build_entries(&m_if_ext_oid, 3, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
			mib_build_entries(&m_if_ext_oid, 4, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
			mib_build_entries(&m_if_ext_oid, 5, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
			mib_build_entries(&m_if_ext_oid, 6, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 7, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 8, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 9, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 10, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 11, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 12, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
			mib_build_entries(&m_if_ext_oid, 13, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1)
			return -1;

		/* ifLinkUpDownTrapEnable */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_ext_oid, 14, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)2 /* disabled */) == -1)
				return -1;
		}

		/* ifHighSpeed */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_ext_oid, 15, i + 1, BER_TYPE_GAUGE, (const void *)(intptr_t)0) == -1) {
				return -1;
			}
		}

		/* ifPromiscuousMode */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_ext_oid, 16, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)2 /* false */) == -1)
				return -1;
		}

		/* ifConnectorPresent */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_ext_oid, 17, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1 /* true */) == -1)
				return -1;
		}

		/* ifAlias */
		for (i = 0; i < g_interface_list_length; i++) {
			const char *ifname = NULL;

			if (g_interface_descr_list[i] == NULL || !strcmp(g_interface_descr_list[i], "")) {
				if (g_interface_name_list[i] == NULL || !strcmp(g_interface_name_list[i], "")) {
					ifname = g_interface_list[i];
				} else {
					ifname = g_interface_name_list[i];
				}
			} else {
				ifname = g_interface_descr_list[i];
			}

			if (mib_build_entry(&m_if_ext_oid, 18, i + 1, BER_TYPE_OCTET_STRING, ifname) == -1)
				return -1;
		}

		/* ifCounterDiscontinuityTime */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_ext_oid, 19, i + 1, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)0) == -1)
				return -1;
		}
	}

	/*
	 * The memory MIB: total/free memory (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_memory_oid,  5, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid,  6, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid, 13, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid, 14, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid, 15, 0, BER_TYPE_INTEGER))
		return -1;

	/*
	 * The disk MIB: mounted partitions (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */

#ifdef NDM
	/* Dynamically populate mounted disks list */
	g_disk_list_length = 0;

	{
		DIR* dirp = opendir(NDM_MOUNT_PATH_);

		if( dirp != NULL )
		{
			struct dirent* dire = NULL;
			while( (dire = readdir(dirp)) )
			{
				struct stat st;
				char pathbuf[512];

				if (dire->d_name[0] == '.') {
					continue;
				}

				snprintf(pathbuf, sizeof(pathbuf), NDM_MOUNT_PATH_ "/%s/", dire->d_name);

				if ( !stat(pathbuf, &st) )
				{
					if( S_ISDIR(st.st_mode) )
					{
						++g_disk_list_length;
						g_disk_list[g_disk_list_length - 1] = strdup(pathbuf);
					}
				}
			}

			closedir(dirp);
		}
	}
#endif

	if (g_disk_list_length > 0) {

		lprintf(LOG_INFO, "build UCD-SNMP-MIB for %d disks", g_disk_list_length);

		for (i = 0; i < g_disk_list_length; i++) {
			if (mib_build_entry(&m_disk_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
				return -1;
		}

		for (i = 0; i < g_disk_list_length; i++) {
			if (mib_build_entry(&m_disk_oid, 2, i + 1, BER_TYPE_OCTET_STRING, g_disk_list[i]) == -1)
				return -1;
		}

		if (mib_build_entries(&m_disk_oid,  6, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid,  7, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid,  8, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid,  9, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid, 10, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1)
			return -1;
	}

	/*
	 * The load MIB: CPU load averages (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	for (i = 0; i < 3; i++) {
		if (mib_build_entry(&m_load_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
			return -1;
	}

	for (i = 0; i < 3; i++) {
		snprintf(name, sizeof(name), "Load-%d", m_load_avg_times[i]);
		if (mib_build_entry(&m_load_oid, 2, i + 1, BER_TYPE_OCTET_STRING, name) == -1)
			return -1;
	}

	if (mib_build_entries(&m_load_oid, 3, 1, 3, BER_TYPE_OCTET_STRING) == -1)
		return -1;

	for (i = 0; i < 3; i++) {
		snprintf(name, sizeof(name), "%d", m_load_avg_times[i]);
		if (mib_build_entry(&m_load_oid, 4, i + 1, BER_TYPE_OCTET_STRING, name) == -1)
			return -1;
	}

	if (mib_build_entries(&m_load_oid, 5, 1, 3, BER_TYPE_INTEGER) == -1)
		return -1;

	/* The CPU MIB: CPU statistics (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_cpu_oid, 50, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 51, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 52, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 53, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 59, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 60, 0, BER_TYPE_COUNTER))
		return -1;

	/* The demo MIB: two random integers
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
#ifdef CONFIG_ENABLE_DEMO
	if (!mib_alloc_entry(&m_demo_oid, 1, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_demo_oid, 2, 0, BER_TYPE_INTEGER))
		return -1;
#endif

	return 0;
}

int mib_update(int full)
{
	char nr[16];
	size_t i, pos;
	union {
		diskinfo_t diskinfo;
		loadinfo_t loadinfo;
		meminfo_t meminfo;
		ipinfo_t ipinfo;
		tcpinfo_t tcpinfo;
		udpinfo_t udpinfo;
		cpuinfo_t cpuinfo;
#ifdef CONFIG_ENABLE_DEMO
		demoinfo_t demoinfo;
#endif
	} u;
	netinfo_t netinfo;

	/* Begin searching at the first MIB entry */
	pos = 0;

	/*
	 * The system MIB: basic info about the host (SNMPv2-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (mib_update_entry(&m_system_oid, 3, 0, &pos, BER_TYPE_TIME_TICKS, (const void *)(uintptr_t)get_process_uptime()) == -1)
		return -1;

	/*
	 * The interface MIB: network interfaces (IF-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		if (g_interface_list_length > 0) {

			get_netinfo(&netinfo);

#ifdef NDM
			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 4, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)netinfo.mtu[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 5, i + 1, &pos, BER_TYPE_GAUGE, (const void *)(intptr_t)netinfo.speed[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 7, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)netinfo.admin_status[i]) == -1)
					return -1;
			}
#endif

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 8, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)netinfo.status[i]) == -1)
					return -1;
			}

#ifdef NDM
			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 9, i + 1, &pos, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)netinfo.last_change[i]) == -1)
					return -1;
			}
#endif

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 10, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_bytes[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 11, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_packets[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 13, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_drops[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 14, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_errors[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 16, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_bytes[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 17, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_packets[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 19, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_drops[i] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 20, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_errors[i] % UINT_MAX)) == -1)
					return -1;
			}
		}
	}

	/*
	 * IP-MIB
	 */

	if (full) {
		get_ipinfo(&u.ipinfo);

		if (mib_update_entry(&m_ip_oid,  1, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.ipinfo.ipForwarding)      == -1 ||
		    mib_update_entry(&m_ip_oid,  2, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.ipinfo.ipDefaultTTL)      == -1 ||
		    mib_update_entry(&m_ip_oid,  13, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.ipinfo.ipReasmTimeout)   == -1 )
		{
			return -1;
		}

	}

	/*
	 * TCP-MIB
	 */

	if (full) {
		get_tcpinfo(&u.tcpinfo);

		if (mib_update_entry(&m_tcp_oid,  1, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpRtoAlgorithm)   == -1 ||
		    mib_update_entry(&m_tcp_oid,  2, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpRtoMin)         == -1 ||
		    mib_update_entry(&m_tcp_oid,  3, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpRtoMax)         == -1 ||
		    mib_update_entry(&m_tcp_oid,  4, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpMaxConn)        == -1 ||
		    mib_update_entry(&m_tcp_oid,  5, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpActiveOpens)   == -1 ||
		    mib_update_entry(&m_tcp_oid,  6, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpPassiveOpens)  == -1 ||
		    mib_update_entry(&m_tcp_oid,  7, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpAttemptFails)  == -1 ||
		    mib_update_entry(&m_tcp_oid,  8, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpEstabResets)   == -1 ||
		    mib_update_entry(&m_tcp_oid,  9, 0, &pos, BER_TYPE_GAUGE, (const void *)(intptr_t)u.tcpinfo.tcpCurrEstab)        == -1 ||
		    mib_update_entry(&m_tcp_oid, 10, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpInSegs)        == -1 ||
		    mib_update_entry(&m_tcp_oid, 11, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpOutSegs)       == -1 ||
		    mib_update_entry(&m_tcp_oid, 12, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpRetransSegs)   == -1 ||
		    mib_update_entry(&m_tcp_oid, 14, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpInErrs)        == -1 ||
		    mib_update_entry(&m_tcp_oid, 15, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpOutRsts)       == -1)
			return -1;
	}

	/*
	 * UDP-MIB
	 */

	if (full) {
		get_udpinfo(&u.udpinfo);

		if (mib_update_entry(&m_udp_oid,  1, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(u.udpinfo.udpInDatagrams & 0xFFFFFFFF))   == -1 ||
		    mib_update_entry(&m_udp_oid,  2, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.udpinfo.udpNoPorts)                      == -1 ||
		    mib_update_entry(&m_udp_oid,  3, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.udpinfo.udpInErrors)                     == -1 ||
		    mib_update_entry(&m_udp_oid,  4, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(u.udpinfo.udpOutDatagrams & 0xFFFFFFFF))  == -1 ||
		    mib_update_entry(&m_udp_oid,  8, 0, &pos, BER_TYPE_COUNTER64, (const void *)(&u.udpinfo.udpInDatagrams))                        == -1 ||
		    mib_update_entry(&m_udp_oid,  9, 0, &pos, BER_TYPE_COUNTER64, (const void *)(&u.udpinfo.udpOutDatagrams))                       == -1  )
			return -1;
	}

	/*
	 * The host MIB: additional host info (HOST-RESOURCES-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (mib_update_entry(&m_host_oid, 1, 0, &pos, BER_TYPE_TIME_TICKS, (const void *)(uintptr_t)get_system_uptime()) == -1)
		return -1;

	/*
	 * IF-MIB
	 * ifXTable
	 */

	if (full) {
		if (g_interface_list_length > 0) {
			uint64_t val = 0;

			for (i = 0; i < g_interface_list_length; i++) {
				const char *ifname = NULL;

				if (g_interface_name_list[i] == NULL || !strcmp(g_interface_name_list[i], "")) {
					ifname = g_interface_list[i];
				} else {
					ifname = g_interface_name_list[i];
				}

				if (mib_update_entry(&m_if_ext_oid, 1, i + 1, &pos, BER_TYPE_OCTET_STRING, ifname) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.rx_mc_packets[i] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 2, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.rx_bc_packets[i] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 3, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.tx_mc_packets[i] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 4, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.tx_bc_packets[i] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 5, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_bytes[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 6, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_packets[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 7, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_mc_packets[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 8, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_bc_packets[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 9, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_bytes[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 10, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_packets[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 11, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_mc_packets[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 12, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_bc_packets[i] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 13, i + 1, &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_ext_oid, 15, i + 1, &pos, BER_TYPE_GAUGE, (const void *)(intptr_t)(netinfo.speed[i] / 1000000)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				int ifConnectorPresent = (netinfo.is_port[i] == 1 && netinfo.status[i] == 1) ? 1 : 2;

				if (mib_update_entry(&m_if_ext_oid, 17, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)ifConnectorPresent) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				const char *ifname = NULL;

				if (g_interface_descr_list[i] == NULL || !strcmp(g_interface_descr_list[i], "")) {
					if (g_interface_name_list[i] == NULL || !strcmp(g_interface_name_list[i], "")) {
						ifname = g_interface_list[i];
					} else {
						ifname = g_interface_name_list[i];
					}
				} else {
					ifname = g_interface_descr_list[i];
				}

				if (mib_update_entry(&m_if_ext_oid, 18, i + 1, &pos, BER_TYPE_OCTET_STRING, ifname) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_ext_oid, 19, i + 1, &pos, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)netinfo.discont_time[i]) == -1)
					return -1;
			}
		}
	}

	/*
	 * The memory MIB: total/free memory (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		get_meminfo(&u.meminfo);
		if (mib_update_entry(&m_memory_oid,  5, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.total)   == -1 ||
		    mib_update_entry(&m_memory_oid,  6, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.free)    == -1 ||
		    mib_update_entry(&m_memory_oid, 13, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.shared)  == -1 ||
		    mib_update_entry(&m_memory_oid, 14, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.buffers) == -1 ||
		    mib_update_entry(&m_memory_oid, 15, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.cached)  == -1)
			return -1;
	}

	/*
	 * The disk MIB: mounted partitions (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		if (g_disk_list_length > 0) {
			get_diskinfo(&u.diskinfo);
			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 6, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.total[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 7, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.free[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 8, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.used[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 9, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.blocks_used_percent[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 10, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.inodes_used_percent[i]) == -1)
					return -1;
			}
		}
	}

	/*
	 * The load MIB: CPU load averages (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		get_loadinfo(&u.loadinfo);
		for (i = 0; i < 3; i++) {
			snprintf(nr, sizeof(nr), "%d.%02d", u.loadinfo.avg[i] / 100, u.loadinfo.avg[i] % 100);
			if (mib_update_entry(&m_load_oid, 3, i + 1, &pos, BER_TYPE_OCTET_STRING, nr) == -1)
				return -1;
		}

		for (i = 0; i < 3; i++) {
			if (mib_update_entry(&m_load_oid, 5, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.loadinfo.avg[i]) == -1)
				return -1;
		}
	}

	/*
	 * The cpu MIB: CPU statistics (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		get_cpuinfo(&u.cpuinfo);
		if (mib_update_entry(&m_cpu_oid, 50, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.user)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 51, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.nice)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 52, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.system) == -1 ||
		    mib_update_entry(&m_cpu_oid, 53, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.idle)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 59, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.irqs)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 60, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.cntxts) == -1)
			return -1;
	}

	/*
	 * The demo MIB: two random integers (note: the random number is only
	 * updated every "g_timeout" seconds; if you want it updated every SNMP
	 * request, remove the enclosing "if" block).
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
#ifdef CONFIG_ENABLE_DEMO
	if (full) {
		get_demoinfo(&u.demoinfo);
		if (mib_update_entry(&m_demo_oid, 1, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.demoinfo.random_value_1) == -1 ||
		    mib_update_entry(&m_demo_oid, 2, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.demoinfo.random_value_2) == -1)
			return -1;
	}
#endif

	return 0;
}

/* Find the OID in the MIB that is exactly the given one or a subid */
value_t *mib_find(const oid_t *oid, size_t *pos)
{
	while (*pos < g_mib_length) {
		value_t *curr = &g_mib[*pos];
		size_t len = oid->subid_list_length * sizeof(oid->subid_list[0]);

		if (curr->oid.subid_list_length >= oid->subid_list_length &&
		    !memcmp(curr->oid.subid_list, oid->subid_list, len))
			return curr;
		*pos = *pos + 1;
	}

	return NULL;
}

/* Find the OID in the MIB that is the one after the given one */
value_t *mib_findnext(const oid_t *oid)
{
	size_t pos;

	for (pos = 0; pos < g_mib_length; pos++) {
		if (oid_cmp(&g_mib[pos].oid, oid) > 0)
			return &g_mib[pos];
	}

	return NULL;
}

/* vim: ts=4 sts=4 sw=4 nowrap
 */
