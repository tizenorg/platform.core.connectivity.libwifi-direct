/*
 * libwifi-direct
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Sungsik Jang <sungsik.jang@samsung.com>, Dongwook Lee <dwmax.lee@samsung.com> 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __WIFI_DIRECT_INTERNAL_H_
#define __WIFI_DIRECT_INTERNAL_H_

#include "wifi-direct.h"


#define true 1
#define false 0

#define WFD_INVALID_ID	-1


#ifndef O_NONBLOCK
#define O_NONBLOCK  O_NDELAY
#endif /** O_NONBLOCK */


#ifndef _UINT32_TYPE_H_
#define _UINT32_TYPE_H_
typedef unsigned int uint32;
#endif /** _UINT32_TYPE_H_ */

typedef unsigned int ipv4_addr_t;

#ifndef TRUE
#define TRUE 1
#endif /** TRUE */

#ifndef FALSE
#define FALSE 0
#endif /** FALSE */

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]

#define IPSTR "%d.%d.%d.%d"

#define WIFI_DIRECT_MAX_SSID_LEN 32
#define WIFI_DIRECT_WPS_PIN_LEN 8
#define WIFI_DIRECT_MAC_ADDRESS_INFO_FILE "/opt/etc/.mac.info"

#define VCONFKEY_IFNAME "memory/private/wifi_direct_manager/p2p_ifname"
#define VCONFKEY_LOCAL_IP "memory/private/wifi_direct_manager/p2p_local_ip"
#define VCONFKEY_SUBNET_MASK "memory/private/wifi_direct_manager/p2p_subnet_mask"
#define VCONFKEY_GATEWAY "memory/private/wifi_direct_manager/p2p_gateway"

typedef enum
{
	WIFI_DIRECT_CMD_INVALID,
	WIFI_DIRECT_CMD_REGISTER,
	WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET,
	WIFI_DIRECT_CMD_DEREGISTER,
	WIFI_DIRECT_CMD_ACTIVATE,
	WIFI_DIRECT_CMD_DEACTIVATE,
	WIFI_DIRECT_CMD_START_DISCOVERY,
	WIFI_DIRECT_CMD_CANCEL_DISCOVERY,
	WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT,
	WIFI_DIRECT_CMD_GET_LINK_STATUS,
	WIFI_DIRECT_CMD_CONNECT,
	WIFI_DIRECT_CMD_DISCONNECT_ALL,
	WIFI_DIRECT_CMD_CREATE_GROUP,
	WIFI_DIRECT_CMD_IS_GROUPOWNER,
	WIFI_DIRECT_CMD_GET_SSID,
	WIFI_DIRECT_CMD_SET_SSID,
	WIFI_DIRECT_CMD_GET_IP_ADDR,
	WIFI_DIRECT_CMD_GET_CONFIG,
	WIFI_DIRECT_CMD_SET_CONFIG,
	WIFI_DIRECT_CMD_SEND_PROVISION_DISCOVERY_REQ,
	WIFI_DIRECT_CMD_SEND_CONNECT_REQ,
	WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON,
	WIFI_DIRECT_CMD_SET_WPS_PIN,
	WIFI_DIRECT_CMD_GET_WPS_PIN,
	WIFI_DIRECT_CMD_GENERATE_WPS_PIN,
	WIFI_DIRECT_CMD_GET_INCOMMING_PEER_INFO,
	WIFI_DIRECT_CMD_SET_WPA,
	WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE,
	WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE,
	WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO,
	WIFI_DIRECT_CMD_CANCEL_GROUP,
	WIFI_DIRECT_CMD_DISCONNECT,
	WIFI_DIRECT_CMD_SET_GO_INTENT,
	WIFI_DIRECT_CMD_GET_GO_INTENT,
	WIFI_DIRECT_CMD_GET_DEVICE_MAC,
	WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP,
	WIFI_DIRECT_CMD_SET_MAX_CLIENT,
	WIFI_DIRECT_CMD_GET_MAX_CLIENT,
	WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE,
	WIFI_DIRECT_CMD_IS_DISCOVERABLE,
	WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL,
	
	WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL,

	WIFI_DIRECT_CMD_MAX
} wifi_direct_cmd_e;

/**
 * Wi-Fi Direct client event for IPC
 */
typedef enum
{
	WIFI_DIRECT_CLI_EVENT_INVALID = -1,					/**< */

	WIFI_DIRECT_CLI_EVENT_ACTIVATION,						/**< */
	WIFI_DIRECT_CLI_EVENT_DEACTIVATION,					/**< */

	WIFI_DIRECT_CLI_EVENT_DISCOVER_START,				/**< 80211 scan*/
	WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY,	/**< listen only mode*/
	WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN,	/**< search, listen*/
	WIFI_DIRECT_CLI_EVENT_DISCOVER_END,					/**< */
	WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS,			/**< */

	WIFI_DIRECT_CLI_EVENT_CONNECTION_START,				/**< */
	WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ,				/**< */
	WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP,				/**< */
	WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ,			/**< */

	WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP,				/**< */
	WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND,				/**< */
	WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND,				/**< */

	WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP,				/**< */
	WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP,				/**< */

	WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND,				/**< */
} wfd_client_event_e;

/**
 * Wi-Fi Direct configuration data structure for IPC
 */
typedef struct
{
	char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];
	int channel;
	wifi_direct_wps_type_e wps_config;
	int max_clients;
	bool hide_SSID;
	int group_owner_intent;
	bool want_persistent_group;
	bool auto_connection;
	wifi_direct_primary_device_type_e primary_dev_type;
	wifi_direct_secondary_device_type_e secondary_dev_type;
} wfd_config_data_s;


/**
 * Wi-Fi Direct buffer structure to store result of peer discovery for IPC
 */
typedef struct
{
	bool is_group_owner;
	char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];
	unsigned char mac_address[6];
	int channel;
	bool is_connected;
	unsigned int services;
	bool is_persistent_go;
	unsigned char intf_mac_address[6];
	unsigned int wps_device_pwd_id;
	unsigned int wps_cfg_methods;
	unsigned int category;
	unsigned int subcategory;
	bool is_wfd_device	;
} wfd_discovery_entry_s;


/**
 * Wi-Fi Direct buffer structure to store information of connected peer
 */
typedef struct
{
	char ssid[WIFI_DIRECT_MAX_SSID_LEN + 1];
	unsigned char ip_address[4];
	unsigned char mac_address[6];
	unsigned char intf_mac_address[6];
	unsigned int services;
	bool is_p2p;
	unsigned short category;
	int channel;
} wfd_connected_peer_info_s;


typedef struct
{
	bool listen_only;
	int timeout;

	int peer_index;
	unsigned char mac_addr[6];

} wifi_direct_client_request_data_s;


typedef struct
{
	wifi_direct_cmd_e cmd;
	int client_id;
	wifi_direct_client_request_data_s data;
} wifi_direct_client_request_s;

typedef struct
{
	wifi_direct_cmd_e cmd;
	wifi_direct_error_e result;
	int client_id;
	int param1;
	char param2[64];
	char param3[32];
	int data_length;
} wifi_direct_client_response_s;

typedef struct
{
	wfd_client_event_e event;
	wifi_direct_error_e error;
	char param1[64];
	char param2[64];
} wifi_direct_client_noti_s;


#endif							//__WIFI_DIRECT_INTERNAL_H_
