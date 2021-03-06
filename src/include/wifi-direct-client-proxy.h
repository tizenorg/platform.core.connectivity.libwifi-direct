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

#ifndef __WIFI_DIRECT_CLIENT_PROXY_H_
#define __WIFI_DIRECT_CLIENT_PROXY_H_

/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/
#include <glib.h>

/*****************************************************************************
 * 	Wi-Fi Manager headers
 *****************************************************************************/
#include "wifi-direct.h"

/*****************************************************************************
 * 	Macro Definition
 *****************************************************************************/
#ifdef VITA_FEATURE
#include <dlog.h>

#define WFD_LOG_LOW     LOG_VERBOSE
#define WFD_LOG_HIGH    LOG_INFO
#define WFD_LOG_ERROR   LOG_ERROR
#define WFD_LOG_WARN    LOG_WARN
#define WFD_LOG_ASSERT  LOG_FATAL
#define WFD_LOG_EXCEPTION       LOG_FATAL

#define WFD_CLIENT_MID  "wfd-client"

char *wfd_trim_path(const char *filewithpath);

#define WFD_CLIENT_LOG(log_level, format, args...) \
        LOG(log_level, WFD_CLIENT_MID, "[%s:%04d] " format, wfd_trim_path(__FILE__), __LINE__, ##args)
#define __WFD_CLIENT_FUNC_START__       LOG(LOG_VERBOSE, WFD_CLIENT_MID, "[%s:%04d] Enter: %s()\n", wfd_trim_path(__FILE__), __LINE__,__func__)
#define __WFD_CLIENT_FUNC_END__ LOG(LOG_VERBOSE, WFD_CLIENT_MID, "[%s:%04d] Quit: %s()\n", wfd_trim_path(__FILE__), __LINE__,__func__)

#else /** _DLOG_UTIL */

#define WFD_CLIENT_LOG(log_level, format, args...)
#define __WFD_CLIENT_FUNC_START__
#define __WFD_CLIENT_FUNC_END__

#endif /** _DLOG_UTIL */

typedef struct
{
	bool is_registered;
	int client_id;
	int sync_sockfd;
	int async_sockfd;
	int g_client_info;
	int g_source_id;
	wifi_direct_device_state_changed_cb activation_cb;
	wifi_direct_discovery_state_chagned_cb discover_cb;
	wifi_direct_connection_state_changed_cb connection_cb;
	wifi_direct_client_ip_address_assigned_cb ip_assigned_cb;	
	void *user_data_for_cb_activation;
	void *user_data_for_cb_discover;
	void *user_data_for_cb_connection;
	void *user_data_for_cb_ip_assigned;

} wifi_direct_client_info_s;

extern char *wfd_debug_print(char *file, int line, char *format, ...);

#endif /** __WIFI_DIRECT_CLIENT_PROXY_H_ */
