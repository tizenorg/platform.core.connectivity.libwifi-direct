/*
 * libwifi-direct
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#include "wifi-direct.h"
#include "wifi-direct-client-proxy.h"
#include "wifi-direct-internal.h"


char *wfd_print_state(wifi_direct_state_e s)
{
	switch (s)
	{
	case WIFI_DIRECT_STATE_DEACTIVATED:
		return "DEACTIVATED";
		break;

	case WIFI_DIRECT_STATE_DEACTIVATING:
		return "DEACTIVATING";
		break;
	case WIFI_DIRECT_STATE_ACTIVATING:
		return "ACTIVATING";
		break;
	case WIFI_DIRECT_STATE_ACTIVATED:
		return "ACTIVATED";
		break;
	case WIFI_DIRECT_STATE_DISCOVERING:
		return "DISCOVERING";
		break;
	case WIFI_DIRECT_STATE_CONNECTING:
		return "CONNECTING";
		break;
	case WIFI_DIRECT_STATE_DISCONNECTING:
		return "DISCONNECTING";
		break;
	case WIFI_DIRECT_STATE_CONNECTED:
		return "CONNECTED";
		break;
	case WIFI_DIRECT_STATE_GROUP_OWNER:
		return "GROUP OWNER";
		break;
	default:
		return "Unknown";
	}
}
