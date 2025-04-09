/*
*******************************************************************************
*                                                                             *
* Copyright 2025 Weidsom Nascimento - SNAKE Security                          *
*                                                                             *
* Licensed under the Apache License, Version 2.0 (the "License");             *
* you may not use this file except in compliance with the License.            *
* You may obtain a copy of the License at                                     *
*                                                                             *
*     http://www.apache.org/licenses/LICENSE-2.0                              *
*                                                                             *
* Unless required by applicable law or agreed to in writing, software         *
* distributed under the License is distributed on an "AS IS" BASIS,           *
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    *
* See the License for the specific language governing permissions and         *
* limitations under the License.                                              *
*                                                                             *
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int is_valid_version(const char *version) {
    int dots = 0, dashes = 0;
    int has_digits = 0;
    int len = strlen(version);

    if (len == 0) return 0;

    for (int i = 0; i < len; i++) {
        if (isdigit(version[i])) {
            has_digits = 1;
        } else if (version[i] == '.') {
            dots++;
            if (dots > 2) return 0; 
            if (i == 0 || i == len - 1 || !isdigit(version[i - 1]) || !isdigit(version[i + 1])) {
                return 0; 
            }
        } else if (version[i] == '-') {
            dashes++;
            if (dashes > 1) return 0; 
            if (i == 0 || i == len - 1 || !isdigit(version[i + 1])) {
                return 0; 
            }
        } else {
            return 0;
        }
    }

    return (has_digits);
}

int afos_compare_versions(const char *v1, const char *v2) {
    if (!is_valid_version(v1) || !is_valid_version(v2)) {
        return -2;
    }

    int v1_major = 0, v1_minor = 0, v1_patch = 0, v1_extra = 0;
    int v2_major = 0, v2_minor = 0, v2_patch = 0, v2_extra = 0;

    sscanf(v1, "%d.%d.%d-%d", &v1_major, &v1_minor, &v1_patch, &v1_extra);
    sscanf(v2, "%d.%d.%d-%d", &v2_major, &v2_minor, &v2_patch, &v2_extra);

    if (v1_major < v2_major) return -1;
    if (v1_major > v2_major) return 1;

    if (v1_minor < v2_minor) return -1;
    if (v1_minor > v2_minor) return 1;

    if (v1_patch < v2_patch) return -1;
    if (v1_patch > v2_patch) return 1;

    if (v1_extra < v2_extra) return -1;
    if (v1_extra > v2_extra) return 1;

    return 0;
}