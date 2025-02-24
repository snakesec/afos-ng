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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <curl/curl.h>

#include "afos.h"

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int get_afos_packages(char *urltofetch, char *file_to_save) {
    char urt_to_parse[500];

    strncpy(urt_to_parse, urltofetch, 499);

    CURL *curl_handle;
    FILE *pagefile;

    strtok(urt_to_parse, "\n");

    curl_global_init(CURL_GLOBAL_ALL);

    curl_handle = curl_easy_init();

    curl_easy_setopt(curl_handle, CURLOPT_URL, urt_to_parse);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "ANDRAX-NG AFOS-NG AFOS/1.0.0");
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);

    if(access(file_to_save, F_OK ) == 0 ) {
        if(DEBUG) {
            printf("%s[%s %sINFO%s %s]%s Removing old %s\n", WHT, NRM, CYN, NRM, WHT, NRM, file_to_save);
        }
        remove(file_to_save);
    }

    save_file_path = fopen(file_to_save, "ab");
    if(save_file_path) {
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, save_file_path);
        curl_easy_perform(curl_handle);
        fclose(save_file_path);
    }

    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();

    return 0;
}
