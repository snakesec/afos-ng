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

#include "afos.h"
#include <stdio.h>
#include <string.h>

int get_pkgs() {
    FILE* afossourcelist;
    int bufferLengthlist = 500;
    char buffer[bufferLengthlist];

    char default_repo[500] = "https://raw.githubusercontent.com/snakesec/afos-ng/refs/heads/main/repository/afos.yaml";

    char default_repo_testing[500] = "https://raw.githubusercontent.com/snakesec/afos-ng/refs/heads/testing/repository/afos.yaml";

    afossourcelist = fopen("/opt/AFOS/afos.list", "r");

    if(afossourcelist == NULL) {
        if(DEBUG) {
            printf("%s[%s %sERROR%s %s]%s Switching to default repo because no valid URL was provided\n", WHT, NRM, YEL, NRM, WHT, NRM);
        }
        if(TESTING) {
            get_afos_packages(default_repo_testing, "/opt/AFOS/afos_pkgs.yaml");
        } else {
            get_afos_packages(default_repo, "/opt/AFOS/afos_pkgs.yaml");
        }
    } else {
        int linen = 0;

        while(fgets(buffer, bufferLengthlist, afossourcelist)) {
            get_afos_packages(buffer, "/opt/AFOS/afos_pkgs.yaml");
        }

        fclose(afossourcelist);
    }


    return 0;
}
