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

int help() {

    printf("AFOS-NG HELP:\n\n");
    printf("        --install, -i: [ Install or update packages ]\n");
    printf("        --update, -u: [ Check for updates ]\n");
    printf("        --update-all, -a: [ Update all packages ]\n");
    printf("        --list, -l: [ List installed packages by AFOS ]\n");
    printf("        --repo, -r: [ List packages on AFOS REPO ]\n");
    printf("        --notinstalled, -n: [ List all NOT installed packages ]\n");
    printf("        --debug, -d: [ Debug errors ]\n");
    printf("        --help, -h [ Show this help ]\n\n");

    return 0;
}
