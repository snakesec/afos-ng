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

#define NRM "\033[0m"

#define BLD "\033[1m"

#define BLK "\033[1;90m"
#define RED "\033[1;91m"
#define GRN "\033[1;92m"
#define YEL "\033[1;93m"
#define BLU "\033[1;94m"
#define PUR "\033[1;95m"
#define CYN "\033[1;96m"
#define WHT "\033[1;97m"

extern int DEBUG;

char *lower(char *str_to_lower);
int createdb();
int readdb();
int help();
int update(int all);
int get_afos_packages(char *urltofetch, char *pagefilename);
int get_pkgs();
int repolist();
int install(char *query_name, int update_all);