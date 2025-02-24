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
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include "afos.h"

static char afos_banner[3171] = {
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x90, 0xe2, 0xa0, 0x82,
  0xe2, 0xa0, 0xa4, 0xe2, 0xa3, 0x84, 0xe2, 0xa3, 0x80, 0xe2, 0xa1, 0x80,
  0xe2, 0xa0, 0x90, 0xe2, 0xa0, 0x92, 0xe2, 0xa0, 0xa4, 0xe2, 0xa3, 0x84,
  0xe2, 0xa3, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x99, 0xe2, 0xa0, 0xbb, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3,
  0xa6, 0xe2, 0xa3, 0x84, 0xe2, 0xa3, 0x88, 0xe2, 0xa3, 0x99, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0xa6, 0xe2, 0xa3, 0x84, 0xe2, 0xa3,
  0x80, 0xe2, 0xa1, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0xa0, 0xe2, 0xa3, 0x84, 0xe2, 0xa1, 0x80, 0xe2, 0xa2, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0x80, 0xe2,
  0xa3, 0xa0, 0xe2, 0xa3, 0xa4, 0xe2, 0xa3, 0xb4, 0xe2, 0xa3, 0xb6, 0xe2,
  0xa3, 0xb6, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0xbe, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xa6, 0xe2, 0xa3, 0xb7, 0xe2, 0xa1, 0x86, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa2, 0x80, 0xe2, 0xa0, 0xa0, 0xe2, 0xa0, 0xb4, 0xe2, 0xa3, 0xbe,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0xbf,
  0xe2, 0xa0, 0x9f, 0xe2, 0xa0, 0xbb, 0xe2, 0xa2, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xa6, 0xe2, 0xa1, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0x80, 0xe2, 0xa3,
  0xa4, 0xe2, 0xa3, 0xbe, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xb6, 0xe2, 0xa3, 0xb6, 0xe2, 0xa3, 0xac, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb6, 0xe2, 0xa3,
  0x84, 0xe2, 0xa1, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0x80, 0xe2,
  0xa3, 0xb4, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa1, 0xbf, 0xe2, 0xa0, 0xbf, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0xbf, 0xe2,
  0xa0, 0xbf, 0xe2, 0xa0, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xb7, 0xe2, 0xa1, 0xb6, 0xe2, 0xa0, 0xb6, 0xe2, 0xa2, 0xa6, 0xe2,
  0xa3, 0x84, 0xe2, 0xa3, 0x80, 0xe2, 0xa3, 0xa0, 0xe2, 0xa3, 0x84, 0xe2,
  0xa1, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa2, 0xa0, 0xe2, 0xa3, 0xbe, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0x9c,
  0xe2, 0xa2, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0xb6,
  0xe2, 0xa3, 0xa6, 0xe2, 0xa3, 0xa4, 0xe2, 0xa3, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x88, 0xe2, 0xa0, 0x89, 0xe2, 0xa0, 0x9b,
  0xe2, 0xa2, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0x89, 0xe2, 0xa0, 0x80,
  0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0xb0, 0xe2, 0xa1, 0xbf, 0xe2, 0xa2,
  0x9f, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb6, 0xe2, 0xa1,
  0xac, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0xbf, 0xe2, 0xa0, 0xbf, 0xe2, 0xa0,
  0xbf, 0xe2, 0xa0, 0xbf, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0,
  0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0xbb, 0xe2, 0xa0, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb6, 0xe2, 0xa3,
  0xa4, 0xe2, 0xa3, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x88, 0xe2, 0xa0, 0x89, 0xe2, 0xa0, 0x99, 0xe2, 0xa2, 0xbb, 0xe2, 0xa1,
  0xbf, 0xe2, 0xa0, 0xbb, 0xe2, 0xa0, 0xbf, 0xe2, 0xa2, 0xbf, 0xe2, 0xa1,
  0x9f, 0xe2, 0xa0, 0x81, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x83, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xbc, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa1, 0x8f, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x88, 0xe2,
  0xa0, 0x99, 0xe2, 0xa0, 0xbb, 0xe2, 0xa2, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xb6, 0xe2, 0xa3, 0xa4, 0xe2, 0xa3, 0x80, 0xe2,
  0xa3, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x88, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0x80,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xa6, 0xe2, 0xa1, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x89, 0xe2, 0xa0, 0x89,
  0xe2, 0xa0, 0x89, 0xe2, 0xa0, 0x89, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x9b,
  0xe2, 0xa0, 0x89, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0xb8, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0xa4, 0xe2, 0xa3, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa2, 0xb8, 0xe2, 0xa3, 0xbf, 0xe2, 0xa0, 0x8b, 0xe2, 0xa2, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0xa6, 0xe2,
  0xa3, 0x84, 0xe2, 0xa1, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x88, 0xe2, 0xa0, 0x8f,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x98, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0xa6, 0xe2, 0xa3, 0x84, 0xe2, 0xa1, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x98, 0xe2, 0xa2, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb6, 0xe2, 0xa3,
  0xa4, 0xe2, 0xa3, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x88, 0xe2, 0xa0, 0xbb, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xb7, 0xe2, 0xa3, 0xa6, 0xe2, 0xa1, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x88, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xb7, 0xe2, 0xa3, 0x84, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xa0, 0xe2, 0xa3,
  0xbe, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3,
  0xb7, 0xe2, 0xa3, 0xb6, 0xe2, 0xa1, 0x84, 0xe2, 0xa0, 0x80, 0x0a, 0xe2,
  0xa0, 0x80, 0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0x8f, 0xe2, 0xa0, 0x80, 0xe2,
  0xa3, 0xa4, 0xe2, 0xa3, 0xa4, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xa4, 0xe2,
  0xa3, 0xa4, 0xe2, 0xa1, 0x84, 0xe2, 0xa2, 0xa0, 0xe2, 0xa3, 0xa4, 0xe2,
  0xa3, 0xa4, 0xe2, 0xa2, 0xa0, 0xe2, 0xa3, 0xa4, 0xe2, 0xa3, 0xa4, 0xe2,
  0xa0, 0x80, 0xe2, 0xa3, 0xa4, 0xe2, 0xa3, 0xa4, 0xe2, 0xa1, 0x84, 0xe2,
  0xa2, 0xa0, 0xe2, 0xa3, 0xa4, 0xe2, 0xa1, 0x84, 0xe2, 0xa2, 0xa0, 0xe2,
  0xa3, 0xa4, 0xe2, 0xa3, 0xa4, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0xbb, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa1, 0x87, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0x87,
  0xe2, 0xa2, 0xb8, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa2, 0xb8,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0x87, 0xe2, 0xa2, 0xb8, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa1, 0x87, 0xe2, 0xa2, 0xb8, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80,
  0xe2, 0xa0, 0x80, 0xe2, 0xa2, 0xb8, 0xe2, 0xa3, 0xbf, 0xe2, 0xa0, 0x80,
  0x0a, 0xe2, 0xa0, 0x80, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0x87, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x83, 0xe2, 0xa0, 0x98, 0xe2, 0xa0,
  0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x98, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0,
  0x9b, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0,
  0x83, 0xe2, 0xa0, 0x98, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x83, 0xe2, 0xa0,
  0x98, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x9b, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0,
  0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa0, 0x80, 0xe2, 0xa3,
  0xb8, 0xe2, 0xa3, 0xbf, 0xe2, 0xa0, 0x80, 0x0a, 0xe2, 0xa0, 0x80, 0xe2,
  0xa0, 0xb9, 0xe2, 0xa2, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2,
  0xa3, 0xbf, 0xe2, 0xa3, 0xbf, 0xe2, 0xa1, 0xbf, 0xe2, 0xa0, 0x8b, 0xe2,
  0xa0, 0x80
};

int DEBUG;

int main(int argc, char *argv[]) {

    printf("\n%s%s%s%s\n\n", BLD, GRN, afos_banner, NRM);
    printf("%s%s ANDRAX-NG Next Generation Package Manager %s%sv1.0.0%s\n", BLD, GRN, BLD, RED, NRM);
    printf(" %sCopyright%s %s2025%s By %sSNAKE Security%s %s-%s %sWeidsom Nascimento%s\n\n", YEL, NRM, CYN, NRM, WHT, NRM, RED, NRM, WHT, NRM);

    if(geteuid() != 0) {
        printf("\n%s[%s %s%sFATAL ERROR%s %s]%s : No root no fun!\n\n", WHT, NRM, BLD, RED, NRM, WHT, NRM);
        exit(77);
    }

    int opt;
    opterr = 0;

    if(access("/opt/AFOS/pkg.db", F_OK ) == 0 ) {
        // Ok
    } else {
        mkdir("/opt/AFOS", 0755);
        createdb();
    }

    chdir("/opt/AFOS");

    static struct option long_options[] = {
        {"install", required_argument, NULL, 'i'},
        {"update", no_argument, NULL, 'u'},
        {"update-all", no_argument, NULL, 'a'},
        {"list", no_argument, NULL, 'l'},
        {"repo", no_argument, NULL, 'r'},
        {"notinstalled", no_argument, NULL, 'n'},
        {"debug", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    if(argc <= 1) {
        help();
        exit(1);
    }

    while((opt = getopt_long(argc, argv, "i:ualrdhn", long_options, NULL)) != -1)  {
        switch(opt) {
            case 'd':
                DEBUG = 1;
                break;
            case 'i':
                get_pkgs();
                printf("%s\n",lower(optarg));
                //install(optarg, 0);
                //printf("\n");
                exit(0);
                break;
            case 'r':
                get_pkgs();
                printf("Packages available on AFOS-NG repository:\n\n");
                repolist();
                printf("\n");
                exit(0);
                break;
            case 'n':
                //get_pkgs();
                //printf("Checking Not Installed Packages:\n\n");
                //readdb2();
                //printf("\n");
                exit(0);
                break;
            case 'u':
                //get_pkgs();
                printf("Checking for updates...\n\n");
                update(0);
                printf("\n");
                exit(0);
                break;
            case 'a':
                //get_pkgs();
                printf("Updating all packages...\n\n");
                update(1);
                printf("\n");
                exit(0);
                break;
            case 'l':
                printf("Installed Packages (only by AFOS-NG):\n\n");
                readdb();
                printf("\n");
                exit(0);
                break;
            case 'h':
                help();
                exit(0);
                break;
            case '?':
                if(optopt == 'i') {
                    printf("%s[%s %s%sPackage name?%s %s]%s\n\n", WHT, NRM, BLD, RED, NRM, WHT, NRM);
                }
                exit(1);
                break;
            default:
                help();
                break;
        }
    }

    return 0;
}