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

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <yaml.h>
#include <sqlite3.h>

#include "afos.h"

int pkg_count_db = 0;

struct PKG {
   char name[2000][500];
   char version[2000][500];
   char desc[2000][500];
   char type[2000][500];
};

struct PKG pkgs_on_db;

static int callback_list_on_db(void *data, int argc, char **argv, char **azColName){
   int i;
   
   for(i = 0; i<argc; i++) {
    if(pkg_count_db < 2000){
        if(i==1) {
            strncpy(pkgs_on_db.name[pkg_count_db], argv[i], 499);
        } else if(i==2) {
            strncpy(pkgs_on_db.version[pkg_count_db], argv[i], 499);
        } else if(i==3) {
            strncpy(pkgs_on_db.desc[pkg_count_db], argv[i], 499);
        } else if(i==4) {
            strncpy(pkgs_on_db.type[pkg_count_db], argv[i], 499);
        }
        pkg_count_db++;
    }
   }   
   
   return 0;
}

int list_on_db() {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    char *sql;
    const char* data = "Callback function called";

    rc = sqlite3_open("/opt/AFOS/pkg.db", &db);

    if( rc ) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    } else {
        if(DEBUG) {
            fprintf(stderr, "Opened database successfully\n");
        }
    }

    sql = "SELECT * from PACKAGES";

    rc = sqlite3_exec(db, sql, callback_list_on_db, NULL, &zErrMsg);

    if( rc != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        if(DEBUG) {
            fprintf(stdout, "Operation done successfully\n");
        }
    }
    sqlite3_close(db);
    return 0;
}


int is_installed_or_not(char *query_name) {
    int installed = 0;

    list_on_db();

    for (int i = 0; i < 2000; i++) {
        if(strcmp(query_name, pkgs_on_db.name[i]) == 0) {
            installed = 1;
        }
    }

    if(installed == 0) {
        return 1;
    }

    return 0;
}