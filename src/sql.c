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
#include <sqlite3.h> 
#include <string.h>
#include "afos.h"

struct PKG {
   char name[1000];
   char version[1000];
   char desc[1000];
   char type[1000];
};

struct PKG pkgs1;

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

static int callbackread(void *data, int argc, char **argv, char **azColName){
   int i;
   
   
   for(i = 0; i<argc; i++){
      if(i==1) {
         strncpy(pkgs1.name, argv[i], 999);
      } else if(i==2) {
         strncpy(pkgs1.version, argv[i], 999);
      } else if(i==3) {
         strncpy(pkgs1.desc, argv[i], 999);
      } else if(i==4) {
         strncpy(pkgs1.type, argv[i], 999);
      }
   }

   
   printf("[ %s%s%s ] [ %s%s%s ] [ %s%s%s ] [ %s%s%s ]\n", WHT, pkgs1.name, NRM, RED, pkgs1.version, NRM, YEL, pkgs1.desc, NRM, BLU, pkgs1.type, NRM);
   
   
   return 0;
}

int readdb() {
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;
   const char* data = "Callback function called";

   rc = sqlite3_open("/opt/AFOS/pkg.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } else {
       if(DEBUG) {
           fprintf(stderr, "Opened database successfully\n");
       }
   }

   sql = "SELECT * from PACKAGES";

   rc = sqlite3_exec(db, sql, callbackread, NULL, &zErrMsg);
   
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

int createdb() {
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;

   rc = sqlite3_open("/opt/AFOS/pkg.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n\n", sqlite3_errmsg(db));
      return(0);
   } else {
       if(DEBUG) {
           fprintf(stdout, "Opened database successfully\n");
       }
   }

   sql = "CREATE TABLE PACKAGES("  \
      "ID INTEGER PRIMARY KEY AUTOINCREMENT," \
      "NAME TEXT NOT NULL UNIQUE," \
      "VERSION TEXT NOT NULL," \
      "DESC TEXT NOT NULL," \
      "TYPE TEXT NOT NULL);";

   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
       if(DEBUG) {
           fprintf(stdout, "Table created successfully\n");
       }
   }
   
   sqlite3_close(db);
   return 0;
}
