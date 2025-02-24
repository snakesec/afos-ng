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


///////////////////////////////////////////////////////////////////////
//                                                                   //
// This file is just a test...                                       //
// I'm just learning basic SQLITE3 Manipulation using libsqlite3...  //
//                                                                   //
///////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

int main(int argc, char* argv[]) {
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;

   rc = sqlite3_open("/opt/AFOS/pkg.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } else {
      fprintf(stderr, "Opened database successfully\n");
   }

   sql = "INSERT INTO PACKAGES (NAME,VERSION,DESC,TYPE) VALUES ('nmap', '7.90', 'Advanced NetWork Mapper', 'Information Gathering, Scanning' );" \
         "INSERT INTO PACKAGES (NAME,VERSION,DESC,TYPE) VALUES ('hping', '2.1', 'Packet forger', 'Packet Crafting');";

   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "Records created successfully\n");
   }
   sqlite3_close(db);
   return 0;
}