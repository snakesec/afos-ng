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
#include <stdlib.h>
#include <yaml.h>
#include <sqlite3.h>
#include <string.h>
#include "semver.h"

int update_all = 0;

char pkg_install_names[2000][500];
char pkg_install_versions[2000][500];
char pkg_install_repo_url[2000][500];
int pkg_install_count = 0;

int compare_versions(char *pkg_name, char *local_pkg_version) {

    semver_t current_version = {};
    semver_t compare_version = {};

    FILE *fh = fopen("/opt/AFOS/afos_pkgs.yaml", "r");
    if (!fh) {
        if(DEBUG) {
            printf("%s[%s %sFATAL%s %s]%s Can't locate: %s/opt/AFOS/afos_pkgs.yaml%s\n", WHT, NRM, RED, NRM, WHT, NRM, YEL, NRM);
        }
        exit(1);
    }

    yaml_parser_t parser;
    yaml_event_t event;

    if (!yaml_parser_initialize(&parser)) {
        if(DEBUG) {
            printf("%s[%s %sFATAL%s %s]%s %sError initializing the parser%s\n", WHT, NRM, RED, NRM, WHT, NRM, YEL, NRM);
        }
        fclose(fh);
        exit(1);
    }

    yaml_parser_set_input_file(&parser, fh);

    int done = 0;
    int in_sequence = 0;  
    int in_mapping = 0;   
    int in_categories = 0;
    char *key = NULL;    
    char *categories[10];
    int category_count = 0;
    char name[500];
    char version[500];
    char desc[500];
    char repo_url[500];

    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            if(DEBUG) {
                printf("%s[%s %sFATAL%s %s]%s Parsing error... %s\n", WHT, NRM, RED, NRM, WHT, NRM, parser.problem);
            }
            break;
        }

        switch (event.type) {
            case YAML_STREAM_START_EVENT:
            case YAML_DOCUMENT_START_EVENT:
                break;

            case YAML_SEQUENCE_START_EVENT:
                if (!in_mapping) {
                    in_sequence = 1;
                } else if (key && strcmp(key, "categories") == 0) {
                    in_categories = 1;
                    category_count = 0;
                }
                break;

            case YAML_MAPPING_START_EVENT:
                if (in_sequence && !in_mapping) {
                    in_mapping = 1;
                }
                break;

            case YAML_SCALAR_EVENT:
                if (in_mapping) {
                    if (!key) {
                        key = strdup((char *)event.data.scalar.value);
                    } else {
                        if (strcmp(key, "categories") == 0 && !in_categories) {
                        } else if (in_categories) {
                            categories[category_count++] = strdup((char *)event.data.scalar.value);
                        } else {
                            if(strcmp(key, "name") == 0) {
                                strncpy(name, (const char *)event.data.scalar.value, 499);
                            } else if(strcmp(key, "version") == 0) {
                                strncpy(version, (const char *)event.data.scalar.value, 499);
                            } else if(strcmp(key, "description") == 0) {
                                strncpy(desc, (const char *)event.data.scalar.value, 499);
                            } else if(strcmp(key, "repo_url") == 0) {
                                strncpy(repo_url, (const char *)event.data.scalar.value, 499);
                            }
                            free(key);
                            key = NULL;
                        }
                    }
                }
                break;
            
            case YAML_SEQUENCE_END_EVENT:
                if (in_categories) {
                    for(int i = 0; i < category_count; i++) {
                        free(categories[i]);
                    }
                    in_categories = 0;
                    free(key);
                    key = NULL;
                } else if (in_sequence) {
                    in_sequence = 0;
                }
                break;

            case YAML_MAPPING_END_EVENT:
                if (in_mapping) {
                    in_mapping = 0;
                    //printf("Name: %s, Version: %s, Desc: %s\n", name, version, desc);

                    if(strcmp(pkg_name, name) == 0) {
                        if (semver_parse(local_pkg_version, &current_version) || semver_parse(version, &compare_version)) {
                            if(DEBUG) {
                                printf("%s[%s %sERROR%s %s]%s Invalid semver string LOCAL: %s REPO: %s\n", WHT, NRM, YEL, NRM, WHT, NRM, local_pkg_version, version);
                                printf(" %s %s\n", local_pkg_version, version);
                            }
                        } else {
                            int resolution = semver_compare(compare_version, current_version);

                            if (resolution == 0) {
                                // equal
                            }
                            else if (resolution == -1) {
                                // REPO version is lower... that should not be possible...
                                if(DEBUG) {
                                    printf("%s[%s %sERROR%s %s]%s REPO Version is lower than LOCAL version\n", WHT, NRM, YEL, NRM, WHT, NRM);
                                }
                            }
                            else {
                                // We have update
                                printf("%s[%s UPDATE AVAILABLE %s]%s : %s%s%s%s from %s%s%s%s to %s%s%s%s\n", WHT, NRM, WHT, NRM, BLD, GRN, name, NRM, BLD, RED, local_pkg_version, NRM, BLD, BLU, version, NRM);
                                
                                if(update_all != 0 && pkg_install_count <= 1999) {
                                    strncpy(pkg_install_names[pkg_install_count], name, 499);
                                    strncpy(pkg_install_versions[pkg_install_count], version, 499); 
                                    strncpy(pkg_install_repo_url[pkg_install_count], repo_url, 499); 
                                } else if(update_all != 0 && pkg_install_count >= 2000) {
                                    printf("\n%s[%s %sFATAL%s %s]%s We have more packages than allowed to update at the same time...\n", WHT, NRM, RED, NRM, WHT, NRM);
                                    exit(1);
                                }
                                pkg_install_count++;
                            }
                        }

                        semver_free(&current_version);
                        semver_free(&compare_version);

                        memset(name, 0, sizeof(name));
                        memset(version, 0, sizeof(version));
                        memset(desc, 0, sizeof(desc));
                        memset(repo_url, 0, sizeof(repo_url));
                    }
                }
                break;

            case YAML_DOCUMENT_END_EVENT:
            case YAML_STREAM_END_EVENT:
                done = 1;
                break;

            default:
                break;
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(fh);
    if (key) free(key);

    return 0;

}

static int callback_check_version_on_db(void *data, int argc, char **argv, char **azColName){
   int i;
   char tmp_name[500];
   char tmp_version[500];
   
   for(i = 0; i <= 2; i++){
      if(i==1) {
         strncpy(tmp_name, argv[i], 499);
      } else if(i==2) {
         strncpy(tmp_version, argv[i], 499);
      }
      //printf("Loop: %d\n", i);
   }

   //printf("[ %s%s%s ] [ %s%s%s ]\n", WHT, tmp_name, NRM, RED, tmp_version, NRM);
   compare_versions(tmp_name, tmp_version);
   
   return 0;
}

int read_db_to_compare() {
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;
   const char* data = "Callback function called";

   rc = sqlite3_open("/opt/AFOS/pkg.db", &db);
   
   if( rc ) {
      printf("Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } else {
       if(DEBUG) {
           printf("Opened database successfully\n");
       }
   }

   sql = "SELECT * from PACKAGES";

   rc = sqlite3_exec(db, sql, callback_check_version_on_db, NULL, &zErrMsg);
   
   if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
       if(DEBUG) {
           printf("Operation done successfully\n");
       }
   }
   sqlite3_close(db);
   return 0;
}

int update(int all) {

    if(all) {
        update_all = 1;
    }

    read_db_to_compare();

    if(update_all != 0) {

        char answer[6];
        printf("\nDo you wanna update all? [ Y/n ]: ");
        scanf("%5[^\n]", answer);
        strtok(answer, "\n");
        
        if((strncmp(lower(answer), "y", 5) == 0 || strncmp(lower(answer), "yes", 5) == 0)) {
            printf("\n");
            
            for(int i = 0; i < pkg_install_count; i++) {
                printf("Updating: %s Version: %s from: %s\n", pkg_install_names[i], pkg_install_versions[i], pkg_install_repo_url[i]);
                install(pkg_install_names[i], 1);
            }

        } else {
            printf("\n");
            exit(1);
        }

    }

    return 0;
}
