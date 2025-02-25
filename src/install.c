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

static int callback_insert(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

int insert_in_db(char *sql) {
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;

   rc = sqlite3_open("/opt/AFOS/pkg.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      exit(1);
   }

   rc = sqlite3_exec(db, sql, callback_insert, 0, &zErrMsg);
   
   if( rc != SQLITE_OK ){
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }
   sqlite3_close(db);
   return 0;
}

int git_download(char *name, char *url) {

    char protocolurl[2000];
    char cmd_git[5000];
    long int valuecode;
    char work_dir[800];
    char cmd_tmp[5000];

    snprintf(cmd_tmp, 4999, "rm -rf /opt/AFOS/%s", name);
    system(cmd_tmp);
    memset(cmd_tmp, 0, sizeof(cmd_tmp));
    
    printf("\nStarting at [ %s ]\n\n", url);

    snprintf(protocolurl, 1999, "https://%s", url);
    snprintf(cmd_git, 4999,"git clone %s %s", protocolurl, name); 
    
    valuecode = system(cmd_git);

    if(DEBUG) {
        printf("Value code of GIT: %s%li%s\n\n", YEL, valuecode, NRM);
    }

    if(valuecode == 0) {

        printf("BUILD AND INSTALLING\n\n");
        snprintf(cmd_tmp, 4999, "/opt/AFOS/%s", name);
        chdir(cmd_tmp);
        memset(cmd_tmp, 0, sizeof(cmd_tmp));

        if (access("AFOSBUILD.sh", F_OK) == 0) {
            // Go ahead
        } else {
            if(DEBUG) {
                printf("%sFATAL ERROR%s: Repository is not AFOS compliant!!!\n\n", RED, NRM);
            }
            exit(1);
        }

        if (access("PREAFOS.sh", F_OK) == 0) {
            system("bash PREAFOS.sh");
        } else {
            // No problem just continue
        }

        valuecode = system("bash AFOSBUILD.sh");
        if(DEBUG) {
            printf("Value code AFOSBUILD %s%li%s\n\n", YEL, valuecode, NRM);
        }

        if(valuecode == 0) {

            if (access("POSAFOS.sh", F_OK) == 0) {
                system("bash POSAFOS.sh");
            } else {
                // No problem just continue
            }

            chdir("/opt/AFOS");
            printf("\nCleaning UP\n");
            snprintf(cmd_tmp, 4999, "rm -rf /opt/AFOS/%s", name);
            system(cmd_tmp);
            memset(cmd_tmp, 0, sizeof(cmd_tmp));

        } else {
            printf("%s[%s %s%sFATAL ERROR%s %s]%s Installation failed\n", WHT, NRM, BLD, RED, NRM, WHT, NRM);
            return 1;
        }

    } else {
        return 1;
    }
    
    return 0;
}

int install_pkg(char *pkg_name, char *pkg_version, char *pkg_desc, char *pkg_categories, char *pkg_url, int update_all) {

    if(strlen(pkg_name) < 2 && strlen(pkg_version) < 2 && strlen(pkg_desc) < 2 && strlen(pkg_categories) < 2 && strlen(pkg_url) < 2) {
        printf("%s[%s %sFATAL%s %s]%s Parameters size error %s %s %s %s %s\n", WHT, NRM, RED, NRM, WHT, NRM, pkg_name, pkg_version, pkg_desc, pkg_categories, pkg_url);
        exit(1);
    }

    char answer[6];
    int git_download_result;

    printf("Do you wanna install: %s? [ Y/n ]: ", pkg_name);
    scanf("%5[^\n]", answer);

    if(update_all == 0) {
        if((strncmp(lower(answer), "y", 5) == 0 || strncmp(lower(answer), "yes", 5) == 0)) {

            git_download_result = git_download(pkg_name, pkg_url);

            if(git_download_result == 0) {
                char sqlstate[5000];

                printf("\nUpdating AFOS DATABASE\n\n");

                snprintf(sqlstate, 4999, "INSERT OR REPLACE INTO PACKAGES (NAME,VERSION,DESC,TYPE) VALUES ('%s', '%s', '%s', '%s' );", pkg_name, pkg_version, pkg_desc, pkg_categories);
                insert_in_db(sqlstate);

            } else {
                printf("The installation failed, contact the maintainer <weidsom at snakesecurity.org>\n");
            }

        } else {
            printf("\n");
            exit(1);
        }
    } else {
        git_download_result = git_download(pkg_name, pkg_url);

        if(git_download_result == 0) {
            char sqlstate[5000];

            printf("\nUpdating AFOS DATABASE\n\n");

            snprintf(sqlstate, 4999, "INSERT OR REPLACE INTO PACKAGES (NAME,VERSION,DESC,TYPE) VALUES ('%s', '%s', '%s', '%s' );", pkg_name, pkg_version, pkg_desc, pkg_categories);
            insert_in_db(sqlstate);

        } else {
            printf("The installation failed, contact the maintainer <weidsom at snakesecurity.org>\n");
        }
    }

    return 0;
}

int install(char *query_name, int update_all) {

    int pkg_found = 0;

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
    char pkg_install_categories[1000];

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
                            if(strcmp(query_name, name) == 0) {
                                categories[category_count++] = strdup((char *)event.data.scalar.value);
                            }
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
                    if(strcmp(query_name, name) == 0) {
                        int total_length = 0;

                        for (int i = 0; i < category_count; i++) {
                            total_length += strlen(categories[i]) + 2; 
                        }

                        total_length--;

                        char *result_str_categories = (char *)malloc(total_length + 1); 
                        result_str_categories[0] = '\0'; 

                        for (int i = 0; i < category_count; i++) {

                            strcat(result_str_categories, categories[i]);

                            if (i < category_count - 1) {
                                strcat(result_str_categories, ", ");
                            }

                            free(categories[i]);
                        }

                        strncpy(pkg_install_categories, result_str_categories, 999);

                        free(result_str_categories);
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

                    if(strcmp(query_name, name) == 0) {

                        pkg_found = 1;
                        
                        if(DEBUG) {
                            printf("%s[%s %sFOUND%s %s]%s %s %s(%sv%s%s)%s [ %s ] [ %s ] at %s\n", WHT, NRM, CYN, NRM, WHT, NRM, name, WHT, NRM, version, WHT, NRM, desc, pkg_install_categories, repo_url);
                        }

                        install_pkg(name, version, desc, pkg_install_categories, repo_url, update_all);

                        memset(name, 0, sizeof(name));
                        memset(version, 0, sizeof(version));
                        memset(desc, 0, sizeof(desc));
                        memset(repo_url, 0, sizeof(repo_url));
                        memset(pkg_install_categories, 0, sizeof(pkg_install_categories));
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

    if(!pkg_found) {
        printf("\n%s[%s %sFATAL%s %s]%s Package: %s(%s %s %s)%s NOT FOUND!\n\n", WHT, NRM, RED, NRM, WHT, NRM, WHT, NRM, query_name, WHT, NRM);
        exit(1);
    }

    return 0;
}