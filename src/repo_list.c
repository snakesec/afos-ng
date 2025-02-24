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
#include <yaml.h>

#include "afos.h"

int repolist() {
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
                                printf("[ %s%s%s ] ", WHT, (const char *)event.data.scalar.value, NRM);
                            } else if(strcmp(key, "version") == 0) {
                                printf("[ %s%s%s ] ", RED, (const char *)event.data.scalar.value, NRM);
                            } else if(strcmp(key, "description") == 0) {
                                printf("[ %s%s%s ] ", YEL, (const char *)event.data.scalar.value, NRM);
                                strncpy(desc, (const char *)event.data.scalar.value, 499);
                            }
                            free(key);
                            key = NULL;
                        }
                    }
                }
                break;

            case YAML_SEQUENCE_END_EVENT:
                if (in_categories) {
                    printf("[ ");
                    for (int i = 0; i < category_count; i++) {
                        printf("%s%s%s", BLU, categories[i], NRM);
                        if (i < category_count - 1) {
                            printf(", ");
                        }
                        free(categories[i]);
                    }
                    printf(" ]");
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
                    printf("\n");
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