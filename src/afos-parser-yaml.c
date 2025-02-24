#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

int main(void) {
    FILE *fh = fopen("/opt/AFOS/afos_pkgs.yaml", "r");
    if (!fh) {
        fprintf(stderr, "Erro ao abrir o arquivo YAML\n");
        return 1;
    }

    yaml_parser_t parser;
    yaml_event_t event;

    // Inicializa o parser
    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Erro ao inicializar o parser YAML\n");
        fclose(fh);
        return 1;
    }

    // Define o arquivo de entrada
    yaml_parser_set_input_file(&parser, fh);

    int done = 0;
    int in_sequence = 0;  // Flag para a sequência principal de pacotes
    int in_mapping = 0;   // Flag para o mapeamento de um pacote
    int in_categories = 0; // Flag para a sequência de categorias
    char *key = NULL;     // Armazena a chave atual
    char *categories[10]; // Array para categorias (limite de 10)
    int category_count = 0;

    // Loop pelos eventos do parser
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Erro no parsing: %s\n", parser.problem);
            break;
        }

        switch (event.type) {
            case YAML_STREAM_START_EVENT:
            case YAML_DOCUMENT_START_EVENT:
                break;

            case YAML_SEQUENCE_START_EVENT:
                if (!in_mapping) {
                    in_sequence = 1;
                    printf("Iniciando lista de pacotes:\n");
                } else if (key && strcmp(key, "categories") == 0) {
                    in_categories = 1;
                    category_count = 0;
                }
                break;

            case YAML_MAPPING_START_EVENT:
                if (in_sequence && !in_mapping) {
                    in_mapping = 1;
                    printf("Novo pacote:\n");
                }
                break;

            case YAML_SCALAR_EVENT:
                if (in_mapping) {
                    if (!key) {
                        key = strdup((char *)event.data.scalar.value);
                    } else {
                        if (strcmp(key, "categories") == 0 && !in_categories) {
                            // Apenas marca que estamos entrando em categories, já tratado no SEQUENCE_START
                        } else if (in_categories) {
                            categories[category_count++] = strdup((char *)event.data.scalar.value);
                        } else {
                            printf("  %s: %s\n", key, event.data.scalar.value);
                            free(key);
                            key = NULL;
                        }
                    }
                }
                break;

            case YAML_SEQUENCE_END_EVENT:
                if (in_categories) {
                    printf("  categories:\n");
                    for (int i = 0; i < category_count; i++) {
                        printf("    - %s\n", categories[i]);
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

    // Limpeza
    yaml_parser_delete(&parser);
    fclose(fh);
    if (key) free(key);

    return 0;
}
