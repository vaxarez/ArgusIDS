#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

char *config_interface = "eth0";
char *config_signature_file = "signatures.txt";

int load_config(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open configuration file");
        return -1;
    }

    yaml_parser_t parser;
    yaml_token_t token;

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        fclose(file);
        return -1;
    }
    yaml_parser_set_input_file(&parser, file);

    while (1) {
        yaml_parser_scan(&parser, &token);
        switch (token.type) {
            case YAML_KEY_TOKEN: {
                yaml_parser_scan(&parser, &token);
                if (token.type != YAML_SCALAR_TOKEN) {
                    break;
                }

                const char *key = token.data.scalar.value;
                yaml_parser_scan(&parser, &token);
                if (token.type != YAML_VALUE_TOKEN) {
                    break;
                }
                yaml_parser_scan(&parser, &token);

                if (token.type == YAML_SCALAR_TOKEN) {
                    const char *value = token.data.scalar.value;

                    if (strcmp(key, "interface") == 0) {
                        free(config_interface);
                        config_interface = strdup(value);
                    } else if (strcmp(key, "signature_file") == 0) {
                        free(config_signature_file);
                        config_signature_file = strdup(value);
                    }
                }
                break;
            }
            case YAML_STREAM_END_TOKEN:
                yaml_token_delete(&token);
                goto done;
            default:
                break;
        }
        yaml_token_delete(&token);
    }

done:
    yaml_parser_delete(&parser);
    fclose(file);
    return 0;
}
