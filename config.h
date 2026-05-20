#ifndef CONFIG_H
#define CONFIG_H

extern const char *config_interface;
extern const char *config_signature_file;

int load_config(const char *filename);

#endif // CONFIG_H
