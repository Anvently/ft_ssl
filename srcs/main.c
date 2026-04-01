#include <ft_openssl.h>

static const char *usage = "\
usage: ./openssl command [...]\n\
\n";

const char *executable_name = "ft_ssl";

const struct s_algorithm algorithms[NBR_ALGORITHM] = {
    [MD5] = {.func = md5, .name = "md5", .type = ALGO_TYPE_DIGEST},
    [SHA256] = {.func = sha256, .name = "sha256", .type = ALGO_TYPE_DIGEST},
    [SHA224] = {.func = sha224, .name = "sha224", .type = ALGO_TYPE_DIGEST},
    [SHA512] = {.func = sha512, .name = "sha512", .type = ALGO_TYPE_DIGEST},
    [BASE64] = {.func = base64, .name = "base64", .type = ALGO_TYPE_OTHER},
    [DES] = {.func = des_cbc, .name = "des", .type = ALGO_TYPE_CIPHER},
    [DES_ECB] = {.func = des_ecb, .name = "des-ecb", .type = ALGO_TYPE_CIPHER},
    [DES_CBC] = {.func = des_cbc, .name = "des-cbc", .type = ALGO_TYPE_CIPHER},
    [DES_PCBC] = {.func = des_pcbc,
                  .name = "des-pcbc",
                  .type = ALGO_TYPE_CIPHER},
    [DES_CFB] = {.func = des_cfb, .name = "des-cfb", .type = ALGO_TYPE_CIPHER},
    [DES_OFB] = {.func = des_ofb, .name = "des-ofb", .type = ALGO_TYPE_CIPHER},
    [DES3] = {.func = des3_ecb, .name = "des3", .type = ALGO_TYPE_CIPHER},
    [DES3_ECB] = {.func = des3_ecb,
                  .name = "des3-ecb",
                  .type = ALGO_TYPE_CIPHER},
    [DES3_CBC] = {.func = des3_cbc,
                  .name = "des3-cbc",
                  .type = ALGO_TYPE_CIPHER},
    [DES3_PCBC] = {.func = des3_pcbc,
                   .name = "des3-pcbc",
                   .type = ALGO_TYPE_CIPHER},
    [DES3_CFB] = {.func = des3_cfb,
                  .name = "des3-cfb",
                  .type = ALGO_TYPE_CIPHER},
    [DES3_OFB] = {
        .func = des3_ofb, .name = "des3-ofb", .type = ALGO_TYPE_CIPHER}};

void print_commands() {
    int count = 0;

    ft_sdprintf(2, "COMMANDS\nDigests: ");
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (algorithms[i].type != ALGO_TYPE_DIGEST)
            continue;
        ft_sdprintf(2, "%s%s", count++ == 0 ? "" : ", ", algorithms[i].name);
    }
    ft_sdprintf(2, "\nCiphers: ");
    count = 0;
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (algorithms[i].type != ALGO_TYPE_CIPHER)
            continue;
        ft_sdprintf(2, "%s%s", count++ == 0 ? "" : ", ", algorithms[i].name);
    }
    ft_sdprintf(2, "\nOthers: ");
    count = 0;
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (algorithms[i].type != ALGO_TYPE_OTHER)
            continue;
        ft_sdprintf(2, "%s%s", count++ == 0 ? "" : ", ", algorithms[i].name);
    }
    ft_sdprintf(2, "\n");
}

void error_usage() {
    ft_sdprintf(2, "%s", usage);
    print_commands();
    exit(2);
}

int main(int argc, char **argv) {

    if (argc < 2)
        return (interactive_mode());
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (ft_strcmp(algorithms[i].name, argv[1]) == 0)
            return (algorithms[i].func((unsigned int)(argc - 2), argv + 2));
    }
    error_usage();
}