#include "cld/linker.h"
#include "cld/bso.h"
#include "cld/macho.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *cld_output_kind_name(CldOutputKind output_kind) {
    switch (output_kind) {
        case CLD_OUTPUT_KIND_RELOCATABLE:
            return "relocatable";
        case CLD_OUTPUT_KIND_EXECUTABLE:
            return "executable";
    }

    return "unknown";
}

static void cld_print_targets(FILE *stream) {
    size_t target_index;

    fprintf(stream, "available targets:\n");
    for (target_index = 0; target_index < cld_target_count(); ++target_index) {
        const CldTarget *target;

        target = cld_target_at(target_index);
        fprintf(stream, "  %s\n", target->name);
    }
}

static void cld_print_version(FILE *stream) {
    fprintf(stream, "cld: CHance Loader/Linker version 1.0.0\n");
    fprintf(stream, "cld: (no language standard)\n");
    fprintf(stream, "cld: License: OpenAzure License\n");
    fprintf(stream, "cld: Compiled on %s %s\n", __DATE__, __TIME__);
    fprintf(stream, "cld: Created by Nathan Hornby (AzureianGH)\n");
}

static void cld_print_usage(FILE *stream) {
    fprintf(stream,
            "usage: cld link <input> [more inputs ...] -o <output> [--target <target>] [--output-kind <kind>] [--entry <symbol>] [--stack-size <bytes>] [-nostdlib] [--list-targets] [-d|-vd]\n");
    fprintf(stream, "       cld --flush-cache\n");
    fprintf(stream, "       output kinds: relocatable, executable\n");
}

static void cld_print_debug_header(void) {
    fprintf(stderr, "\n[debug] Configuration\n");
}

static void cld_print_debug_row(const char *key, const char *value) {
    fprintf(stderr, "  %-16s : %s\n", key, value ? value : "-");
}

int main(int argc, char **argv) {
    CldMachOObject *object_files;
    CldBsoObject *bso_files;
    CldLinkOptions options;
    CldError error;
    const char **input_paths;
    size_t input_count;
    size_t parsed_object_count;
    bool entry_symbol_explicit;
    bool debug_enabled;
    bool debug_deep;
    int argument_index;

    object_files = NULL;
    bso_files = NULL;
    input_paths = NULL;
    input_count = 0;
    parsed_object_count = 0;
    entry_symbol_explicit = false;
    debug_enabled = false;
    debug_deep = false;
    memset(&options, 0, sizeof(options));
    memset(&error, 0, sizeof(error));

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        cld_print_version(stdout);
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "--flush-cache") == 0) {
        if (!cld_flush_sdk_cache(&error)) {
            fprintf(stderr, "cld: %s\n", error.message);
            return 1;
        }
        fprintf(stdout, "cld: SDK import cache flushed\n");
        return 0;
    }

    if (argc < 2 || strcmp(argv[1], "link") != 0) {
        if (argc == 2 && strcmp(argv[1], "--list-targets") == 0) {
            cld_print_targets(stdout);
            return 0;
        }
        cld_print_usage(stderr);
        return 1;
    }

    options.target = cld_default_target();
    options.output_kind = CLD_OUTPUT_KIND_EXECUTABLE;
    input_paths = calloc((size_t) argc, sizeof(*input_paths));
    if (input_paths == NULL) {
        fprintf(stderr, "cld: out of memory allocating input list\n");
        return 1;
    }

    for (argument_index = 2; argument_index < argc; ++argument_index) {
        if (strcmp(argv[argument_index], "-d") == 0 || strcmp(argv[argument_index], "--debug") == 0) {
            debug_enabled = true;
        } else if (strcmp(argv[argument_index], "-vd") == 0 || strcmp(argv[argument_index], "--verbose-deep") == 0) {
            debug_enabled = true;
            debug_deep = true;
        }
    }

    for (argument_index = 2; argument_index < argc; ++argument_index) {
        if (strcmp(argv[argument_index], "-o") == 0) {
            if (argument_index + 1 >= argc) {
                cld_print_usage(stderr);
                goto failure;
            }
            options.output_path = argv[++argument_index];
        } else if (strcmp(argv[argument_index], "--entry") == 0) {
            if (argument_index + 1 >= argc) {
                cld_print_usage(stderr);
                goto failure;
            }
            options.entry_symbol = argv[++argument_index];
            entry_symbol_explicit = true;
        } else if (strcmp(argv[argument_index], "--stack-size") == 0) {
            char *end_pointer;

            if (argument_index + 1 >= argc) {
                cld_print_usage(stderr);
                goto failure;
            }
            options.stack_size = strtoull(argv[++argument_index], &end_pointer, 0);
            if (*end_pointer != '\0') {
                fprintf(stderr, "invalid stack size: %s\n", argv[argument_index]);
                goto failure;
            }
        } else if (strcmp(argv[argument_index], "--output-kind") == 0) {
            if (argument_index + 1 >= argc) {
                cld_print_usage(stderr);
                goto failure;
            }
            ++argument_index;
            if (strcmp(argv[argument_index], "relocatable") == 0) {
                options.output_kind = CLD_OUTPUT_KIND_RELOCATABLE;
            } else if (strcmp(argv[argument_index], "executable") == 0) {
                options.output_kind = CLD_OUTPUT_KIND_EXECUTABLE;
            } else {
                fprintf(stderr, "unsupported output kind: %s\n", argv[argument_index]);
                goto failure;
            }
        } else if (strcmp(argv[argument_index], "--target") == 0) {
            const CldTarget *target;

            if (argument_index + 1 >= argc) {
                cld_print_usage(stderr);
                goto failure;
            }
            target = cld_find_target(argv[++argument_index]);
            if (target == NULL) {
                fprintf(stderr, "unsupported target: %s\n", argv[argument_index]);
                cld_print_targets(stderr);
                goto failure;
            }
            options.target = target;
        } else if (strcmp(argv[argument_index], "-nostdlib") == 0) {
            options.no_stdlib = true;
        } else if (strcmp(argv[argument_index], "--list-targets") == 0) {
            if (debug_enabled) {
                cld_print_debug_header();
                cld_print_debug_row("Action", "list-targets");
                cld_print_debug_row("Deep mode", debug_deep ? "enabled" : "disabled");
            }
            cld_print_targets(stdout);
            free(input_paths);
            return 0;
        } else if (strcmp(argv[argument_index], "-d") == 0 || strcmp(argv[argument_index], "--debug") == 0) {
            debug_enabled = true;
        } else if (strcmp(argv[argument_index], "-vd") == 0 || strcmp(argv[argument_index], "--verbose-deep") == 0) {
            debug_enabled = true;
            debug_deep = true;
        } else if (argv[argument_index][0] == '-') {
            cld_print_usage(stderr);
            goto failure;
        } else {
            input_paths[input_count++] = argv[argument_index];
        }
    }

    if (input_count == 0 || options.output_path == NULL) {
        cld_print_usage(stderr);
        goto failure;
    }

    if (!entry_symbol_explicit) {
        options.entry_symbol = options.target->object_format == CLD_OBJECT_FORMAT_ELF ? "main" : "_main";
    }

    if (!options.no_stdlib &&
        !options.target->host_native &&
        options.target->object_format != CLD_OBJECT_FORMAT_BSO) {
        fprintf(stderr,
                "cld: warning: enabling -nostdlib by default because the current platform is not the target\n");
        options.no_stdlib = true;
    }

    if (debug_enabled) {
        char input_count_buf[32];
        snprintf(input_count_buf, sizeof(input_count_buf), "%zu", input_count);
        cld_print_debug_header();
        cld_print_debug_row("Target", options.target ? options.target->name : "-");
        cld_print_debug_row("Output", options.output_path ? options.output_path : "-");
        cld_print_debug_row("Output kind", cld_output_kind_name(options.output_kind));
        cld_print_debug_row("Entry", options.entry_symbol ? options.entry_symbol : "-");
        cld_print_debug_row("No stdlib", options.no_stdlib ? "yes" : "no");
        cld_print_debug_row("Inputs", input_count_buf);
        if (debug_deep) {
            cld_print_debug_row("Deep mode", "enabled");
            for (size_t i = 0; i < input_count; ++i) {
                fprintf(stderr, "    input[%zu]         = %s\n", i, input_paths[i]);
            }
        }
    }

    if (options.target->object_format == CLD_OBJECT_FORMAT_MACHO ||
        options.target->object_format == CLD_OBJECT_FORMAT_ELF) {
        object_files = calloc(input_count, sizeof(*object_files));
        if (object_files == NULL) {
            fprintf(stderr, "cld: out of memory allocating object list\n");
            goto failure;
        }

        for (parsed_object_count = 0; parsed_object_count < input_count; ++parsed_object_count) {
            if (options.target->object_format == CLD_OBJECT_FORMAT_MACHO) {
                if (!cld_parse_macho_object(input_paths[parsed_object_count], &object_files[parsed_object_count], &error)) {
                    fprintf(stderr, "cld: %s\n", error.message);
                    goto failure;
                }
            } else {
                object_files[parsed_object_count].path = strdup(input_paths[parsed_object_count]);
                if (object_files[parsed_object_count].path == NULL) {
                    fprintf(stderr, "cld: out of memory duplicating input path\n");
                    goto failure;
                }
            }
        }

        if (!cld_link_objects(object_files, input_count, &options, &error)) {
            fprintf(stderr, "cld: %s\n", error.message);
            goto failure;
        }
    } else if (options.target->object_format == CLD_OBJECT_FORMAT_BSO) {
        bso_files = calloc(input_count, sizeof(*bso_files));
        if (bso_files == NULL) {
            fprintf(stderr, "cld: out of memory allocating BSO object list\n");
            goto failure;
        }

        for (parsed_object_count = 0; parsed_object_count < input_count; ++parsed_object_count) {
            if (!cld_parse_bslash_object(input_paths[parsed_object_count], &bso_files[parsed_object_count], &error)) {
                fprintf(stderr, "cld: %s\n", error.message);
                goto failure;
            }
        }

        if (!cld_link_bso_objects(bso_files, input_count, &options, &error)) {
            fprintf(stderr, "cld: %s\n", error.message);
            goto failure;
        }
    } else {
        fprintf(stderr, "cld: unsupported object format for target %s\n", options.target->name);
        goto failure;
    }

    fprintf(stdout, "cld: wrote %s output for target %s to %s\n",
            cld_output_kind_name(options.output_kind),
            options.target->name,
            options.output_path);

    if (object_files != NULL) {
        for (parsed_object_count = 0; parsed_object_count < input_count; ++parsed_object_count) {
            cld_free_macho_object(&object_files[parsed_object_count]);
        }
    }
    if (bso_files != NULL) {
        for (parsed_object_count = 0; parsed_object_count < input_count; ++parsed_object_count) {
            cld_free_bso_object(&bso_files[parsed_object_count]);
        }
    }
    free(object_files);
    free(bso_files);
    free(input_paths);
    return 0;

failure:
    if (object_files != NULL) {
        for (size_t object_index = 0; object_index < parsed_object_count; ++object_index) {
            cld_free_macho_object(&object_files[object_index]);
        }
    }
    if (bso_files != NULL) {
        for (size_t object_index = 0; object_index < parsed_object_count; ++object_index) {
            cld_free_bso_object(&bso_files[object_index]);
        }
    }
    free(object_files);
    free(bso_files);
    free(input_paths);
    return 1;
}

