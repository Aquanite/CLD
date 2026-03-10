#include "game.h"

#include <ctype.h>
#include <stdio.h>

const char *const cld_game_title = "The Clockwork Gate";

void cld_print_banner(void) {
    printf("\n");
    printf("==================== %s ====================\n", cld_game_title);
    printf("\n");
    printf("You stand before a buried observatory as thunder rolls over the sea.\n");
    printf("Salt spray hisses across the bronze doors while old engines wake below.\n");
    printf("\n");
}

int cld_prompt_choice(const char *question,
                      char first_key,
                      const char *first,
                      char second_key,
                      const char *second) {
    char buffer[64];
    int selected_key;

    printf("%s\n", question);
    printf("\n");
    printf("  [%c] %s\n", toupper((unsigned char) first_key), first);
    printf("  [%c] %s\n", toupper((unsigned char) second_key), second);
    printf("\n");
    printf("Choose a key: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        return 0;
    }

    selected_key = tolower((unsigned char) buffer[0]);
    if (selected_key == tolower((unsigned char) first_key)) {
        return 0;
    }
    if (selected_key == tolower((unsigned char) second_key)) {
        return 1;
    }

    printf("\n");
    printf("The gate ignores that answer, so fate takes the safer road.\n");
    printf("\n");
    return 0;
}

void cld_print_status(const GameState *state) {
    printf("\n");
    printf("status: courage=%d relics=%d\n", state->courage, state->relics);
    printf("\n");
}