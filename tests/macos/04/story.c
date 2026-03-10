#include "game.h"

#include <stdio.h>

int cld_play_intro(GameState *state) {
    int choice;

    choice = cld_prompt_choice("Do you enter the observatory or walk away?",
                               'l',
                               "Leave the ruins to the storm",
                               'e',
                               "Enter the observatory");
    if (choice == 0) {
        printf("\n");
        printf("You leave the storm to swallow the gate.\n");
        printf("\n");
        return 0;
    }

    state->courage += 2;
    printf("\n");
    printf("You step inside and the bronze floor hums beneath your boots.\n");
    printf("Dust falls from the dome as constellations begin moving overhead.\n");
    cld_print_status(state);
    return 1;
}

int cld_play_ruins(GameState *state) {
    int choice;

    choice = cld_prompt_choice("At the core you find a star-map table and a locked crown vault.",
                               'm',
                               "Take the map cylinder and run for daylight",
                               'v',
                               "Open the vault and claim the crown");
    if (choice == 0) {
        state->relics += 1;
        printf("\n");
        printf("You pull a star-map cylinder free and hear the sea wall cracking.\n");
        cld_print_status(state);
        return 0;
    }

    state->courage += 1;
    state->relics += 2;
    printf("\n");
    printf("The vault opens and an old sun-crown sparks to life in your hands.\n");
    cld_print_status(state);
    return 1;
}