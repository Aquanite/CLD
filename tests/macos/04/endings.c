#include "game.h"

#include <stdio.h>

int cld_finish_escape(const GameState *state) {
    printf("\n");
    printf("You escape with a single relic while the observatory sinks behind you.\n");
    printf("Ending: Tide Runner\n");
    printf("\n");
    return 21 + state->relics;
}

int cld_finish_crown(const GameState *state) {
    printf("\n");
    printf("You raise the crown and restart the storm-breakers above the harbor.\n");
    printf("Ending: Harbor Keeper\n");
    printf("\n");
    return 40 + state->courage + state->relics;
}

int cld_finish_retreat(const GameState *state) {
    printf("\n");
    printf("You survive, but the story belongs to someone braver.\n");
    printf("Ending: Quiet Shore\n");
    printf("\n");
    return 5 + state->courage + state->relics;
}