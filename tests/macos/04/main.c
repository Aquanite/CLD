#include "game.h"

int run_game(void) {
    GameState state;

    state.courage = 1;
    state.relics = 0;

    cld_print_banner();
    if (cld_play_intro(&state) == 0) {
        return cld_finish_retreat(&state);
    }
    if (cld_play_ruins(&state) == 0) {
        return cld_finish_escape(&state);
    }
    return cld_finish_crown(&state);
}

int main(void) {
    return run_game();
}