#ifndef TESTS_MACOS_04_GAME_H
#define TESTS_MACOS_04_GAME_H

typedef struct {
    int courage;
    int relics;
} GameState;

extern const char *const cld_game_title;

void cld_print_banner(void);
int cld_prompt_choice(const char *question,
                      char first_key,
                      const char *first,
                      char second_key,
                      const char *second);
void cld_print_status(const GameState *state);

int cld_play_intro(GameState *state);
int cld_play_ruins(GameState *state);
int cld_finish_escape(const GameState *state);
int cld_finish_crown(const GameState *state);
int cld_finish_retreat(const GameState *state);

int run_game(void);

#endif