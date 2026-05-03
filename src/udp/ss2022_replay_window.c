#include "ss2022_internal.h"

void ss2022_replay_window_init(struct ss2022_replay_window *w) {
    if (w != NULL) {
        memset(w, 0, sizeof(*w));
    }
}

int ss2022_replay_window_check(const struct ss2022_replay_window *w, uint64_t id) {
    if (w == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (id > w->highest) {
        return SS2022_OK;
    }
    uint64_t offset = w->highest - id;
    if (offset >= SS2022_REPLAY_WINDOW_BITS) {
        return SS2022_ERR_REPLAY;
    }
    uint64_t bit = UINT64_C(1) << (offset % 64u);
    if ((w->bitmap[offset / 64u] & bit) != 0u) {
        return SS2022_ERR_REPLAY;
    }
    return SS2022_OK;
}

void ss2022_replay_window_commit(struct ss2022_replay_window *w, uint64_t id) {
    if (w == NULL) {
        return;
    }
    if (id > w->highest) {
        uint64_t shift = id - w->highest;
        if (shift >= SS2022_REPLAY_WINDOW_BITS) {
            memset(w->bitmap, 0, sizeof(w->bitmap));
        } else {
            uint64_t word_shift = shift / 64u;
            unsigned bit_shift = (unsigned)(shift % 64u);
            for (size_t i = SS2022_REPLAY_WINDOW_BITS / 64u; i > 0u; i--) {
                size_t idx = i - 1u;
                uint64_t value = 0u;
                if (idx >= word_shift) {
                    value = w->bitmap[idx - word_shift] << bit_shift;
                    if (bit_shift != 0u && idx > word_shift) {
                        value |= w->bitmap[idx - word_shift - 1u] >> (64u - bit_shift);
                    }
                }
                w->bitmap[idx] = value;
            }
        }
        w->highest = id;
    }
    uint64_t offset = w->highest - id;
    if (offset < SS2022_REPLAY_WINDOW_BITS) {
        w->bitmap[offset / 64u] |= UINT64_C(1) << (offset % 64u);
    }
}
