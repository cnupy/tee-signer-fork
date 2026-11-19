/* G1 arithmetic on public points for dv-split (commitments.go). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "blst.h"

/*
 * sum(scalars[i] * points[i]) in G1. points: n compressed public keys of 48
 * bytes. scalars: n little-endian 32-byte scalars. Returns 0, or 1 if a
 * point does not decode or is not in the group.
 */
int admin_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48])
{
    blst_p1 acc, p, term;
    blst_p1_affine a;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < n; i++) {
        if (blst_p1_uncompress(&a, points + 48 * i) != BLST_SUCCESS ||
            !blst_p1_affine_in_g1(&a))
            return 1;
        blst_p1_from_affine(&p, &a);
        blst_p1_mult(&term, &p, scalars + 32 * i, 255);
        if (i == 0)
            acc = term;
        else
            blst_p1_add_or_double(&acc, &acc, &term);
    }
    blst_p1_compress(out, &acc);
    return 0;
}
