/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 **********************************************************************/

#ifndef SECP256K1_ECMULT_CONST_H
#define SECP256K1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

static void secp256k1_ecmult_const(secp256k1_gej *r, const secp256k1_ge *a, const secp256k1_scalar *q);

#endif /* SECP256K1_ECMULT_CONST_H */
