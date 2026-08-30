#include "mpcops.hpp"
#include "bitutils.hpp"

// P0 and P1 both hold additive shares of x (shares are x0 and x1) and y
// (shares are y0 and y1); compute additive shares of z = x*y =
// (x0+x1)*(y0+y1). x, y, and z are each at most nbits bits long.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 MultTriple
void mpc_mul(MPCTIO &tio, yield_t &yield,
    RegAS &z, RegAS x, RegAS y,
    nbits_t nbits)
{
    const value_t mask = MASKBITS(nbits);
    // Compute z to be an additive share of (x0*y1+y0*x1)
    mpc_cross(tio, yield, z, x, y, nbits);
    // Add x0*y0 (the peer will add x1*y1)
    z.ashare = (z.ashare + x.ashare * y.ashare) & mask;
}

// P0 and P1 both hold additive shares of x (shares are x0 and x1) and y
// (shares are y0 and y1); compute additive shares of z = x0*y1 + y0*x1.
// x, y, and z are each at most nbits bits long.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 MultTriple
void mpc_cross(MPCTIO &tio, yield_t &yield,
    RegAS &z, RegAS x, RegAS y,
    nbits_t nbits)
{
    const value_t mask = MASKBITS(nbits);
    size_t nbytes = BITBYTES(nbits);
    auto [X, Y, Z] = tio.multtriple(yield);

    // Send x+X and y+Y
    value_t blind_x = (x.ashare + X) & mask;
    value_t blind_y = (y.ashare + Y) & mask;

    tio.queue_peer(&blind_x, nbytes);
    tio.queue_peer(&blind_y, nbytes);

    yield();

    // Read the peer's x+X and y+Y
    value_t  peer_blind_x=0, peer_blind_y=0;
    tio.recv_peer(&peer_blind_x, nbytes);
    tio.recv_peer(&peer_blind_y, nbytes);

    z.ashare = ((x.ashare * peer_blind_y) - (Y * peer_blind_x) + Z) & mask;
}

// P0 holds the (complete) value x, P1 holds the (complete) value y;
// compute additive shares of z = x*y.  x, y, and z are each at most
// nbits bits long.  The parameter is called x, but P1 will pass y
// there.  When called by another task during preprocessing, set tally
// to false so that the required halftriples aren't accounted for
// separately from the main preprocessing task.
//
// Cost:
// 1 word sent in 1 message
// consumes 1 HalfTriple
void mpc_valuemul(MPCTIO &tio, yield_t &yield,
    RegAS &z, value_t x,
    nbits_t nbits, bool tally)
{
    const value_t mask = MASKBITS(nbits);
    size_t nbytes = BITBYTES(nbits);
    auto [X, Z] = tio.halftriple(yield, tally);

    // Send x+X
    value_t blind_x = (x + X) & mask;

    tio.queue_peer(&blind_x, nbytes);

    yield();

    // Read the peer's y+Y
    value_t  peer_blind_y=0;
    tio.recv_peer(&peer_blind_y, nbytes);

    if (tio.player() == 0) {
        z.ashare = ((x * peer_blind_y) + Z) & mask;
    } else if (tio.player() == 1) {
        z.ashare = ((-X * peer_blind_y) + Z) & mask;
    }
}

// P0 and P1 hold bit shares f0 and f1 of the single bit f, and additive
// shares y0 and y1 of the value y; compute additive shares of
// z = f * y = (f0 XOR f1) * (y0 + y1).  y and z are each at most nbits
// bits long.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 MultTriple
void mpc_flagmult(MPCTIO &tio, yield_t &yield,
    RegAS &z, RegBS f, RegAS y,
    nbits_t nbits)
{
    const value_t mask = MASKBITS(nbits);

    // Compute additive shares of [(1-2*f0)*y0]*f1 + [(1-2*f1)*y1]*f0
    value_t bs_fval = value_t(f.bshare);
    RegAS fval;
    fval.ashare = bs_fval;
    mpc_cross(tio, yield, z, y*(1-2*bs_fval), fval, nbits);

    // Add f0*y0 (and the peer will add f1*y1)
    z.ashare = (z.ashare + bs_fval*y.ashare) & mask;

    // Now the shares add up to:
    // [(1-2*f0)*y0]*f1 + [(1-2*f1)*y1]*f0 + f0*y0 + f1*y1
    // which you can rearrange to see that it's equal to the desired
    // (f0 + f1 - 2*f0*f1)*(y0+y1), since f0 XOR f1 = (f0 + f1 - 2*f0*f1).
}

// P0 and P1 hold bit shares f0 and f1 of the single bit f, and additive
// shares of the values x and y; compute additive shares of z, where
// z = x if f=0 and z = y if f=1.  x, y, and z are each at most nbits
// bits long.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 MultTriple
void mpc_select(MPCTIO &tio, yield_t &yield,
    RegAS &z, RegBS f, RegAS x, RegAS y,
    nbits_t nbits)
{
    const value_t mask = MASKBITS(nbits);

    // The desired result is z = x + f * (y-x)
    mpc_flagmult(tio, yield, z, f, y-x, nbits);
    z.ashare = (z.ashare + x.ashare) & mask;
}

// P0 and P1 hold bit shares f0 and f1 of the single bit f, and XOR
// shares of the values x and y; compute XOR shares of z, where z = x if
// f=0 and z = y if f=1.  x, y, and z are each at most nbits bits long.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 SelectTriple
void mpc_select(MPCTIO &tio, yield_t &yield,
    RegXS &z, RegBS f, RegXS x, RegXS y,
    nbits_t nbits)
{
    const value_t mask = MASKBITS(nbits);
    size_t nbytes = BITBYTES(nbits);
    // Sign-extend f (so 0 -> 0000...0; 1 -> 1111...1)
    value_t fext = (-value_t(f.bshare)) & mask;

    // Compute XOR shares of f & (x ^ y)
    auto [X, Y, Z] = tio.valselecttriple(yield);

    bit_t blind_f = f.bshare ^ X;
    value_t d = (x.xshare ^ y.xshare) & mask;
    value_t blind_d = (d ^ Y) & mask;

    // Send the blinded values
    tio.queue_peer(&blind_f, sizeof(blind_f));
    tio.queue_peer(&blind_d, nbytes);

    yield();

    // Read the peer's values
    bit_t peer_blind_f = 0;
    value_t peer_blind_d;
    tio.recv_peer(&peer_blind_f, sizeof(peer_blind_f));
    peer_blind_f &= 1;
    tio.recv_peer(&peer_blind_d, nbytes);
    peer_blind_d &= mask;

    // Compute our share of f ? x : y = (f * (x ^ y))^x
    value_t peer_blind_fext = -value_t(peer_blind_f);
    z.xshare = ((fext & peer_blind_d) ^ (Y & peer_blind_fext) ^
            (fext & d) ^ (Z ^ x.xshare)) & mask;
}

// P0 and P1 hold bit shares f0 and f1 of the single bit f, and bit
// shares of the values x and y; compute bit shares of z, where
// z = x if f=0 and z = y if f=1.
//
// Cost:
// 1 byte sent in 1 message
// consumes 1/64 AndTriple
void mpc_select(MPCTIO &tio, yield_t &yield,
    RegBS &z, RegBS f, RegBS x, RegBS y)
{
    // The desired result is z = x ^ (f & (y^x))
    mpc_and(tio, yield, z, f, y^x);
    z ^= x;
}

// P0 and P1 hold bit shares f0 and f1 of the single bit f, and additive
// shares of the values x and y. Obliviously swap x and y; that is,
// replace x and y with new additive sharings of x and y respectively
// (if f=0) or y and x respectively (if f=1).  x and y are each at most
// nbits bits long.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 MultTriple
void mpc_oswap(MPCTIO &tio, yield_t &yield,
    RegAS &x, RegAS &y, RegBS f,
    nbits_t nbits)
{
    const value_t mask = MASKBITS(nbits);

    // Let s = f*(y-x).  Then the desired result is
    // x <- x + s, y <- y - s.
    RegAS s;
    mpc_flagmult(tio, yield, s, f, y-x, nbits);
    x.ashare = (x.ashare + s.ashare) & mask;
    y.ashare = (y.ashare - s.ashare) & mask;
}

// P0 and P1 hold XOR shares of x. Compute additive shares of the same
// x. x is at most nbits bits long.  When called by another task during
// preprocessing, set tally to false so that the required halftriples
// aren't accounted for separately from the main preprocessing task.
//
// Cost:
// nbits-1 words sent in 1 message
// consumes nbits-1 HalfTriples
void mpc_xs_to_as(MPCTIO &tio, yield_t &yield,
    RegAS &as_x, RegXS xs_x,
    nbits_t nbits, bool tally)
{
    const value_t mask = MASKBITS(nbits);

    // We use the fact that for any nbits-bit A and B,
    // A+B = (A XOR B) + 2*(A AND B)  mod 2^nbits
    // so if we have additive shares C0 and C1 of 2*(A AND B)
    // (so C0 + C1 = 2*(A AND B)), then (A-C0) and (B-C1) are
    // additive shares of (A XOR B).

    // To get additive shares of 2*(A AND B) (mod 2^nbits), we first
    // note that we can ignore the top bits of A and B, since the
    // multiplication by 2 will shift it out of the nbits-bit range.
    // For the other bits, use valuemult to get the product of the
    // corresponding bit i of A and B (i=0..nbits-2), and compute
    // C = \sum_i 2^{i+1} * (A_i * B_i).

    // This can all be done in a single message, using the coroutine
    // mechanism to have all nbits-1 instances of valuemult queue their
    // message, then yield, so that all of their messages get sent at
    // once, then each will read their results.

    RegAS as_bitand[nbits-1];
    std::vector<coro_t> coroutines;
    for (nbits_t i=0; i<nbits-1; ++i) {
        coroutines.emplace_back(
            [&tio, &as_bitand, &xs_x, i, nbits, tally](yield_t &yield) {
                mpc_valuemul(tio, yield, as_bitand[i],
                    (xs_x.xshare>>i)&1, nbits, tally);
            });
    }
    run_coroutines(yield, coroutines);
    value_t as_C = 0;
    for (nbits_t i=0; i<nbits-1; ++i) {
        as_C += (as_bitand[i].ashare<<(i+1));
    }
    as_x.ashare = (xs_x.xshare - as_C) & mask;
}

// P0 and P1 hold XOR shares x0 and x1 of x. x is at most nbits bits
// long. Return x to P0 and P1 (and 0 to P2).
//
// Cost: 1 word sent in 1 message
value_t mpc_reconstruct(MPCTIO &tio, yield_t &yield,
    RegXS x, nbits_t nbits)
{
    RegXS res;
    size_t nbytes = BITBYTES(nbits);
    if (tio.player() < 2) {
        tio.queue_peer(&x, nbytes);
        yield();
        tio.recv_peer(&res, nbytes);
        res ^= x;
    } else {
        yield();
    }
    return res.xshare;
}

// P0 and P1 hold additive shares x0 and x1 of x. x is at most nbits
// bits long. Return x to P0 and P1 (and 0 to P2).
//
// Cost: 1 word sent in 1 message
value_t mpc_reconstruct(MPCTIO &tio, yield_t &yield,
    RegAS x, nbits_t nbits)
{
    RegAS res;
    size_t nbytes = BITBYTES(nbits);
    if (tio.player() < 2) {
        tio.queue_peer(&x, nbytes);
        yield();
        tio.recv_peer(&res, nbytes);
        res += x;
    } else {
        yield();
    }
    return res.ashare;
}

// P0 and P1 hold bit shares f0 and f1 of f. Return f to P0 and P1 (and
// 0 to P2).
//
// Cost: 1 word sent in 1 message
bool mpc_reconstruct(MPCTIO &tio, yield_t &yield, RegBS f)
{
    RegBS res;
    if (tio.player() < 2) {
        tio.queue_peer(&f, 1);
        yield();
        tio.recv_peer(&res, 1);
        res ^= f;
    } else {
        yield();
    }
    return res.bshare;
}

// P0 and P1 hold bit shares of f, and DPFnode XOR shares x0,y0 and
// x1,y1 of x and y.  Set z to x=x0^x1 if f=0 and to y=y0^y1 if f=1.
//
// Cost:
// 6 64-bit words sent in 2 messages
// consumes one AndTriple
void mpc_reconstruct_choice(MPCTIO &tio, yield_t &yield,
    DPFnode &z, RegBS f, DPFnode x, DPFnode y)
{
    // Sign-extend f (so 0 -> 0000...0; 1 -> 1111...1)
    DPFnode fext = if128_mask[f.bshare];

    // Compute XOR shares of f & (x ^ y)
    auto [X, Y, Z] = tio.nodeselecttriple(yield);

    bit_t blind_f = f.bshare ^ X;
    DPFnode d = x ^ y;
    DPFnode blind_d = d ^ Y;

    // Send the blinded values
    tio.queue_peer(&blind_f, sizeof(blind_f));
    tio.queue_peer(&blind_d, sizeof(blind_d));

    yield();

    // Read the peer's values
    bit_t peer_blind_f = 0;
    DPFnode peer_blind_d;
    tio.recv_peer(&peer_blind_f, sizeof(peer_blind_f));
    tio.recv_peer(&peer_blind_d, sizeof(peer_blind_d));

    // Compute _our share_ of f ? x : y = (f * (x ^ y))^x
    DPFnode peer_blind_fext = if128_mask[peer_blind_f];
    DPFnode zshare =
            (fext & peer_blind_d) ^ (Y & peer_blind_fext) ^
            (fext & d) ^ (Z ^ x);

    // Now exchange shares
    tio.queue_peer(&zshare, sizeof(zshare));

    yield();

    DPFnode peer_zshare;
    tio.recv_peer(&peer_zshare, sizeof(peer_zshare));

    z = zshare ^ peer_zshare;
}

// P0 and P1 hold bit shares of x and y.  Set z to bit shares of x & y.
//
// Cost:
// 1 byte sent in 1 message
// consumes 1/64 AndTriple
void mpc_and(MPCTIO &tio, yield_t &yield,
    RegBS &z, RegBS x, RegBS y)
{
    //std::cout<<"Array Value "<<mpc_reconstruct(tio,yield,x) <<" z_Value "<<mpc_reconstruct(tio,yield,y)<<" ";
    // Compute XOR shares of x & y
    auto T = tio.bitselecttriple(yield);
    bit_t blind_x = x.bshare ^ T.X;
    bit_t blind_y = y.bshare ^ T.Y;

    // Send the blinded values
    uint8_t v = (blind_x << 1) | blind_y;
    tio.queue_peer(&v, sizeof(v));

    yield();

    // Read the peer's values
    bit_t peer_blind_x = 0;
    bit_t peer_blind_y = 0;
    uint8_t peer_v = 0;
    tio.recv_peer(&peer_v, sizeof(peer_v));
    peer_blind_x = (peer_v >> 1) & 1;
    peer_blind_y = peer_v & 1;

    // Compute our share of x & y
    z.bshare = (x.bshare & peer_blind_y) ^ (T.Y & peer_blind_x) ^
        (x.bshare & y.bshare) ^ T.Z;
       // std::cout<<mpc_reconstruct(tio,yield,z)<<" ";

}

// P0 and P1 hold bit shares of x and y.  Set z to bit shares of x | y.
//
// Cost:
// 1 byte sent in 1 message
// consumes 1/64 AndTriple
void mpc_or(MPCTIO &tio, yield_t &yield,
    RegBS &z, RegBS x, RegBS y)
{
    if (tio.player() == 0) {
        x.bshare = !x.bshare;
        y.bshare = !y.bshare;
    }
    mpc_and(tio, yield, z, x, y);
    if (tio.player() == 0) {
        z.bshare = !z.bshare;
    }
}


// P0 and P1 hold XOR shares x0 and x1 of x, and y0 and y1 of y;
// compute XOR shares of z = x & y.
//
// Cost:
// 2 words sent in 1 message
// consumes 1 AndTriple
void mpc_and(MPCTIO &tio, yield_t &yield, RegXS &z, const RegXS &x, const RegXS &y)
{
    // Fetch an AND triple (A, B, C) such that (A_i & B_i) = C_i for each bit i
    auto [A, B, C] = tio.andtriple(yield);

    // Compute blinded values by XORing with the triple shares
    value_t blind_x = x.xshare ^ A;
    value_t blind_y = y.xshare ^ B;

    // Send the FULL blinded 64-bit values to the peer
    tio.queue_peer(&blind_x, sizeof(blind_x));
    tio.queue_peer(&blind_y, sizeof(blind_y));

    yield();

    // Receive the peer's FULL blinded 64-bit values
    value_t peer_blind_x = 0;
    value_t peer_blind_y = 0;
    tio.recv_peer(&peer_blind_x, sizeof(peer_blind_x));
    tio.recv_peer(&peer_blind_y, sizeof(peer_blind_y));

    // Beaver's method for AND: z_i = (x_i & y_j) ^ (x_j & y_i) ^ (x_i & y_i) ^ c_i
    // Since we are P0, the peer is P1 (j=1). Our share is x0, y0.
    z.xshare = (x.xshare & y.xshare) ^ (x.xshare & peer_blind_y) ^ (B & peer_blind_x) ^ C;
}



// void mpc_xor_if(MPCTIO &tio, yield_t &yield,  const RegXS &x, const RegXS &y, const RegXS &condition, unsigned player)
// {
//         RegXS not_condition;
//         not_condition.xshare = 1 - condition.xshare; // not operation
//         RegXS mpc_and_out; 
//         mpc_and(tio, yield,  mpc_and_out, condition, y, 64); // remeber that n_bits is hardcoded to 64

//         x = condition ^ mpc_and_out;
// }

void mpc_xor_if(MPCTIO &tio, yield_t &yield, RegXS &x, const RegXS &insert_value, RegXS &condition,RegXS &input, unsigned player) {
    RegXS not_input;
    not_input.xshare = 1 - input.xshare; // NOT operation
    RegBS not_boolean; 
    if(not_input.xshare==1)
    not_boolean.bshare = true;
    else
    not_boolean.bshare = false;

    RegBS insert;
    if(insert_value.xshare==1)
    insert.bshare = true;
    else
    insert.bshare = false;

    //std::cout<<" not value "<<not_input.xshare<<" insert value "<< insert_value.xshare<<" ";
    RegXS mpc_and_out;
    RegBS mpcand;

    mpc_and(tio, yield, mpcand,not_boolean,insert); // AND with 64-bit hardcoded
    if(mpcand.bshare ==true)
    mpc_and_out.xshare = 1;
    else
    mpc_and_out.xshare=0;

    //std::cout<<"mpc and "<< mpc_and_out<<" and output "<<mpc_reconstruct(tio,yield,mpc_and_out,64)<<" ";
    x.xshare = condition.xshare ^ mpc_and_out.xshare; // XOR operation on xshare
}


void mpc_not(RegXS &z, RegXS x, nbits_t nbits) {
    const value_t mask = MASKBITS(nbits);
    z.xshare = (~x.xshare) & mask;
    std::cout<<z.xshare<<" ";
}


//##nayandEditzs##

void mpc_public_shift_right(RegXS &z, const RegXS &x, uint8_t amount) {
    // For XOR sharing, a public shift is just a local shift on each share.
    z.xshare = x.xshare >> amount;
}

void mpc_get_bit(RegBS &out, const RegXS &word, uint8_t public_idx) {
    // 1. Shift the word right by the public index
    RegXS shifted_word;
    mpc_public_shift_right(shifted_word, word, public_idx);

    // 2. The LSB of the shifted word is now our desired bit.
    // We can extract this locally from each share.
    out.bshare = (shifted_word.xshare & 1);
}

void mpc_set_bit(MPCTIO &tio, yield_t &yield, RegXS &word, uint8_t public_idx, const RegBS &new_bit_val, unsigned player) {
    // 1. Extract the current bit at the target position from the word.
    RegBS old_bit;
    mpc_get_bit(old_bit, word, public_idx);

    // 2. Calculate if the bit needs to be flipped.
    // (old_bit XOR new_bit_val) will be 1 if they are different, 0 otherwise.
    RegBS delta_bit;
    delta_bit.bshare = old_bit.bshare ^ new_bit_val.bshare;

    // 3. SECURELY RECONSTRUCT the 1-bit result. This is the crucial step.
    // It requires communication but ensures both parties agree on the action.
    bool needs_flip = mpc_reconstruct(tio, yield, delta_bit);

    // 4. Both parties now know the public outcome and create the mask locally.
    value_t mask = 0;
    if (needs_flip) {
        mask = (value_t)1 << public_idx;
    }

    // 5. Secret-share the mask. P0 holds the value, P1 holds 0.
    RegXS delta_word;
    if (player == 0) {
        delta_word.xshare = mask;
    } else {
        delta_word.xshare = 0;
    }

    // 6. Apply the correctly shared mask to the original word.
    word.xshare ^= delta_word.xshare;
}
void mpc_and_public(MPCTIO &tio, yield_t &yield, RegXS &z, const RegXS &x, value_t public_mask, unsigned player) {
    // Represent the public mask as a secret share where P0 holds the whole value
    RegXS y_mask;
    y_mask.xshare = (player == 0) ? public_mask : 0;

    // Call the existing MPC protocol for ANDing two secret values
    mpc_and(tio, yield, z, x, y_mask);
}
void mpc_secret_shift_right(RegXS &z, const RegXS &x, uint8_t amount) {
    // A public shift on an XOR-shared value is just a local shift on each share.
    //similar function as mpc_public_shift_right above (kept for defination matching)
    z.xshare = x.xshare >> amount;
}

void mpc_secret_shift_left(RegXS &z, const RegXS &x, uint8_t amount) {
    // A public shift on an XOR-shared value is just a local shift on each share.
    z.xshare = x.xshare << amount;
}


//##nayandEditzs##

// void mpc_bitwise_not(MPCTIO &tio, yield_t &yield, RegXS &z, const RegXS &x, nbits_t nbits) {
//     const value_t mask = MASKBITS(static_cast<size_t>(nbits));

//     // Compute NOT using MPC principles
//     value_t x_reconstructed = mpc_reconstruct(tio, yield, x, nbits);  // Reconstruct the original value
//     value_t not_x = (~x_reconstructed) & mask;  // Perform bitwise NOT on the reconstructed value

//     // Secret-share the NOT result again
//     z = mpc_secret_share(tio, yield, not_x, nbits);
// }


