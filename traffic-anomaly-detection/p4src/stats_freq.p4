#include <core.p4>
#include <v1model.p4>

/***
 * ! Problem: we can't initialize the register to all 0. bmv2 seems to
 * do it, but the spec doesn't say anything about it - in fact, GH issues
 * state explicitly that you should **not** assume it to be zero-initialized.
 * We could probably work around it somehow, but it seems like a ridiculous amount
 * of work for something simple.
 ***/

/* TODO: Find a better way to store this because this is technically kind of a struct.
 * But there's no way to persist structs across flows in P4, I think.
 * We allow the user to access the data from this "struct" by declaring a struct inout
 * that the user gives us and we populate (so they get it in an actual struct).
 *
 * stats_data is an array that contains:
 * [0]: N
 * [1]: Xsum = Ybar
 * [2]: Xsum_sq
 * [3]: Last clear request (initially 0).
 * where Y = NX. We can calculate Nx quite simply for any new x we want to compare
 * with the existing values, so this allows us to do comparisons.
 ***/

register<bit<32>>(4 * STAT_FREQ_COUNTER_N) stats_data;
register<bit<16>>(STAT_FREQ_COUNTER_SIZE * STAT_FREQ_COUNTER_N) stats_freq_internal;
register<bit<32>>(STAT_FREQ_COUNTER_SIZE * STAT_FREQ_COUNTER_N) stats_last_clear;

// zeros a bucket, dropping its values from Xsum and Xsum_sq.

action read_bucket(out bit<16> val, bit<32> idx, bit<32> counter_idx) {
    bit<32> val_write = (counter_idx * STAT_FREQ_COUNTER_SIZE) + idx; // offset
    stats_freq_internal.read(val, val_write);
}

action drop_bucket(bit<32> idx, bit<32> counter_idx) {
    bit<32> val_write = (counter_idx * STAT_FREQ_COUNTER_SIZE) + idx; // offset
    bit<32> data_offset = counter_idx * 4;
    bit<32> tmp;
    bit<16> val;
    stats_freq_internal.read(val, val_write);

    stats_data.read(tmp, data_offset);
    if (val > 0) {
        tmp = tmp - 1;
    }
    stats_data.write(data_offset, tmp);

    stats_data.read(tmp, data_offset + 1);
    tmp = tmp - (bit<32>)val;
    stats_data.write(data_offset + 1, tmp);

    stats_data.read(tmp, data_offset + 2);
    tmp = tmp - ((bit<32>)val * (bit<32>)val);
    stats_data.write(data_offset + 2, tmp);

    stats_freq_internal.write(val_write, 0);
}

action stats_clear(bit<32> counter_idx) {
    bit<32> data_offset = counter_idx * 4;

    stats_data.write(data_offset, 0);
    stats_data.write(data_offset + 1, 0);
    stats_data.write(data_offset + 2, 0);

    bit<32> ts;
    stats_data.read(ts, data_offset + 3);
    stats_data.write(data_offset + 3, ts + 1);
}

action stats_push_freq(out bit<16> freq_value, bit<32> idx, bit<32> counter_idx) {
    bit<32> val_write = (counter_idx * STAT_FREQ_COUNTER_SIZE) + idx; // offset
    bit<32> tmp;
    bit<32> ts;
    bit<32> ts_actual;
    bit<32> data_offset = counter_idx * 4;

    // ** Critical section stat_data

    stats_data.read(tmp, data_offset + 1);
    tmp = tmp + 1;
    stats_data.write(data_offset + 1, tmp);

    stats_data.read(tmp, data_offset + 2);
    stats_freq_internal.read(freq_value, val_write);
    
    // Check if we need to clear the value before using it.
    stats_last_clear.read(ts_actual, val_write);
    stats_data.read(ts, data_offset + 3);
    if (ts_actual < ts) {
        freq_value = 0; // account for clear
    }
    stats_last_clear.write(val_write, ts);

    stats_freq_internal.write(val_write, freq_value + 1);

    /***
     * Derivation:
     * Xsum_sq_new = Xsum_sq - X^2 + (X + 1)^2
     *             = Xsum_sq + 2X + 1
     ***/  
    tmp = tmp + (bit<32>)(freq_value * 16w2) + 32w1;

    // Compute VarNX and StdNX in request instead to minimize time spent here.
    stats_data.write(data_offset + 2, tmp);

    stats_data.read(tmp, data_offset);
    if (freq_value == 0) { // new contender
        tmp = tmp + 1;
    }
    stats_data.write(data_offset, tmp);
}

struct stats_t {
    bit<32> N;
    bit<32> Xsum;
    bit<32> Xsum_sq;
    bit<32> VarNX;
    bit<32> StdNX;
}

// Allows extracting the stats about the data currently pushed in so far.
action stats_get_data(out stats_t stat_struct, bit<32> counter_idx) {
    stats_data.read(stat_struct.N, (counter_idx * 4));
    stats_data.read(stat_struct.Xsum, (counter_idx * 4) + 1);
    stats_data.read(stat_struct.Xsum_sq, (counter_idx * 4) + 2);

    /***
    * Derivation:
    * Var(NX) = E[(NX)^2] - E[NX]^2
    *         = Sum((NX)^2)/N - (Xsum)^2
    *         = N^2/N Xsum_sq - (Xsum)^2
    *         = N(Xsum_sq) - (Xsum)^2
    ***/
    stat_struct.VarNX = stat_struct.N * stat_struct.Xsum_sq - (stat_struct.Xsum * stat_struct.Xsum);

    // Approximation of sqrt(N):
    // https://github.com/EOSIO/logchain/blob/master/doc/sqrt.md
    bit<32> stdY = stat_struct.VarNX;

    if (stdY > 1) {
        bit<8> msb_x = 0;
        // Unrolled MSB matching up to 2^31 -  this is probably extremely slow
        // We can use a LPM match table for this, but we don't have the luxury of jumping
        // into a table... There also aren't any P4 primitives for MSB matching, sadly.
        
        if      (stdY & 0b10000000000000000000000000000000 != 0) msb_x = 31;
        else if (stdY & 0b1000000000000000000000000000000  != 0) msb_x = 30;
        else if (stdY & 0b100000000000000000000000000000   != 0) msb_x = 29;
        else if (stdY & 0b10000000000000000000000000000    != 0) msb_x = 28;
        else if (stdY & 0b1000000000000000000000000000     != 0) msb_x = 27;
        else if (stdY & 0b100000000000000000000000000      != 0) msb_x = 26;
        else if (stdY & 0b10000000000000000000000000       != 0) msb_x = 25;
        else if (stdY & 0b1000000000000000000000000        != 0) msb_x = 24;
        else if (stdY & 0b100000000000000000000000         != 0) msb_x = 23;
        else if (stdY & 0b10000000000000000000000          != 0) msb_x = 22;
        else if (stdY & 0b1000000000000000000000           != 0) msb_x = 21;
        else if (stdY & 0b100000000000000000000            != 0) msb_x = 20;
        else if (stdY & 0b10000000000000000000             != 0) msb_x = 19;
        else if (stdY & 0b1000000000000000000              != 0) msb_x = 18;
        else if (stdY & 0b100000000000000000               != 0) msb_x = 17;
        else if (stdY & 0b10000000000000000                != 0) msb_x = 16;
        else if (stdY & 0b1000000000000000                 != 0) msb_x = 15;
        else if (stdY & 0b100000000000000                  != 0) msb_x = 14;
        else if (stdY & 0b10000000000000                   != 0) msb_x = 13;
        else if (stdY & 0b1000000000000                    != 0) msb_x = 12;
        else if (stdY & 0b100000000000                     != 0) msb_x = 11;
        else if (stdY & 0b10000000000                      != 0) msb_x = 10;
        else if (stdY & 0b1000000000                       != 0) msb_x = 9;
        else if (stdY & 0b100000000                        != 0) msb_x = 8;
        else if (stdY & 0b10000000                         != 0) msb_x = 7;
        else if (stdY & 0b1000000                          != 0) msb_x = 6;
        else if (stdY & 0b100000                           != 0) msb_x = 5;
        else if (stdY & 0b10000                            != 0) msb_x = 4;
        else if (stdY & 0b1000                             != 0) msb_x = 3;
        else if (stdY & 0b100                              != 0) msb_x = 2;
        else if (stdY & 0b10                               != 0) msb_x = 1;

        bit<8> msb_z = msb_x >> 1;
        bit<32> mantissa_mask = (32w1 << msb_x) - 1;
        bit<32> mantissa_z_hi = 0;
        if (msb_x & 1 != 0) {
            mantissa_z_hi = (32w1 << msb_z);
        }

        bit<32> mantissa_z_lo = (stdY & mantissa_mask) >> (msb_x - msb_z);
        stdY = (32w1 << msb_z) | ((mantissa_z_hi | mantissa_z_lo) >> 1);
    }
    stat_struct.StdNX = stdY;
}