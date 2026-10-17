/* brute2.c -- exhaustive scan over kI's intermediate  Ry  (= Rf(Rb[2], ..., 90, 9)).
 *
 * Why Ry and not va:  kI's four returned state words and va are ALL functions of
 * this single 32-bit value, while RV is independent of it:
 *
 *    Rc = B2[0] ^ Ry                 (146 ^ Ry)
 *    RF = B2[1] ^ floor(Ry/2^32)     (== 9, unchanged)
 *    Ru = B2[2] ^ floor(Ry/2^16)     (217 ^ Ry>>16)
 *    Rx = B2[3] ^ floor(Ry/2^24)     (202 ^ Ry>>24)
 *    va = ((Rf2 + Rc*0x10001 + RF*0x101 + Ru*0x11 + Rx) % 2147483646) + 1
 *
 * so scanning Ry covers state faults and va faults simultaneously.  Rf2, Rb[]
 * and RV are constants already pinned down by RZ (fully deterministic: the env
 * table resolves 0x2267BA0C -> "number", so kF's t5 = 0x1D88) and by the bk
 * slot table (whose decode is triple-validated by RI/RN handler keys 4/26/56).
 *
 * Oracle, all read before kd()'s loop:
 *    yt = RS()#14 (numparams)              <= 8
 *    yQ = RS()#16 (frame offset)           <= 64
 *    kQ = Rw5 ^ rotl(kE,11) ^ rotl(RV,7)   in (0, 7462)
 *         (16 stream bytes per kd iteration, 119405-byte budget)
 * Expected random survivors: ~66 over 2^32 -- small enough to inspect by hand,
 * and the genuine one is then separated by continuing the parse.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "params.h"

#define M32   0xFFFFFFFFULL
#define RCM   0x7FFFFFFFULL
#define VAMOD 2147483646ULL

static uint8_t DATA[ND + 64];

static inline uint32_t rotl32(uint32_t v, int k) { k &= 31; return k ? ((v << k) | (v >> (32 - k))) : v; }
static inline uint8_t  rotr8(uint32_t x, int n)  { x &= 0xFF; n &= 7; return n ? (uint8_t)(((x >> n) | (x << (8 - n))) & 0xFF) : (uint8_t)x; }

typedef struct { uint32_t Rc, RF, Ru, Rx; int pos; uint32_t vU; } St;

static uint32_t RS(St *s, uint32_t va) {
    uint32_t RW = DATA[s->pos++];
    s->vU = (uint32_t)s->pos;
    uint32_t vU = s->vU, z = RW;
    z = (z + 256 - ((s->Rx + (vU % 256) * 7) % 256)) % 256;
    z = rotr8(z, 3);
    z = (z ^ s->Ru) & M32;
    z = (z + 256 - ((s->Rc + s->RF + (vU % 256) * 0xC3) % 256)) % 256;
    uint32_t Ry = z;
    uint64_t RO = vU % RCM, Rt = va % RCM;
    uint64_t RE = (Rt + RO * P1 + (XV % RCM)) % RCM;
    uint64_t RL = (Rt * 0x101 + RO * P2 + P1 * 0x11) % RCM;
    for (int i = 0; i < 3; i++) {
        uint64_t n1 = (RE * ((RL % 0x10000) + P1 + 0x101) + RL * 0x101 + RO * (0x11 + XV % 0x1F) + Rt) % RCM;
        uint64_t n2 = (RL * ((n1 % 0x10000) + P2 + 0x107) + n1 * 0x81 + RO * (0x17 + A1) + XV) % RCM;
        RE = n1; RL = n2;
    }
    uint32_t RA = (uint32_t)((RE % 256 + (RL % 256) * 3 + (RO % 256) * 5
                   + ((RE - RE % 256) / 256) % 256 + ((RL - RL % 256) / 256) % 256) % 256);
    Ry = (Ry ^ RA) & M32;
    uint32_t R = Ry, v = RW;
    s->Rc = (rotr8((s->Rc + R + s->Rx + (vU % 256)) % 256, 5) ^ v) & M32;
    s->RF = rotr8((s->RF * 5 + v + ((R ^ s->Rc) & M32)) % 256, 2);
    s->Ru = (rotr8((s->Ru + R + v + s->RF + 7) % 256, 5) ^ s->Rx) & M32;
    s->Rx = rotr8((s->Rx + v + R + s->Rc + s->Ru + 7) % 256, 1);
    return Ry;
}
static uint32_t Rw(St *s, uint32_t va) {
    uint32_t a = RS(s, va), b = RS(s, va), c = RS(s, va), d = RS(s, va);
    return (a + d * 16777216u + b * 256u + c * 65536u) & M32;
}

typedef struct { uint32_t ry, va, kE, kz, kP, yE, yt, yl, yQ, kQ; } Res;

static int probe(uint32_t ry, Res *o) {
    uint32_t Rc = (DATA[0] ^ ry) & M32;
    uint32_t RF = DATA[1];
    uint32_t Ru = (DATA[2] ^ (ry >> 16)) & M32;
    uint32_t Rx = (DATA[3] ^ (ry >> 24)) & M32;
    uint32_t va = (uint32_t)(((uint64_t)RF2 + (uint64_t)Rc * 0x10001ULL + (uint64_t)RF * 0x101ULL
                              + (uint64_t)Ru * 0x11ULL + Rx) % VAMOD) + 1;
    St s = { Rc, RF, Ru, Rx, 4, 4 };
    uint32_t kE = Rw(&s, va) ^ RV0;
    uint32_t kz = Rw(&s, va) ^ (rotl32(kE, 5) ^ rotl32(RV0, 11));
    uint32_t kP = Rw(&s, va) ^ (rotl32(kE, 13) ^ rotl32(RV0, 19));
    uint32_t yE = RS(&s, va), yt = RS(&s, va), yl = RS(&s, va), yQ = RS(&s, va);
    uint32_t kQ = Rw(&s, va) ^ (rotl32(kE, 11) ^ rotl32(RV0, 7));
    o->ry = ry; o->va = va; o->kE = kE; o->kz = kz; o->kP = kP;
    o->yE = yE; o->yt = yt; o->yl = yl; o->yQ = yQ; o->kQ = kQ;
    return (yt <= 8 && yQ <= 64 && kQ > 0 && kQ < 7462);
}

static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static FILE *hits; static long nhits = 0; static double prog = 0;
#define NTH 2

static void *worker(void *arg) {
    long id = (long)arg;
    uint64_t span = 0x100000000ULL / NTH;
    uint64_t lo = id * span, hi = (id == NTH - 1) ? 0xFFFFFFFFULL : (lo + span - 1);
    Res r;
    for (uint64_t ry = lo; ry <= hi; ry++) {
        if (probe((uint32_t)ry, &r)) {
            pthread_mutex_lock(&mx); nhits++;
            fprintf(hits, "ry=%10llu va=%10u kQ=%6u yt=%3u yQ=%3u yE=%3u yl=%3u kE=0x%08X kz=0x%08X kP=%10u\n",
                    (unsigned long long)ry, r.va, r.kQ, r.yt, r.yQ, r.yE, r.yl, r.kE, r.kz, r.kP);
            fflush(hits); pthread_mutex_unlock(&mx);
        }
        if ((ry & 0xFFFFFF) == 0) {
            pthread_mutex_lock(&mx); prog += 16777216.0;
            if (((long)(prog / 1.34e8) % 16) == 0)
                fprintf(stderr, "  %.2f%%  hits=%ld\n", 100.0 * prog / 4294967296.0, nhits), fflush(stderr);
            pthread_mutex_unlock(&mx);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    FILE *f = fopen("data.bin", "rb");
    if (!f) { perror("data.bin"); return 1; }
    if (fread(DATA, 1, ND, f) != ND) { fprintf(stderr, "short read\n"); return 1; }
    fclose(f);
    hits = fopen(argc > 1 ? argv[1] : "hits_ry.txt", "w");
    Res r; probe(RY0, &r);
    printf("baseline ry=%llu -> va=%u kQ=%u yt=%u yQ=%u kE=0x%08X\n",
           (unsigned long long)RY0, r.va, r.kQ, r.yt, r.yQ, r.kE);
    printf("RV0=%llu  RF2=%llu  VAMOD=%llu\n", (unsigned long long)RV0, (unsigned long long)RF2, (unsigned long long)VAMOD);
    fflush(stdout);
    if (argc > 1 && !strcmp(argv[1], "-b")) return 0;
    pthread_t t[NTH];
    for (long i = 0; i < NTH; i++) pthread_create(&t[i], NULL, worker, (void *)i);
    for (int i = 0; i < NTH; i++) pthread_join(t[i], NULL);
    printf("DONE. hits=%ld\n", nhits);
    fclose(hits);
    return 0;
}
