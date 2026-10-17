/* brute.c -- exhaustive scan of `va` (kI's 3rd return, RS()'s Rt input).
 *
 * Everything upstream of va has been independently verified against the Lua
 * source: RZ is a pure constant hash (env table fully resolved => t5 = "number"
 * => 0x1D88), kI's bk slots cross-validate to keys {1..8}, the RI/RN handler
 * keys decode to {4,26,56,44,228} matching the RA[..][1] type codes, and B2 is
 * proven by stage-1 LZ77 -> valid Lua plus an exact 149262-token / 119409-byte
 * accounting through the Cv=true literal path.
 *
 * RV does NOT enter the keystream, so for a fixed (state, RV) each candidate va
 * yields a deterministic 20-byte header.  Oracle:
 *   yt = RS()#14  (numparams)          <= 12
 *   yQ = RS()#16  (frame offset)       <= 96
 *   kQ = Rw5 ^ rotl(kE,11) ^ rotl(RV,7) in (0, 20000)   [16 bytes/iter budget]
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "params.h"

#define M32   0xFFFFFFFFULL
#define RCM   0x7FFFFFFFULL

static uint8_t DATA[ND + 64];

static inline uint32_t rotl32(uint32_t v, int k) {
    k &= 31; return k ? ((v << k) | (v >> (32 - k))) : v;
}
static inline uint8_t rotr8(uint32_t x, int n) {
    x &= 0xFF; n &= 7; return n ? (uint8_t)(((x >> n) | (x << (8 - n))) & 0xFF) : (uint8_t)x;
}

typedef struct { uint32_t Rc, RF, Ru, Rx; int pos; uint32_t vU; } St;

static uint32_t RS(St *s, uint32_t va) {
    uint32_t RW = DATA[s->pos++];
    s->vU = (uint32_t)s->pos;                 /* vU = Rm-1, Rm post-increment */
    uint32_t vU = s->vU;
    uint32_t z = RW;
    z = (z + 256 - ((s->Rx + (vU % 256) * 7) % 256)) % 256;             /* RR[41] */
    z = rotr8(z, 3);                                                     /* RR[48] */
    z = (z ^ s->Ru) & M32;                                               /* RR[82] */
    z = (z + 256 - ((s->Rc + s->RF + (vU % 256) * 0xC3) % 256)) % 256;   /* RR[22] */
    uint32_t Ry = z;

    uint64_t RO = vU % RCM;
    uint64_t Rt = va % RCM;
    uint64_t RE = (Rt + RO * P1 + (XV % RCM)) % RCM;
    uint64_t RL = (Rt * 0x101 + RO * P2 + P1 * 0x11) % RCM;
    for (int i = 0; i < 3; i++) {
        uint64_t n1 = (RE * ((RL % 0x10000) + P1 + 0x101) + RL * 0x101
                       + RO * (0x11 + XV % 0x1F) + Rt) % RCM;
        uint64_t n2 = (RL * ((n1 % 0x10000) + P2 + 0x107) + n1 * 0x81
                       + RO * (0x17 + A1) + XV) % RCM;
        RE = n1; RL = n2;
    }
    uint32_t RA = (uint32_t)((RE % 256 + (RL % 256) * 3 + (RO % 256) * 5
                   + ((RE - RE % 256) / 256) % 256
                   + ((RL - RL % 256) / 256) % 256) % 256);
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

typedef struct { uint32_t va, RV, kE, kz, kP, yE, yt, yl, yQ, kQ; } Res;

static int probe(uint32_t va, uint32_t RV, Res *out) {
    St s = { RC0, RF0, RU0, RX0, 4, 4 };
    uint32_t kE = Rw(&s, va) ^ RV;
    uint32_t kz = Rw(&s, va) ^ (rotl32(kE, 5) ^ rotl32(RV, 11));
    uint32_t kP = Rw(&s, va) ^ (rotl32(kE, 13) ^ rotl32(RV, 19));
    uint32_t yE = RS(&s, va), yt = RS(&s, va), yl = RS(&s, va), yQ = RS(&s, va);
    uint32_t kQ = Rw(&s, va) ^ (rotl32(kE, 11) ^ rotl32(RV, 7));
    out->va = va; out->RV = RV; out->kE = kE; out->kz = kz; out->kP = kP;
    out->yE = yE; out->yt = yt; out->yl = yl; out->yQ = yQ; out->kQ = kQ;
    return (yt <= 12 && yQ <= 96 && kQ > 0 && kQ < 20000);
}

static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static FILE *hits;
static long nhits = 0, ndone = 0;

static void *worker(void *arg) {
    long id = (long)arg;
    uint64_t lo = 1 + (uint64_t)id * ((M32 - 1) / 2);
    uint64_t hi = (id == 1) ? 2147483646ULL : (lo + ((M32 - 1) / 2) - 1);
    Res r;
    for (uint64_t va = lo; va <= hi; va++) {
        if (probe((uint32_t)va, RV0, &r)) {
            pthread_mutex_lock(&mx);
            nhits++;
            fprintf(hits, "va=%10llu kQ=%7u yt=%3u yQ=%3u yE=%3u yl=%3u kE=0x%08X kz=0x%08X kP=0x%08X\n",
                    (unsigned long long)va, r.kQ, r.yt, r.yQ, r.yE, r.yl, r.kE, r.kz, r.kP);
            fflush(hits);
            pthread_mutex_unlock(&mx);
        }
        if ((va & 0xFFFFF) == 0) {
            pthread_mutex_lock(&mx); ndone++; 
            if ((ndone % 64) == 0) fprintf(stderr, "progress: %.2f%%  hits=%ld\n",
                    100.0 * (ndone * 1048576.0) / 2147483646.0, nhits), fflush(stderr);
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
    hits = fopen(argc > 1 ? argv[1] : "hits_va.txt", "w");

    Res r;
    probe(VA0, RV0, &r);
    printf("baseline va=%llu kQ=%u yt=%u yQ=%u yE=%u yl=%u kE=0x%08X kz=0x%08X kP=0x%08X\n",
           (unsigned long long)VA0, r.kQ, r.yt, r.yQ, r.yE, r.yl, r.kE, r.kz, r.kP);
    fflush(stdout);
    if (argc > 1 && !strcmp(argv[1], "-b")) return 0;

    pthread_t t[2];
    for (long i = 0; i < 2; i++) pthread_create(&t[i], NULL, worker, (void *)i);
    for (int i = 0; i < 2; i++) pthread_join(t[i], NULL);
    printf("DONE. total hits = %ld\n", nhits);
    fclose(hits);
    return 0;
}
