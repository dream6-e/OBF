/* rvscan.c -- independent scan of RV (the master key mask).
 *
 * Crucial structural fact: RV never enters the RS() keystream.  The keystream
 * depends only on (va, Rc/RF/Ru/Rx, position, ciphertext) -- all pinned down by
 * kI's intermediate Ry -- so it is precomputed once into ks.bin (119405 bytes).
 * Every quantity vu() reads is then  keystream_byte XOR mask(kE,kz,kP,RV).
 *
 * That makes RV a free 32-bit variable and gives a two-stage search:
 *   stage A (2^32, ~10 ops each):  kQ = Rw5 ^ rotl(kE,11) ^ rotl(RV,7) < 7462
 *   stage B (~7462 survivors):     full kd loop -> RV2 -> RH -> Rh -> Rh rounds,
 *                                  requiring Rh small and the byte budget to hold.
 * This covers the failure mode the Ry scan cannot: Rb[]'s *values* (hence Rf/RV)
 * being wrong while its 8 keys still decode to {1..8}.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define M32 0xFFFFFFFFULL
static uint8_t KS[200000];
static int NKS;

static inline uint32_t rotl(uint32_t v, int k){k&=31;return k?((v<<k)|(v>>(32-k))):v;}
static inline uint32_t xr(uint32_t a,uint32_t b){return (a^b)&M32;}

typedef struct { int p; } Rd_;
static Rd_ RD;
static int eof_flag;

static inline uint32_t RSb(void){
    if (RD.p >= NKS) { eof_flag = 1; return 0; }
    return KS[RD.p++];
}
static uint32_t Rw(void){
    uint32_t a=RSb(),b=RSb(),c=RSb(),d=RSb();
    return (a + d*16777216u + b*256u + c*65536u) & M32;
}
/* kj() is Rw() sign-extended; every use in kd is  X()%2^32  which undoes the
   sign extension, so raw Rw() suffices and the byte count is identical. */

static int full_parse(uint32_t RV, uint32_t *out) {
    eof_flag = 0; RD.p = 0;
    uint32_t kE = xr(Rw(), RV);
    uint32_t kz = xr(Rw(), xr(rotl(kE,5),  rotl(RV,11)));
    uint32_t kP = xr(Rw(), xr(rotl(kE,13), rotl(RV,19)));
    uint32_t yE=RSb(), yt=RSb(), yl=RSb(), yQ=RSb();

    uint32_t kQ = xr(Rw(), xr(rotl(kE,11), rotl(RV,7)));
    if (kQ == 0 || kQ > 7461) return 0;

    uint32_t RL  = xr(xr(xr(589742u,0x720EEu),0xC33D6FB1u), xr(rotl(kE,3),  rotl(RV,7)));
    uint32_t RWc = xr(xr(xr(0x10599u,0x8B73u),4132475171u),  xr(rotl(kz,9),  rotl(RV,13)));
    uint32_t ROc = xr(xr(xr(152743u,491838u),1555620535u),   xr(rotl(kP,15), rotl(kE,21)));
    uint32_t REc = xr(xr(xr(331361u,863629u),1213750126u),   xr(rotl(RV,17), rotl(kz,25)));
    uint32_t RR  = xr(xr(kE, rotl(kz,7)), xr(rotl(kP,13), rotl(RV,19)));

    for (uint32_t i = 0; i < kQ; i++) {
        uint32_t Ryv = Rw();                       if (eof_flag) return 0;
        uint32_t RCv = xr(Ryv, xr(kz, RR % 0x10000000u));
        uint32_t lv  = Rw();                       if (eof_flag) return 0;   /* kL */
        Rw();                                      if (eof_flag) return 0;   /* kW */
        Rw();                                      if (eof_flag) return 0;   /* kO */
        uint32_t RXv = xr(lv, xr(rotl(RR,5), kE));
        RR = xr((rotl(RR,7) + RCv) & M32, RXv);
        uint32_t Rz = ((Ryv - Ryv % 0x20000000u) / 0x20000000u) % 4u;
        for (uint32_t q = 0; q < Rz; q++) { RR = (rotl(RR,3) + RSb() + 0x3Du) & M32; if (eof_flag) return 0; }
    }
    uint32_t RV2 = xr(RV, rotl(RR,9));
    uint32_t RH = RSb();                           if (eof_flag) return 0;
    uint32_t Rh = xr(Rw(), xr(rotl(kE,9), rotl(RV2,15)));
    if (Rh > 20000) return 0;
    for (uint32_t q = 1; q <= Rh; q++) {
        uint32_t b = RSb();                        if (eof_flag) return 0;
        Rw();                                      if (eof_flag) return 0;
        if (b == 4) { uint32_t len = Rw(); if (eof_flag) return 0;
                      if (len > 100000) return 0;
                      for (uint32_t z=0;z<len;z++){ RSb(); if (eof_flag) return 0; } }
        else if (b == 26 || b == 56) { for (int z=0;z<8;z++){ RSb(); if (eof_flag) return 0; } }
    }
    out[0]=kE; out[1]=kz; out[2]=kP; out[3]=yE; out[4]=yt; out[5]=yl; out[6]=yQ;
    out[7]=kQ; out[8]=RH; out[9]=Rh; out[10]=(uint32_t)RD.p; out[11]=RV2;
    return 1;
}

int main(void) {
    FILE *f = fopen("ks.bin","rb");
    if (!f) { perror("ks.bin"); return 1; }
    NKS = (int)fread(KS,1,sizeof KS,f); fclose(f);
    printf("keystream bytes = %d\n", NKS);

    /* stage A constants: Rw1 and Rw5 of the fixed keystream */
    RD.p = 0; uint32_t Rw1 = Rw(); RD.p = 16; uint32_t Rw5 = Rw();
    printf("Rw1=%u (0x%08X)   Rw5=%u (0x%08X)\n", Rw1,Rw1,Rw5,Rw5);

    FILE *out = fopen("hits_rv.txt","w");
    long stageA = 0, stageB = 0;
    uint32_t o[16];
    for (uint64_t RV = 0; RV <= M32; RV++) {
        uint32_t kE = xr(Rw1, (uint32_t)RV);
        uint32_t kQ = xr(Rw5, xr(rotl(kE,11), rotl((uint32_t)RV,7)));
        if (kQ == 0 || kQ > 7461) continue;
        stageA++;
        if (full_parse((uint32_t)RV, o)) {
            stageB++;
            fprintf(out,"RV=%10u kQ=%6u Rh=%6u RH=%3u yt=%3u yQ=%3u yE=%3u yl=%3u kE=0x%08X kz=0x%08X kP=0x%08X consumed=%u/%d RV2=%u\n",
                    (uint32_t)RV,o[7],o[9],o[8],o[4],o[6],o[3],o[5],o[0],o[1],o[2],o[10],NKS,o[11]);
            fflush(out);
            printf("  *** SURVIVOR *** RV=%u kQ=%u Rh=%u consumed=%u/%d\n",(uint32_t)RV,o[7],o[9],o[10],NKS);
            fflush(stdout);
        }
        if ((stageA % 1000) == 0) { fprintf(stderr,"  stageA=%ld stageB=%ld (RV=%llu)\n",stageA,stageB,(unsigned long long)RV); fflush(stderr); }
    }
    printf("DONE stageA=%ld stageB=%ld\n", stageA, stageB);
    fclose(out);
    return 0;
}
