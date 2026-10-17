#include <stdio.h>
#include <stdint.h>
#include "rzparams.h"
#define M32 0xFFFFFFFFULL
static inline uint32_t rotl(uint32_t v,int k){k&=31;return k?((v<<k)|(v>>(32-k))):v;}
static inline uint32_t xr(uint32_t a,uint32_t b){return (uint32_t)((a^b)&M32);}
int main(void){
  uint32_t b=2113217106u; uint64_t k=90,y=9;
  uint64_t s1=(C_BIAS*(k+1))%M32; printf("C_BIAS*(k+1)%%M = %llu\n",(unsigned long long)s1);
  uint64_t arg=xr(b,(uint32_t)((RZTRUE*0x7A05ULL+0x2452BA5DULL)%M32));
  printf("Rf arg b' = %llu\n",(unsigned long long)arg);
  uint64_t RR=xr((uint32_t)arg,(uint32_t)s1); printf("step1 RR=%llu\n",(unsigned long long)RR);
  uint64_t RR2=xr(rotl((uint32_t)RR,13),rotl((uint32_t)RR,7)); printf("step2 RR=%llu\n",(unsigned long long)RR2);
  uint64_t lo=RR2%0x10000ULL,hi=RR2/0x10000ULL;
  uint64_t RC=0x1F3A5ULL+k*0x9E37ULL,RX=0x2C1B3ULL+k*0x4F17ULL,Rs=0x13F7ULL*(k+1);
  printf("lo=%llu hi=%llu RC=%llu RX=%llu Rs=%llu\n",(unsigned long long)lo,(unsigned long long)hi,(unsigned long long)RC,(unsigned long long)RX,(unsigned long long)Rs);
  uint32_t Rj=(uint32_t)((lo*RC+hi*RX+Rs)%M32); printf("Rj=%u\n",Rj);
  printf("final=%u\n",xr(Rj,(uint32_t)((Y_BIAS*(y+1))%M32)));
  return 0;
}
