/* rzzscan.c -- joint scan over RZ (kF's 2nd return), the single root unknown
 * from which kI's Ry (=> state + va) AND RV are both derived consistently.
 * The two previous scans each moved only one of those two dimensions. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "rzparams.h"
#define M32 0xFFFFFFFFULL
#define RCM 0x7FFFFFFFULL
static uint8_t DATA[ND+64];
static inline uint32_t rotl(uint32_t v,int k){k&=31;return k?((v<<k)|(v>>(32-k))):v;}
static inline uint8_t rotr8(uint32_t x,int n){x&=0xFF;n&=7;return n?(uint8_t)(((x>>n)|(x<<(8-n)))&0xFF):(uint8_t)x;}
static inline uint32_t xr(uint32_t a,uint32_t b){return (a^b)&M32;}
/* kI's PRF */
static uint32_t Rf(uint32_t b,uint64_t k,uint64_t y){
    uint64_t RR = xr(b,(uint32_t)((C_BIAS*(k+1))&M32));
    RR = xr(rotl((uint32_t)RR,13),rotl((uint32_t)RR,7));
    uint64_t lo = RR%0x10000ULL, hi = RR/0x10000ULL;
    uint64_t RC = 0x1F3A5ULL + k*0x9E37ULL;
    uint64_t RX = 0x2C1B3ULL + k*0x4F17ULL;
    uint64_t Rs = 0x13F7ULL*(k+1);
    uint32_t Rj = (uint32_t)((lo*RC + hi*RX + Rs)&M32);
    return xr(Rj,(uint32_t)((Y_BIAS*(y+1))&M32));
}
typedef struct{uint32_t Rc,RF,Ru,Rx;int pos;uint32_t vU;}St;
static uint32_t va_g;
static uint32_t RS(St*s){
    uint32_t RW=DATA[s->pos++]; s->vU=(uint32_t)s->pos;
    uint32_t vU=s->vU,z=RW;
    z=(z+256-((s->Rx+(vU%256)*7)%256))%256;
    z=rotr8(z,3);
    z=xr(z,s->Ru);
    z=(z+256-((s->Rc+s->RF+(vU%256)*0xC3)%256))%256;
    uint32_t Ry=z;
    uint64_t RO=vU%RCM, Rt=va_g%RCM;
    uint64_t RE=(Rt+RO*P1+(XV%RCM))%RCM;
    uint64_t RL=(Rt*0x101+RO*P2+P1*0x11)%RCM;
    for(int i=0;i<3;i++){
        uint64_t n1=(RE*((RL%0x10000)+P1+0x101)+RL*0x101+RO*(0x11+XV%0x1F)+Rt)%RCM;
        uint64_t n2=(RL*((n1%0x10000)+P2+0x107)+n1*0x81+RO*(0x17+A1)+XV)%RCM;
        RE=n1;RL=n2;
    }
    uint32_t RA=(uint32_t)((RE%256+(RL%256)*3+(RO%256)*5+((RE-RE%256)/256)%256+((RL-RL%256)/256)%256)%256);
    Ry=xr(Ry,RA);
    uint32_t R=Ry,v=RW;
    s->Rc=xr(rotr8((s->Rc+R+s->Rx+(vU%256))%256,5),v);
    s->RF=rotr8((s->RF*5+v+xr(R,s->Rc))%256,2);
    s->Ru=xr(rotr8((s->Ru+R+v+s->RF+7)%256,5),s->Rx);
    s->Rx=rotr8((s->Rx+v+R+s->Rc+s->Ru+7)%256,1);
    return Ry;
}
static uint32_t Rw(St*s){uint32_t a=RS(s),b=RS(s),c=RS(s),d=RS(s);return (a+d*16777216u+b*256u+c*65536u)&M32;}
int main(int argc,char**argv){
    FILE*f=fopen("data.bin","rb"); if(!f){perror("data.bin");return 1;}
    if(fread(DATA,1,ND,f)!=ND){fprintf(stderr,"short read\n");return 1;} fclose(f);
    FILE*out=fopen("hits_rz.txt","w");
    /* self-test against the Python baseline at the proven RZ */
    { uint64_t RZ=RZTRUE;
      uint32_t Ry=Rf(xr(RB2,(uint32_t)((RZ*0x7A05ULL+0x2452BA5DULL)&M32)),K1C,Y1C);
      uint32_t Rc=xr(DATA[0],Ry),RF=DATA[1],Ru=xr(DATA[2],Ry>>16),Rx=xr(DATA[3],Ry>>24);
      uint32_t Rf2=Rf(xr(RB7,(uint32_t)((RZ*0x4BBDULL+0x48221848ULL)&M32)),K1C,Y2C);
      va_g=(uint32_t)(((uint64_t)Rf2+(uint64_t)Rc*0x10001ULL+(uint64_t)RF*0x101ULL+(uint64_t)Ru*0x11ULL+Rx)%VAMOD)+1;
      uint32_t RV=Rf(xr(RB4,(uint32_t)((RZ*0x1F33ULL+0xB7D0034EULL)&M32)),K3C,Y3C);
      St s={Rc,RF,Ru,Rx,4,4};
      uint32_t kE=xr(Rw(&s),RV); Rw(&s); Rw(&s);
      uint32_t yE=RS(&s),yt=RS(&s),yl=RS(&s),yQ=RS(&s);
      uint32_t kQ=xr(Rw(&s),xr(rotl(kE,11),rotl(RV,7)));
      printf("SELFTEST RZ=%llu Ry=%u va=%u RV=%u kE=0x%08X yt=%u yQ=%u kQ=%u\n",
             (unsigned long long)RZ,Ry,va_g,RV,kE,yt,yQ,kQ);
      printf("  expect      Ry=1961775487 va=961330124 RV=1774284823 kE=0x579359E4 yt=11 yQ=224 kQ=3574921221\n");
      fflush(stdout);
      if(argc>1){return 0;} }
    long n=0,nhit=0; double w=0;
    for(uint64_t RZ=0;RZ<=M32;RZ++){
        uint32_t Ry = Rf(xr(RB2,(uint32_t)((RZ*0x7A05ULL+0x2452BA5DULL)&M32)),K1C,Y1C);
        uint32_t Rc = xr(DATA[0],Ry), RF=DATA[1], Ru=xr(DATA[2],Ry>>16), Rx=xr(DATA[3],Ry>>24);
        uint32_t Rf2= Rf(xr(RB7,(uint32_t)((RZ*0x4BBDULL+0x48221848ULL)&M32)),K1C,Y2C);
        va_g=(uint32_t)(((uint64_t)Rf2+(uint64_t)Rc*0x10001ULL+(uint64_t)RF*0x101ULL
                        +(uint64_t)Ru*0x11ULL+Rx)%VAMOD)+1;
        uint32_t RV = Rf(xr(RB4,(uint32_t)((RZ*0x1F33ULL+0xB7D0034EULL)&M32)),K3C,Y3C);
        St s={Rc,RF,Ru,Rx,4,4};
        uint32_t kE=xr(Rw(&s),RV);
        uint32_t kz=xr(Rw(&s),xr(rotl(kE,5),rotl(RV,11)));
        uint32_t kP=xr(Rw(&s),xr(rotl(kE,13),rotl(RV,19)));
        uint32_t yE=RS(&s),yt=RS(&s),yl=RS(&s),yQ=RS(&s);
        uint32_t kQ=xr(Rw(&s),xr(rotl(kE,11),rotl(RV,7)));
        n++;
        if(kQ<=7461){
            nhit++;
            fprintf(out,"RZ=%10llu Ry=%10u va=%10u RV=%10u kQ=%6u yt=%3u yQ=%3u yE=%3u yl=%3u kE=0x%08X kz=0x%08X kP=%10u\n",
                (unsigned long long)RZ,Ry,va_g,RV,kQ,yt,yQ,yE,yl,kE,kz,kP);
            if((nhit%500)==0){fflush(out);fprintf(stderr,"  RZ=%.3f%%  hits=%ld\n",100.0*RZ/4294967296.0,nhit);fflush(stderr);}
        }
        (void)kP;(void)kz;(void)yE;(void)yl;(void)w;
    }
    printf("DONE scanned=%ld kQ-survivors=%ld\n",n,nhit);
    fclose(out); return 0;
}
