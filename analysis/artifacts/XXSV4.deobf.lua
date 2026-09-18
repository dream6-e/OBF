local w = {}
return setmetatable({
  [9088] = function(t, w)
  local j = function(j)
    if (not j[2]) then
      return j[1]
    else
      return j[2][j[3]]
    end
  end
  local x = function(j, x)
    if (not j[2]) then
      j[1] = x
    else
      j[2][j[3]] = x
    end
  end
  local i = function(j, x)
    if ("userdata" == t(j)) then
      if (x == "add") then
        return function(x, ...)
          return j:add(...)
        end
      else
        w()
      end
    end
    return j[x]
  end
  return j, x, i
end,
  [1910] = function()
  local t = ((getfenv and getfenv(1)) or _G)
  local j = {
    function()
    return "q"
  end,
    function()
    return "u"
  end,
    function()
    return "t"
  end,
    function()
    return "z"
  end,
    function()
    return "6"
  end,
    function()
    return "k"
  end,
    function()
    return "w"
  end,
    function()
    return "g"
  end,
    function()
    return "y"
  end,
    function()
    return "c"
  end,
    function()
    return "h"
  end,
    function()
    return "m"
  end,
    function()
    return "l"
  end,
    function()
    return "2"
  end,
    function()
    return "1"
  end,
    function()
    return "s"
  end,
    function()
    return "n"
  end,
    function()
    return "b"
  end,
    function()
    return "o"
  end,
    function()
    return "e"
  end,
    function()
    return "d"
  end,
    function()
    return "3"
  end,
    function()
    return "x"
  end,
    function()
    return "r"
  end,
    function()
    return "4"
  end,
    function()
    return "p"
  end,
    function()
    return "a"
  end,
    function()
    return "8"
  end,
    function()
    return "f"
  end,
    function()
    return "i"
  end
  }
  local x = function(w, x)
    local j = ""
    for t = 1, (#x) do
      j = (j .. w[x[t]]())
    end
    return j
  end
  local uh, mp, le, f = x(j, {16, 20, 13, 20, 10, 3}), x(j, {20, 24, 24, 19, 24}), x(j, {26, 10, 27, 13, 13}), x(j, {2, 17, 26, 27, 10, 6})
  local m, qt, sm, op = x(j, {16, 3, 24, 30, 17, 8}), x(j, {18, 9, 3, 20}), x(j, {16, 2, 18}), x(j, {29, 19, 24, 12, 27, 3})
  local d, zf, up, ra = x(j, {3, 27, 18, 13, 20}), x(j, {10, 19, 17, 10, 27, 3}), x(j, {10, 11, 27, 24}), x(j, {12, 27, 3, 11})
  local ro, zo, yo, er = x(j, {29, 13, 19, 19, 24}), x(j, {3, 19, 17, 2, 12, 18, 20, 24}), x(j, {3, 9, 26, 20}), x(j, {3, 19, 16, 3, 24, 30, 17, 8})
  local mb, mg, tl, rf = x(j, {17, 20, 23, 3}), x(j, {8, 20, 3, 12, 20, 3, 27, 3, 27, 18, 13, 20}), x(j, {16, 20, 3, 12, 20, 3, 27, 3, 27, 18, 13, 20}), x(j, {24, 27, 7, 8, 20, 3})
  local ia, a, ac, ii = x(j, {24, 27, 7, 20, 1, 2, 27, 13}), (j[21]() .. (j[20]() .. (j[18]() .. (j[2]() .. j[8]())))), x(j, {13, 19, 27, 21, 16, 3, 24, 30, 17, 8}), (j[30]() .. (j[17]() .. (j[3]() .. (j[20]() .. (j[8]() .. (j[20]() .. j[24]()))))))
  local s, g, z, r = x(j, {29, 24, 19, 12, 16, 3, 24, 30, 17, 8}), x(j, {29, 24, 20, 20, 4, 20}), x(j, {30, 17, 29, 19}), x(j, {18, 30, 3, 22, 14})
  local y, lb, sp, uu = x(j, {18, 2, 29, 29, 20, 24}), x(j, {18, 23, 19, 24}), x(j, {18, 27, 17, 21}), x(j, {18, 19, 24})
  local hp, xm, aq, iu = (j[18]() .. (j[17]() .. (j[19]() .. j[3]()))), x(j, {13, 24, 19, 3, 27, 3, 20}), x(j, {13, 16, 11, 30, 29, 3}), x(j, {24, 16, 11, 30, 29, 3})
  local zs, mi, ff, ca = x(j, {10, 24, 20, 27, 3, 20}), x(j, {7, 24, 30, 3, 20, 2, 28}), x(j, {24, 20, 27, 21, 2, 28}), x(j, {24, 20, 27, 21, 2, 15, 5})
  local sv, ns, nr, wo = x(j, {24, 20, 27, 21, 2, 22, 14}), x(j, {24, 20, 27, 21, 30, 22, 14}), x(j, {24, 20, 27, 21, 29, 5, 25}), x(j, {13, 20, 17})
  local o = t[uh]
  local kl = t[d][g]
  local i, yr, mj = t[m][qt], t[m][sm], t[m][op]
  local b, oc, rx, dk, mn, mz, wg, yq, pe = t[ra][ro], t[zo], t[yo], t[er], t[mb], t[mg], t[tl], t[rf], t[ia]
  local ut = (t[f] or t[d][f])
  local kk = function(...)
    return {n = o("#", ...), ...}
  end
  local k, q = t[r], t[y]
  local u, p, c, l, aa, e, ny = k[lb], k[sp], k[uu], k[hp], k[xm], k[aq], k[iu]
  local hq, iq, qa, vu, nh, zz, hw, ju, ec = q[zs], q[mi], q[ff], q[ca], q[s], q[sv], q[ns], q[nr], q[wo]
  local di = t[ii]
  local xp = (di and di[s])
  local h = t[a]
  local jy = (h and h[z])
  local qf = t[ac]
  local pk = t[mp]
  local dj = (y .. ("|" .. (r .. ("|" .. (d .. ("|" .. (g .. ("|" .. (a .. ("|" .. z))))))))))
  local qu = t[le]
  local cx, is = t[m][up], t[d][zf]
  local vk = function(j, x)
    return p(c(j, x), l(p(j, x)))
  end
  local zb = function(j, x)
    return u(j, x)
  end
  local gi = function(t, w, q)
    local j, x = 1, 0
    for w = w, q do
      j = ((j + i(t, w)) % 65521)
      x = ((x + j) % 65521)
    end
    return (j + (x * 65536))
  end
  local vy = function(j, x)
    local t, w, i, q = i(j, x), i(j, (x + 1)), i(j, (x + 2)), i(j, (x + 3))
    return c(c(e(q, 24), e(i, 16)), c(e(w, 8), t))
  end
  local n = function(j, x)
    local i, q, k, t = i(j, x), i(j, (x + 1)), i(j, (x + 2)), i(j, (x + 3))
    if (not t) then
      pk()
    end
    return ((((((t * w.e) + k) * w.e) + q) * w.e) + i)
  end
  local cl = function(i, q, t, k)
    local x = {}
    local j = ((k + 119) % w.e)
    for t = 1, t do
      local i = (((qa(i, ((q + t) - 2)) + w.e) - j) % w.e)
      x[t] = cx(i)
      j = ((((j * 193) + (i * 109)) + 217) % w.e)
    end
    return is(x)
  end
  local w = function(i, q)
    local k, j = n(i, q), n(i, (q + 4))
    local x = (((j >= 2147483648) and -1) or 1)
    local t = (b((j / 1048576)) % 2048)
    local w = (((j % 1048576) * w.h) + k)
    if (t == 2047) then
      if (w == 0) then
        return (x / 0)
      else
        return (0 / 0)
      end
    elseif (t == 0) then
      return (x * (w * 5e-324))
    else
      return (x * ((1 + (w / 4503599627370496)) * (2 ^ (t - 1023))))
    end
  end
  return aa, hq, zb, mj, k, rx, mn, yq, qf, oc, gi, dj, o, ju, nh, qa, b, ec, kl, zz, vy, cx, l, t, h, c, kk, e, cl, vk, yr, mz, vu, xp, pe, i, jy, w, ny, q, u, p, wg, qu, hw, pk, dk, n, iq, is, ut
end,
  ["g"] = function(t, ...)
  w.e, w.h, w.u, w.aa, w.ab, w.ac, w.ad = 256, 4294967296, 33659, 65536, 65521, 3001000, 8000000
  do
    local lrotate, buf_create, XOR, fmt, bit32lib, typeof, nextf, rawget_, loadstring, tonum, adler32, LIBSTR, select_, buf_readf64, buf_fromstring, buf_readu8, floor, buf_len, tfreeze, buf_readu32, u32le_str, strchar, bnot, ENV, debuglib, bor, packN, lshift, decstr, XOR2, strsub, getmeta, buf_readu16, int_fromstring, rawequal_, strbyte, dbginfo, f64le, rshift, bufferlib, bxor, band, setmeta, pcall_, buf_readi32, ERR, tostr, u32le_str2, buf_writeu8, tconcat, tunpack, ia
    local mp, le, qt, sm, ac, sv, ii, op, ns, nr, wo, kl, yr, mj, oc, rx, dk
    local i = 0
    local q = 110
    while true do
      if (q == 907) then
        if (i ~= 132927) then
          ERR()
        end
        local buf_writeu8 = t[7594](select_, packN, tunpack, ENV, ERR, pcall_, strbyte, strsub, fmt, floor, tonum, typeof, tostr, nextf, getmeta, setmeta, rawget_, rawequal_, int_fromstring, tfreeze, op, oc, rx, dk, wo, kl, yr, mj, ia, bxor, band, bor, bnot)
        local bxor = buf_writeu8(nr, packN(...), {})
        return tunpack(bxor, 1, bxor.n)
      elseif (q == 255) then
        t[1283] = function(i, x, t, q, k, c, m)
          local w = (q and k(c, "s"))
          w = (w .. m)
          local j = (((x * 37) + t) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          x = 0
          t = 1
          while (t <= (#w)) do
            x = (((x + (x * 256)) + i(w, t)) % 2147483647)
            t = (t + 1)
          end
          return (1 + ((j + (x * 37)) % 2147483646))
        end
        i = (i + 1283)
        t[6142] = function(k, t, s, q, h, x)
          local j = function(c, i, j)
            local x, m = x(c, i)
            local n = {}
            local t = 0
            while (t < j) do
              local m = (t + 8192)
              if (m > j) then
                m = j
              end
              local d, e = {}, {}
              local i = w.e
              local q = nil
              local f = 0
              while (t < m) do
                local p = x(1)
                local j
                if (p == 1) then
                  j = x(8)
                  if (j < 32) then
                    k()
                  end
                else
                  p = x(1)
                  if (p == 1) then
                    j = x(5)
                  else
                    if (q == nil) then
                      k()
                    end
                    local t = 0
                    local i = (i - w.e)
                    while (i > 0) do
                      t = (t + 1)
                      i = h((i / 2))
                    end
                    j = (w.e + x(t))
                  end
                end
                if (j > i) then
                  k()
                end
                local a = (j == i)
                if a then
                  d[i] = ((q * w.e) + f)
                end
                local x = 0
                local c = j
                while (c >= w.e) do
                  local j = d[c]
                  x = (x + 1)
                  e[x] = (j % w.e)
                  c = h((j / w.e))
                end
                x = (x + 1)
                e[x] = c
                local h = c
                if ((not a) and (q ~= nil)) then
                  d[i] = ((q * w.e) + h)
                end
                if (not (q == nil)) then
                  i = (i + 1)
                end
                q = j
                f = h
                if ((t + x) > m) then
                  k()
                end
                for x = x, 1, -1 do
                  t = (t + 1)
                  n[t] = s(e[x])
                end
              end
            end
            if (m() ~= i) then
              k()
            end
            return q(n)
          end
          return j
        end
        i = (i + 6142)
        qt = t[9080](strbyte, 3328, 1283, debuglib, dbginfo, loadstring, LIBSTR)
        t[3328] = function(i, x, t, q, k, c, m)
          local w = (q and k(c, "s"))
          w = (w .. m)
          local j = (((x * 37) + t) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          x = 0
          t = 1
          while (t <= (#w)) do
            x = (((x + (x * 256)) + i(w, t)) % 2147483647)
            t = (t + 1)
          end
          return (1 + ((j + (x * 37)) % 2147483646))
        end
        i = (i + 3328)
        t[3227] = function(t, i, k, c)
          local j = 1
          local m = function()
            return j
          end
          local x = function()
            local x = k(t, j)
            if (x == nil) then
              i()
            end
            j = (j + 1)
            return x
          end
          local d = function()
            local j, x = x(), x()
            return (j + (x * w.e))
          end
          local w = function()
            local j, x, t, i = x(), x(), x(), x()
            return (((j + (x * w.e)) + (t * w.aa)) + (i * 16777216))
          end
          local q = function(x)
            if (x > (((#t) - j) + 1)) then
              i()
            end
            local t = c(t, j, ((j + x) - 1))
            j = (j + x)
            return t
          end
          local e = function()
            return q(w())
          end
          return x, d, w, q, e, m
        end
        i = (i + 3227)
        le = t[1283](strbyte, 901, 9088, debuglib, dbginfo, loadstring, LIBSTR)
        t[8255] = function(x, t, i, q, k, c, m, d)
          local e = (c and m(d, "s"))
          if (e ~= "[C]") then
            x()
          end
          local j = {}
          j[66] = ("!4fdWU BX^V" .. ("2G5mL[0)l]k" .. ("_i}@Obpwa:<" .. ("N>Kvx+jFo$H" .. ("`?;CqSDs\31Qn" .. ("%(=t8rR&y\28A" .. ("Mu1J/6|\29T,~" .. "37I{*gYE\30")))))))
          j[87] = {
            " }5^$G{+%iUN,F;kS\29$NNCr$%aFTo;L1Ql0WMgqq[551H,3)}n<3QbkTN&qQdJEFV@3Du y[r\28Co7T:_yKVr]I(W i1H=m?2|w$_m| HHod(~d)ft,l{Qv0^x5Lm4=R%0jFkM0s6oYD2AtMJd;YS(Xr8{2)Al);JKn~:4*sq,i($7)Nq6L!p<S[x3O/+GNlfwr\28If:HDw5<GxG\29nQ2bF2rd0vn}45uXX~Xo~H`DY5gL a8i=6i=3Od`pB` \28\31XT=,\30F,H\29AfOn1%`w=X5ALrH\31CNFvR[8!JIiOKM_*QYr{WwFw3X2=,,oWH,$32;B0BkG:\31/Dk,^n_/DS%onDJI)6TtbuUiC(m@i[o*sOM\0295iBHBM@J\29[Ix]^s2ESG)Q@/I/RFa1tbxdd+q=%&X6=TH\29T}k8dCl*WW;$jdv}m\28}|ux2a^6Q@&dlE2YuQQK>I: ,6BF8% :$v)r;@GT<\30H)[W!6QG>`ISoq\30y;vX4oVu%wwqLiym,o)BS)d*;*0~rj>2EX~^>&&R5~\30U!VYya,gmUxYl6QQM!E%,Lq7C|*N6AI!SavA?$*?fE2Q+{Y+$x\28vRUi{C]7plV1N_JTTEBn)<U\29n+:AMRNk2}1m+<Fy^vtAK^",
            "4=)NO+y+~0{XnI~v8/m[>A$f]6K7{&!OMV?QSl?SYw\0304j^3S1o}K[JBQHVVq(JMs\30 \0314rg&\29ALUlxuL7lxVFmsVQuox\29\28t|a(/=Y<E(N$6p+l2t}yq\30j0p,$1MEv$r\31~)?(pK6;,>@DaC|f/_qmsd=\28J!aI7\31]:]@=n!}bQlqal/r(f]&pDJRS2{\31GN6!$0A>BuVY|&S%!>54M@+)%6 II*y%5M/N@\31paCm>O}y3<Dl{imb}_[f6FiO:TM32pvbfyHrYg>oMG?LSS\29``SrSY!i<,n,C+fK$}M~v&sL\30!L?}+D^kQ]ynA:aS &`y]aVSKI6G_[B\0315\29+Gx]jJ2\29r!yBS\31(7YvAb[[;KAA\31SbE\28=\0297CEj+Q}DLg}bsgAxX6:R~pbJ*b^LU][vmO1Kfr}8@b{~`V30Kw<[}8Xv:&ki0}AJ` >0kn\31\31H_F^U/KM}^%aB5MlfF5\29[?IYE|]=[^\28k\31Qw+ %;L8\31nf]M0ob^6A}>B4<|vyOC(Yg{0``\29Y,dg?:m]pndg&,0u3o`$IT=y(({Ykgaw7dpstxKl1Q\29S7!t4QMxF+UA?\31EN\31j,GB_p\31f\0317(8C_0Xg;]iK{{p7Wj!DiQ\28u;MlyTk5B21{j\29}WB@7\0290$<",
            "^anNvDu*:K_Y=1_yff&Xd,o4?U(07LvdJ[o}~3Nj5diR,CLMB@\29MmC^f~K*\29Ms?fjNg8Kx\31XNi\29]HU?)A:\31%!Ki25\30s,_C\30&q:<GAu\28;*)ln+StxLC_0Xw<)|n7Xl>8RT0lk\28T\28ImR0HBl>s@W(jf\29x62:d;;B\29Bp$BUl YmQRmwf!RX2iR6SM(fyy2F;BKyb^Cq?U|^6koxis!>pAox8WJ 0FQ=]VMRO\29YA\31\30/HQq0`VR! 2FL?3\31:D\31OF|xd*{OGYYC,wbDDQv?aa)aSg\31`LCET\31[xC<BM]g(yAAQkR!p,14@_7^nNl;L6!yf,\28C>\28sfGqkdy:Dnkd;kWfgkdy ao+uD;tQNF2ROC0yL[0:mA*3y:rCy~~{ov=q+vSbt0+YD*kQxL_FtwOk< JG(\28fK62x_drumIHy?KVK&SK<l0oqdB$=lq+%p7E(QL\29W&lb|3R+KMGO+mCaGWa,$}&RH5BI2>oR[JxMN)C/QLxQ<?gu1G;K4,61dECm| V)THT~xWRQ(:uKEf\30MKxt5TA*<N\31v{ow;iw?S qd7aQ|T[BR1:I{D2tI&l*{uj|35nt?x\28aTUIpp`%`HQ*V!)V8xM*X/TjbgYau5MCD3\31i0V,[,$?<",
            "Vsq=7?^;&\29}H_U^Ln;l+\29+XBF?^JTQI\29i\29n8Gr3JYW}fK6kOVkvy\30&sI?G7\30iEq}1V\0314M+|3u+U:N*qCV=mbpI[\29^?[,M<~\28}r!E!)WYq2LCRsdTWaSG7d/wJ$+Tr/xj!^[Mix\0316G!XK lN:AL*HqaTDI+iq\30`\03031\30H:iWA6Bjdvadt34G\28+)TbOU/Apb=(sWQCt()65\29@BHL]AIB3$M_T;diO8}Y[]gLj<}@4*qG=rbEV^>18Jb%EX\28F$:K(IV8FXBu!pNj1L(fKx_H=OTSuM\31l|M0wwOQ$(yjLDpO,N0OpB(u _!`0Xjr AX{a?`RlWLok\28n}G=G{J!r0sEN8`b2C_MK~\31X>3x`w\31,,f6&(iQ`EQ(A?vwU8VGRDfBX`\30H\31%qf&7\30E>2C\29jN&`5R?!1ACCVTL\0318K&toOpU24t@wr]~rliLf*J=X&$B/H\31VluuW18_mG>8+F)_f+qy3nU&>mVjTA)xWr=>%QN>[+WFvnS/+iFoOO)bs4EiFXaq\02916Xp3!m}VmT$q~\29xkUjY*U~7]\0302im:KKuS|_w__rRpL=C(n447*mRA\0293x+%@{u/Xv<H{v^`H4Gt*rk]FIf^MX?^[xRXoy=N_y^`71;]\03134j\31Q&3~",
            "BNw2 ;W!)y^$Qig\28M+amX?E;y2_+LL^(IYYTT6_CLONG[xu?l)OS(8}_ ?o\31qp QmFv8^)Tty,\31juofTN6I2GbNvVDA%grQR0fs(qN!I+L^)xAkTOJODj|C[b,<F\30~+$2?Axn*/&Mj`;r30yU&WC?}u@:K\29G4G2|fiR;5]8atL$Br<\29^*$3@jK7b\28f]kH;`>^y25D!!jNH Y&WW%Dd)]?7RNU 7WoYx3t,33GBkq @x[:Xjwn|)qd/N1\28qi*J@O)^~7)2*?RpjU_|vG(m$vD_%vX$Iy k\0287@4SjS1\28\0297\02847BdsCOq;)*TL:/\30ILQ*k,mOUN_pmm3V(|*[`D+VJk0(TNtj+Xf8fbIGvMFf/f@0{^&<G%Ep3?NHEjC=IR)(jw+nuK/p}u@nWo?E,>5>H<BNXB\29W\29KN_>\28s7R{ll,V;3(UM0k5\31L3nA8}sqYvYogywbn EmUH7@&)7XXH/p *>x7m1\28yM :L %1xu *aU~R\0304G?jD}<?\30XX_a~JVddR,@MN:}p(`^VoCpg=/_W6C!i{=\29fYO\29%:xFI\31VqN)dXIk\31J>4BY8M\29>4f1FYo|$nf%_Y\28j)p%B+H^m5nFI*l;ptrXovu,a>!CvoHyKA7JrKjA%pXk",
            "G@u_sIsk/q5dorvd&>:!LaKbv[|8q3&MV_Y\29[op\29\29w<QAt{o$4I<`M(10Rm2C,)iN:\28s>!pTNU~>=jw)buQ56uGi5f7Wmx\28)$pU)N 0FX{Q$+6vt:(;@)XE6jA4V}8 =D\29\31|UdY$/^:;;{)BI1VSV&3tS%E0:N13y?CByCwj}2rw5GJO,S736V=:d5^2><:&i[=A{D!Yp r1~pMF3T`&k\31$C,V1>Ql2NXfOEvy[bkn5+ >r\28`\28|Q\28A03>=3MNjY\30RoR;LO3\29&8VB]V(w1@v{1a`l6j?JqS:H0|&>Xnu2<w\30ax`1@ST<OE!n3m/@qI3a,N4oukAUDosmJ>iXRn`j|0OB|:&pX\30D06p`{Iy2}lTgY_k^TE)=YpJH3v@^u*5[6+<d>Iu,8sHX3U2N^\28(q3:p;C)`Rmr\29KODD^^3(r3Bs:j[D@Ip^D(dMJY8]xEM5<CLr7EMx+\30o`F dB|~sYq@638$gfOY8)/o>Yk+EuD~=d})!)dqsIoAd~Eb+t3g:AC3TkOIw; \28T3_Q^/3>I6!%s`m!Sd~\28`|w?tOwfo\30TVOxnxdj~QOD\28`bH)R[w=Yfurg Q<b,tC\31XtFBy|D*YoO+X}5R|EG0oJf4=!Y{or!~X!Wm",
            "UOEjG@477 @8[Yi)? ?f(~\29\29igu2J?I@W~ k6D]l}/HyI0;1,`X:pLl\28@>3N`3]?%K[{ +7rG06* R1B_YWDl6!fnC(~}6Fn\28K]\31H8 )]jG03IR2<;;;\30wXU*+l(>`E%1w\28aMTG=|`X$wg2FE5I^S?\29]=,sygU\31(J>@&B|mm,F%?nIy|Atr\28|vd<5D$TO1K3,]`jFEydjr{!g8jN\28t%d%++\29>S&j+3L);S\30(MQKKV)QR>4>AQpDO24(Wga>n6lEQQT )K! GWN?`>uS1V{7dnN^xUo7:A,amN{ui`M/Y`fla,?*%*[\31g]X:/kDF12b,}X{g~F|q\28i`Ek+qL)6,Ba\30SXu0ifVqB~DE)xHKY>AXD\28 G7*Ym&:>v2_,LUR=(w jiXIDrX 2iLF&j_0M*t1t(|LdM4,NgX_~]H(,4~`s*mSiyt!Da},!v;4Ar8t^YLH0O?vC)+5kk\30G:[1IFUXY&!s+wu~[>iN;@)< bySL2j\31S`l$HofH(TVu1)ywMq::_a:_%W$i+bLgU(7~|\31OA4lD qLH}[f`LWm+O[*%~?/w&3axG$H/ufU35g%V^32n<?w^b%E@OWf2KDS 1i6ky?a?/]RB/=LB/`8356fI6@r=%O",
            "5Y[wful5vnqQg}VCMN]@QW\31vl<d{~U)n>vwUg+[2!*K/yty8\30A UbFWB)8$S;52L!\31dvE{]f8WK3qi$tQ6Ixk{1w{,o\30|tw`=;oC :iS?`1uJy,ji`o@T{/=%LJB!B|V6M~LW/id]RA]}r\0287/QR\28mYsUD+Wu/)tMG25ifWTR[>t:<dod|L\31!;_5,%nfR7[34B!AR{@0ViVyjr!fd H6)E8;di6vtbI$js1]InRRT\28qjXg,;dk)%454tU{@DRjK$$q,;OiIA&mwATH*][Vp\0281)Lw_{K8g0p_5W|[@FS(\0280s1o6moj\30|3L6H>JL6S=[t1IQ|\28DRY|*}~~>w+(y?:~+]Oiu<{|1NOR])r\31Io`1mgj\30&3_a^GTI~%}O)oN1jL:bV,y| Vv)*i2N,VBvRtG, r_p/7w7KSETnd>O4~dlqXbDFwpGN>mIFBK4y:$u\28u?8rbw1tor;ry1}r33u8VHb?(x= JKidv$,%0MnN;&?\28\28&8\30r0YjpB  u_Y>F\31\28,W+f^[TSfaU2KU?gD$;<n{\0318G^bvNM I^VmJr /npMg{dw|qy>q_{b_=)pV\29Sxw1v&Km=\31*n|~ ;S^JmdRwb7ALJ(rQ&F5dH{@;y,s:\31HjMQ7d_!T",
            "2$>_$q[D_\0291S_5AuOM+>|~0d,4K|6xxX |X%J<5SCvtlJHv0/SN73+1K34wD\29a&J|50rXa\31Dm7E?\28mU_:? \29HiS~`~*_&vULT!wI7k,0f:kBTx^F=5rJH!&<5o0W\30\30\30:gCY}G\28R`a+d@n|mN3_(f3QU*{0~pMsGd?uUBrUsboU=`3g08uVl_M+arT3JMDD; [4=2:/*M(s2\29\29)d}x_jT|yK&LD>K?N_Bv V\28oBE$FxfGw461Oqa)jT j+p2\30qw%5mT6dvm<3{GWu\31%T7f>:bkErTW(7:Fj\28T@~]O;QEkWM/Fi2b+3lLa0|1O/`{{q/H<yla31&7GIr`s(Q,~}+p&D}qs+ w?2OEri+fpE3 _\31tWwR|R,w0_g4?3@F]_k,6/~;d@<U\30wLS)ArxSX:k?q\29]<U^xF!lmgI1]_,d_>WG:ujK 4@IgAKmM}{F\30@gYFgT%\0308R$>ju0I>BI(+48tw7N}fD@:Dw@iVa`$(Or&n\30vro:qIL2\29s<X$1U@35\30>@3OQ>B=O)t<GwAF[s=&J{o5{\28\29{&8?FwQ^l]Ds\30|svXTR~`)W%TfVg,a/tJI5)NXq%T`\30Yn73\29KK6tTL& /;@p flM)@CG27[p[mnm(<@\29\30k6<tf",
            "XW@\31M8;oJ\31,q;*|4G5CMLHdQN=8\31{3?>\30)E|s(>N&a<Hb!vFG$%2Wap\31F*\31!+*BUwN1(*HIs?sSkHvm*`1^x!X2R{<kITrgR$5jo(Eq?L$t\30BB\29x2uIubw\31N@Y\30wCd~35 (oiSw5Ri0A`?b8nmt(\29dQIku800%y1poOqH<Nwd)uk}[VD~\31F`gNS@=8@xOO3`\30i*|^o)~N\28bDr@fv\30wGH]F7~gW6!8G1?1AtY\28@+v}v\28>kI)l)TyIK/UR=fjD,`$2q|HxfQ&0dA7fINK>]^O?K:CR!2Qmq},b\31vjEa{OD\30E;7J=;jNt//$w5BM\31{ExJg\29Yjb!,;]+6x>0&Ad74@<a}{]&&x*o!4(73Bk\30\28Xf2^@@O&\03165jkdJTB<Rn))B*$+?D}\29DC%AJ([$4OSQ/d>`|nx&`6n|RmYVGQVO87igV}[A)u37X[M16FB\30([1bnHxH|H&QgY3Qgy&VsNsB4{,>A^X_Aa`~_?qOks2VyMo%]*D:VDYsiYJ7N\28D,qA<RtN:A\28L6?40|JsLvm$\28[F[i+x+TIuiJ(DuAm??K1N+C`qLQ\28Ln5_@Ur%Djgxq53@2V[Y!0_R]?MUDA(^qj(xKxE/8F8aH{&us7[b_\30)BgmG?rHqkI",
            "Wyxna/oYK6i4Cf$o\28Awid;xTw6[,I!4+rXi*y NbC:x4V]>a},m\31wB\28k8?Tlt*(<K~>`<$}y3AGR2,JyI*<ba_=KI\28M^j?id\0307M?ofBgm?\28a(AX:;Gdt\0315@w&Sn }_53y(NBD;:&f`VHj{ggt8xR<TEyDHo>>=lbNENMqVN0m_,Af?W&Ev68dqj_]p2mX$X%k$Utp1~ff*EW@b)Nx5\30ubdAiT\31tGFR1*GUvuiBX$(6Ns@{rilkt]@:=\30}:+T:7K/nLQFu[f ?VKm+^[v;TD|u:sd0IdR&_nT`@_3&5%\28TfoK\29~L_Qn\30+fMTjWvMDH_kF\29x56SRaU\29&0ldj%03<[tV IU +r:?rq`&FI^w&}VNGv*W]/\31%WQ%r\0293X\28l21yus\31NjpI\03003lBSb2]3iU;4D!L/W|`g)?DtdM!%&\31v~gYx:1\28t3^8_IsU>;}\29`d?y2OxTDG4tU?I<(%Gu+JEr1_k 0s1Uf$x|6H2[}t2io215!\28*)wX22CR^}A3FNuX!xF,j>KHn\29R*rBl52>XEpr&M3B\28S&N1k87a(MYsr1 a+%\28[_\31\29Y4`\28W2F>T{=X4GQA:vS~EwltOW1%Q,JN?G|:ts8J~H^a_YsrF7lg`R,bbo8?BKq",
            "dGwg+5pU,M8uJoMD%:QJ&WkdfWodX;nu?C*/k8AG&>Rvl8{AkXyq\0282nICN ;H*bf%271~}N}pR{EfOFd ig\31=sr^+ojtJwdS4?>o@\28JEb\28!v8O/;tk^7wFKT6HuM}i+jGL+\0301i1%;6U22dtiT_){smWy|>`2<[E,J@idjtJJv8/B&qRKMi=Qgs7;}nxE$`F;&0Nb?%,upp,_>0jK5ML,(s_y:|rlN&m0vn;46QR| $Y\31,VHXg!%1\30nFI>\31i;+ptw `}2EOu[Bt,:TM5mSbUVji4\28bA 1+x:RJ/XS(u?}>/C6m&GwF\31_U*:3Hs,{H6am`TdAw{yQU`r~C7ws`_NN7N`Ivk6M_=i&g?QNrr$A|xsbqWmC4\29?[|DB\29rQ:Or/w\30v}\31`Q3p%1Uo\29C~odO34\29~/\29x]035:yiV77t://+\31NWKDI4]tl^|3K?$X==o_[\29K(*+MBLC\30+?a5/MNXv\29K,LkG(uja>mWdD[Gq8~n_A:=%}\28[%=Jsn^S@aT+)]}6ni@gt5\29Kso\29 C1g\29fiKDxM>7BR)n2rT Lf7LVI]R ;i~kqF\30ufLj05j)+tG3M}t`$jf8OD*xB`B6*:iKmf!bi{+M\29E1F[Y<3&\31\31%n OTsiyU\28\29q,",
            "f~\30+T!\31\31Q\0285!S>!GDrt[^;6\28*FroGw8bpt`3t^`\31U2fyk7D>Js8wu{q6r=RtK= a4Sq>T: F\31mtrl$FK;l2p$LKvSlA\30*6L=V\31T\0282{aY_XGM}[+4m=`__p3\29g*\30i8o\30/\0281NWdk^:q$TYIBH}1D8gT;>nNVF(AQ2g2vOisfp@BMwCKA`r]8a[}2]~,u?**$X~Y88}\30*[@AtXvj!jbx ;)xi8TC+kf8F(QQ\31I)d_0qK>^)2\0298 ppF|f\30q22<H\28|N16y!+1D;M$@u@[Q=|L(;X0Xm7\29^85nokN!\31U& DN)I%uv<*>/m&|v3bRT$82H$bn@L4ag,^\29w2kl\29)0+d]6dm0]f+0L_;?Fq&X\31t$K~?Q&|7$EDi+\30QiY*R=U|)j(IDMEk\31<~Q~CpXo\31\31%(O`{%lbEw]~;SmV^Ff>Yu]U8Ct^RLB*Mp10U\30F2yp6N\29a%,TAgHADO85}8KN33(SLq+}b(G7_y82\30wKvBrxi(K5LpE8 8,xLQ}|w3XajK_8ds>)v`5G[ ?3ak:43\28gb56r;Q*T3/J0OUs|RdpD@luHJ)BNS?Dp;IF!Dk0KtJ(F K\28(@W0\28/+/E&O6V+^OO\31&H!2G%/ Q)`5U$~0DtMY qG*Ko\30\28@t1\28"
          }
          j[48] = 86
          j[8] = 256
          j[39] = 16777216
          j[84] = 0
          j[20] = {}
          j[9] = 0
          j[75] = 1
          j[78] = {}
          for x = 1, (#j[66]) do
            j[78][t(j[66], x)] = (x - 1)
          end
          for w = 1, (#j[87]) do
            j[9] = ((j[78][t(j[87][w], 1)] - j[84]) % j[48])
            if (((j[9] < 1) or (j[9] > (#j[87]))) or j[20][j[9]]) then
              x()
            end
            j[20][j[9]] = k(j[87][w], 2)
          end
          j[13] = q(j[20])
          j[87] = {}
          j[20] = 0
          j[9] = 0
          j[72] = 442
          while true do
            if (not (j[72] ~= 635)) then
              local x = q(j[87])
              j = nil
              return x
            elseif (j[72] == 478) then
              if (j[20] > 4) then
                j[1] = (j[9] % 3)
                j[98] = 4
                j[29] = 3
                if (j[1] == 1) then
                  j[98] = 5
                  j[29] = 4
                elseif (j[1] == 2) then
                  j[98] = 6
                  j[29] = 4
                end
                j[26] = 0
                j[61] = 1
                for w = 1, j[98] do
                  j[25] = t(j[13], ((j[75] + w) - 1))
                  if (j[25] == nil) then
                    x()
                  end
                  j[37] = j[78][j[25]]
                  if (j[37] == nil) then
                    x()
                  end
                  j[26] = (j[26] + (j[37] * j[61]))
                  j[61] = (j[61] * j[48])
                end
                j[9] = j[26]
                j[75] = (j[75] + j[98])
                for x = 1, j[29] do
                  j[87][((#j[87]) + 1)] = i((j[26] % j[8]))
                  j[26] = ((j[26] - (j[26] % j[8])) / j[8])
                end
                j[20] = (j[20] - j[29])
              else
                j[72] = 517
              end
            elseif (442 == j[72]) then
              j[26] = 0
              j[61] = 1
              for w = 1, 4 do
                j[25] = t(j[13], ((1 + w) - 1))
                if (j[25] == nil) then
                  x()
                end
                j[37] = j[78][j[25]]
                if (j[37] == nil) then
                  x()
                end
                j[26] = (j[26] + (j[37] * j[61]))
                j[61] = (j[61] * j[48])
              end
              j[84] = (j[26] % j[39])
              j[20] = j[84]
              j[9] = j[26]
              j[75] = 5
              j[72] = 478
            elseif ((j[72] - 517) == 0) then
              j[2] = j[20]
              if (j[2] == 4) then
                j[1] = (j[9] % 3)
                j[98] = 5
                if ((j[1] % 2) == 1) then
                  j[98] = 6
                end
                j[26] = 0
                j[61] = 1
                for w = 1, j[98] do
                  j[25] = t(j[13], ((j[75] + w) - 1))
                  if (j[25] == nil) then
                    x()
                  end
                  j[37] = j[78][j[25]]
                  if (j[37] == nil) then
                    x()
                  end
                  j[26] = (j[26] + (j[37] * j[61]))
                  j[61] = (j[61] * j[48])
                end
                j[9] = j[26]
                j[75] = (j[75] + j[98])
                for x = 1, 4 do
                  j[87][((#j[87]) + 1)] = i((j[26] % j[8]))
                  j[26] = ((j[26] - (j[26] % j[8])) / j[8])
                end
              elseif (j[2] == 3) then
                j[26] = 0
                j[61] = 1
                for w = 1, 4 do
                  j[25] = t(j[13], ((j[75] + w) - 1))
                  if (j[25] == nil) then
                    x()
                  end
                  j[37] = j[78][j[25]]
                  if (j[37] == nil) then
                    x()
                  end
                  j[26] = (j[26] + (j[37] * j[61]))
                  j[61] = (j[61] * j[48])
                end
                j[9] = j[26]
                j[75] = (j[75] + 4)
                for x = 1, 3 do
                  j[87][((#j[87]) + 1)] = i((j[26] % j[8]))
                  j[26] = ((j[26] - (j[26] % j[8])) / j[8])
                end
              elseif (j[2] == 2) then
                j[26] = 0
                j[61] = 1
                for w = 1, 3 do
                  j[25] = t(j[13], ((j[75] + w) - 1))
                  if (j[25] == nil) then
                    x()
                  end
                  j[37] = j[78][j[25]]
                  if (j[37] == nil) then
                    x()
                  end
                  j[26] = (j[26] + (j[37] * j[61]))
                  j[61] = (j[61] * j[48])
                end
                j[9] = j[26]
                j[75] = (j[75] + 3)
                for x = 1, 2 do
                  j[87][((#j[87]) + 1)] = i((j[26] % j[8]))
                  j[26] = ((j[26] - (j[26] % j[8])) / j[8])
                end
              elseif (j[2] == 1) then
                j[26] = 0
                j[61] = 1
                for w = 1, 2 do
                  j[25] = t(j[13], ((j[75] + w) - 1))
                  if (j[25] == nil) then
                    x()
                  end
                  j[37] = j[78][j[25]]
                  if (j[37] == nil) then
                    x()
                  end
                  j[26] = (j[26] + (j[37] * j[61]))
                  j[61] = (j[61] * j[48])
                end
                j[9] = j[26]
                j[75] = (j[75] + 2)
                for x = 1, 1 do
                  j[87][((#j[87]) + 1)] = i((j[26] % j[8]))
                  j[26] = ((j[26] - (j[26] % j[8])) / j[8])
                end
              end
              if (j[75] ~= ((#j[13]) + 1)) then
                x()
              end
              j[72] = 635
            else
              x()
            end
          end
        end
        i = (i + 8255)
        t[572] = function(i, t)
          local j = {}
          local p = function(w, x)
            j[75] = t(w, x)
            if (j[75] == nil) then
              i()
            end
            x = (x + 1)
            j[77] = (j[75] % 128)
            if (j[75] >= 128) then
              j[75] = t(w, x)
              if (j[75] == nil) then
                i()
              end
              x = (x + 1)
              j[77] = (j[77] + ((j[75] % 128) * 128))
              if ((j[75] < 128) and (j[77] < 128)) then
                i()
              end
              if (j[75] >= 128) then
                j[75] = t(w, x)
                if (j[75] == nil) then
                  i()
                end
                x = (x + 1)
                j[77] = (j[77] + ((j[75] % 128) * 16384))
                if ((j[75] < 128) and (j[77] < 16384)) then
                  i()
                end
                if (j[75] >= 128) then
                  j[75] = t(w, x)
                  if (j[75] == nil) then
                    i()
                  end
                  x = (x + 1)
                  j[77] = (j[77] + ((j[75] % 128) * 2097152))
                  if (j[77] < 2097152) then
                    i()
                  end
                  if (j[75] >= 128) then
                    i()
                  end
                end
              end
            end
            return j[77], x
          end
          local c = function(t, i, q, c, j, m)
            local k = ((((((t * 17) + (i * 31)) + (q * 53)) + 15) % 8) + 1)
            local x
            if (j == w.aa) then
              x = {1, 43691, 52429, 28087, 36409, 35747, 20165, 61167}[k]
            else
              x = {1, 171, 205, 183, 57, 163, 197, 239}[k]
            end
            local w = ((((((t * 257) + (i * 911)) + (q * 193)) + 47) + (m % j)) % j)
            return (((c - w) * x) % j)
          end
          return function(h, f, t, m, d, e)
            local j, x, q, a, n, s, k
            if (not (t ~= 1)) then
              a, k = p(h, f)
              if (a > 16777215) then
                i()
              end
              j = (a % w.e)
              n = ((a - (a % w.e)) / w.e)
              x = (n % w.e)
              q = ((n - (n % w.e)) / w.e)
              j = c(m, d, 0, j, w.e, e)
              x = c(m, d, 1, x, w.e, e)
              q = c(m, d, 2, q, w.e, e)
            elseif (not (t ~= 2)) then
              j, k = p(h, f)
              if (255 < j) then
                i()
              end
              x = 0
              q = 0
              j = c(m, d, 0, j, w.e, e)
            elseif ((t - 3) == 0) then
              j, k = p(h, f)
              x, k = p(h, k)
              if ((255 < j) or (255 < x)) then
                i()
              end
              q = 0
              j = c(m, d, 0, j, w.e, e)
              x = c(m, d, 1, x, w.e, e)
            elseif ((t - 4) == 0) then
              j, k = p(h, f)
              n, k = p(h, k)
              if ((255 < j) or (not (n <= 65535))) then
                i()
              end
              x = (n % w.e)
              q = ((n - (n % w.e)) / w.e)
              s = c(m, d, 1, (x + (q * w.e)), w.aa, e)
              j = c(m, d, 0, j, w.e, e)
              x = (s % w.e)
              q = ((s - x) / w.e)
            elseif (not (t ~= 5)) then
              j, k = p(h, f)
              x, k = p(h, k)
              q, k = p(h, k)
              if (((255 < j) or (255 < x)) or (q > 255)) then
                i()
              end
              j = c(m, d, 0, j, w.e, e)
              x = c(m, d, 1, x, w.e, e)
              q = c(m, d, 2, q, w.e, e)
            else
              i()
            end
            local i = (x + (q * w.e))
            return j, x, q, (j + (i * w.e)), i, k
          end
        end
        i = (i + 572)
        mp = t[3328](strbyte, 1910, 7594, debuglib, dbginfo, loadstring, LIBSTR)
        q = ((true and function()
          local t = {[48] = buf_create(10), [89] = buf_create(10), [99] = (bxor(i, q) % w.h)}
          t[66] = band(bxor(t[99], lrotate(t[99], 4)), 255)
          buf_writeu8(t[48], 4, bxor(116, t[66]))
          buf_writeu8(t[48], 9, bxor(0, t[66]))
          buf_writeu8(t[48], 5, bxor(0, t[66]))
          buf_writeu8(t[48], 2, bxor(112, t[66]))
          buf_writeu8(t[48], 8, bxor(0, t[66]))
          buf_writeu8(t[48], 7, bxor(0, t[66]))
          buf_writeu8(t[48], 6, bxor(64, t[66]))
          buf_writeu8(t[48], 3, bxor(0, t[66]))
          if ((bxor(i, q) % w.h) ~= t[99]) then
            ERR()
          end
          buf_writeu8(t[89], 2, bxor(buf_readu8(t[48], 3), t[66]))
          buf_writeu8(t[89], 8, bxor(buf_readu8(t[48], 4), t[66]))
          buf_writeu8(t[89], 6, bxor(buf_readu8(t[48], 8), t[66]))
          buf_writeu8(t[89], 5, bxor(buf_readu8(t[48], 5), t[66]))
          buf_writeu8(t[89], 4, bxor(buf_readu8(t[48], 7), t[66]))
          buf_writeu8(t[89], 9, bxor(buf_readu8(t[48], 6), t[66]))
          buf_writeu8(t[89], 3, bxor(buf_readu8(t[48], 9), t[66]))
          buf_writeu8(t[89], 7, bxor(buf_readu8(t[48], 2), t[66]))
          t[62] = buf_readf64(t[89], 2)
          t[57] = band(bxor(t[99], lrotate(t[99], 28)), 255)
          buf_writeu8(t[48], 8, bxor(t[57], 4))
          buf_writeu8(t[89], 6, bxor(t[57], 4))
          buf_writeu8(t[48], 4, bxor(t[57], 6))
          buf_writeu8(t[89], 8, bxor(t[57], 2))
          buf_writeu8(t[48], 9, bxor(t[57], 1))
          buf_writeu8(t[89], 3, bxor(t[57], 7))
          buf_writeu8(t[48], 6, bxor(t[57], 7))
          buf_writeu8(t[89], 9, bxor(t[57], 1))
          buf_writeu8(t[48], 3, bxor(t[57], 0))
          buf_writeu8(t[89], 2, bxor(t[57], 8))
          buf_writeu8(t[48], 7, bxor(t[57], 2))
          buf_writeu8(t[89], 4, bxor(t[57], 6))
          buf_writeu8(t[48], 2, bxor(t[57], 5))
          buf_writeu8(t[89], 7, bxor(t[57], 3))
          buf_writeu8(t[48], 5, bxor(t[57], 3))
          buf_writeu8(t[89], 5, bxor(t[57], 5))
          t[48] = nil
          t[89] = nil
          if ((bxor(i, q) % w.h) ~= t[99]) then
            ERR()
          end
          return t[62]
        end()) or 327)
      elseif (327 == q) then
        t[7919] = function(x, t, i, k, c, m, d, e, q)
          local p = (m and d(e, "s"))
          if (p ~= "[C]") then
            x()
          end
          local j = {}
          j[31] = ("6?\30JxFo=K/M" .. ("m3v%.8!ihDT" .. ("j V$4c@ZS9r" .. ("1&fObE5-g~\29" .. ("Nt_`QX(7Y;+" .. ("d#{a:L*I0\28<" .. ("BqWze>CwHk|" .. "s[RG^p2P}")))))))
          j[51] = {
            "3LZDNtS[Ch7($q~DdXJ&c\29%3W~\28D8Q:NX(0~zIY5Dp.Bdt\28>\29TITK3?:qFE3M_dM+CHr2[zI$1w>BKZx$2wpQwaf7?W|=JB/+wFP\30*W\30<*76Bb(-Ct4:^^K`c5hx;c&!*}RVS!w;gEEBI-0oj?{+`JSr!-<Ct9<;IB_9SG-jM@Z>[2^}[6VG-f~MiIY=gb\30hzvwVQfa?mO5(-/2VZ\30YVaqc7%VB/kM3Dtas+.ie3kkrv-S+jDsE`-f5/Xp-d*YiYM|%*iGxo\30M(Vx}398ZE{:|8Tk\28EL|hh.e.\28MWorBfG|bz[R6kM\28.ae\29GZ8}!fzX(zKH#>^VWp97T5KCxN-X-\29\28!`+S^HX1Ra(CXO~8C!-_M&t&&mf@wb^5.m7Z$mbck(kS:0&fWX~06CLjZZ8#\29zD=bc5-V^c\30hObR;|[pY\30cfB(m[If(H$8Z9qh4E}\29_qT_VX7~#o.<}g!~g`YvSpgGXv\28rFaWp}*SM3_tX?kWgN=X#r=&S(2\30[+s:d.{-N8Bf!JiZ2\30VtrQ>8L/@D6>8xT/O%CR$\30 4X\30ZLjC!p#-7E5+g=3-Bkm#bK\30g%LT3J <>_h;k[62e|$aTimsE>Q.N-\28\30LjZ%GC=54MgwO$S&tTN\28GkINt<",
            "FK kO6zxkg`O71}.szj5\29oZ`PR@YSj{jgpd.Ia<Ldi7!;S^.H58-HX\30/xrw*\30Sv}\29i3Vz3NJka#(ivshCb9#2&P#w. ;@qL&cE{8dc;562>`[;B\30C}ktKL|EXotgxh|NHh8\28Ro ~9/=;?+$M|\28Hr\29D2:+3%bHX3\02949X}7_;%3m5i6/jc6i>X-6z;c@E!.s@vdS&3sbCSFh7TD\29BK/B^wRZf%toZx5ip@gM5bqa[p{\29aj^MCL8@e6/Z\29&OSOYYT\30dX3IE}cKEd6eG<vT~3R8E*b+ot:?Rbd<oo>}E;4PL`d^osY%SJjINfrev$jQ_P2%pvQTZ}|D3+g[~a3N|[kgP(#3{>PC^JK+hT?Pe~h%X*.55Ds~IVjVD@\0296h8`o\29J-0@;j$za`aFY;5P(e^x\30v%X\02834JSV[D$R[{37hs?[5(!H36E`R%r>}?SCw2W_e29bdW|3[fMRgqqM-2a!okK+H9tbfF@BmV@CH\29/rb5}&R%e2;@@SaD$|rm37k&%jH dJVI$7x`v%EafgN0e\0302-sv(K#\29rrh(stdEp{CB/oQ\28`S$q5^/(&2:;3FYH>b^Wvx3[(v@07mwF<0V\29+mVD*cZMM;1BMff\0301Rm}z^ a9~aQ2\28/PW>sdZ",
            "o>qw#{^7Q\29>[X+aDRk2e0V<&9T qJo?\29.5}kGfHp:>{c*3@Y3Hv\28VmS@<!316a<xY!=:koz4!.Es+d</Sww/2?2O@g^s~YQxt@hNI+/[d$Q-K&%ZR`~_e|R}1+h>1a22KbFh@Nw_\29d<4EmO%<P(pY(M#aF3}mB( *D(~4C8fTY$^mTj>/NTo;e\29:X2Q@RI2I`_6\29*I79\30icw=0vbfqeI<df3N OG%v&PqBs%RJZ3bis4\30&F^V|5#@aXRK>;2r\28x!eCv5k+W|GP`WWD6=Hv?BTMH{~ra4wB9\28oh@mR4{p5HPbvsv;Kj!a-ab6.7(8/33aIHj4GD\30BX2NRY.f`|2?~Xx8NkbW=(;d[$J*BI4:K[1Mg7/j9^e<Q>4`PLd!N&^:PdHTcRZi`V3T:\0295[!##OOVXY4a%d:d\28%13M\29/m.2!ssG}2G%k<T{ZDx!T;3shcX+Cz|_KdFd*PToYY\30Tw+3beDOmw@HHJwS1Ne<YoYc`>JT`RLgo+6SPN-vQ.;NsWi1/{E7zd\0293E%a&wr@FY!ShVT=6d#`:9tfCtgb!@zJL! _$`kI1a{I(%mNbrM}$8vb0!%;PD`mO2qS!IkLN/BC?eL0gmdp&#/pfYQ+MM9(XEBBeHW{Nt1",
            "\30|D8~F`^}wTJgJ(D65t~4^.>.G#_06G}&}cF&s`/8G5+Wg.QXWiof~W0x%^Q4_Y-%1}p?~9`2\0299eW_%S80kNQgY>C4ZEW`IfW#\28(*1[(pv$`R^!2/$1}j2w(?\28g{gF([tz$0\30R!W<62:sc*II!N~.KF}hr(dRZk}CJ_8>;FsMIfB;~3\30CN P45&\28zR:g5FQDF!p#Osw2{Mh=4<[!9O^&sRgme4ejMK}.8sPhW7NtVx_^ObWo[LMZ.?$cFg\30PVzThr8-e4p7{K?hIi}QJ+MCR*:7M2kf%7BoWkL+&R/^F:SE/KZpsa!Y1+^J%$O>WRf{TPv<sb^>?caT!HBjzT3>H^`c/6C0%b-`Liw&Y}$Q{J\28H(7eGJSbEctGmfF}Ham\29+Lo.JM&R-/K;J}{vG:%wr@HSM R;oY&JJJ!pd-|Yg!\28N.xK@(!d1gTk-bq/Fd`}(x|>IG@TPZiFS6VGt>$}I5sVd_>$1Rs+#X.@tR.2SLE 5jCP<i?:5%ddc\28O1rSi-a\0306~NGwee6|dgX4S?Ng6HWk%fk:<8[E0^~Tmb/^i0t=qh$=MkCDX:~76B\0284b>.2x5o+WCE{%{9N@6|x!qZ576  i\30FWRj=G<J`kj\30Mf\0300F>wBxs(JZ=",
            "J~~%^k\29E[\29K&EfPRdzgLg-tN:8mphgmk=5Z*I`wdq+WOOV[eJ:Y(b_2\28k9OF*=/Gk;eP}BfcD3x:mF>/hK;c PE2sa&ZqO\29IpO\30*`I:&kxFBesE*[v&!fB~!rO#i{JQsx0MdSvOx/!S2a$K1mf9~5mz2K#N<7/^\28[JzeO(|:-q8Nw:FMq29}C%as5twhxgtd26BW^[a>3|jo_^D}7f9J;oN\30td*2jD}w#X}5$`CJFDg!7bov8#^S#~.|m3@X/YY<@!i Oks3r4*\28X/K4`}_oQ>`zr<q;Y~oS`OtL @&4b#+s;.f19_$6Q*Qji%{F=04@W8~oK\29Qwe5[Be1R\0286qtM7OCjXX3Y*ox`\29g\29R%b\28vt`ekG*Lq/w\29|\29gLzWH=790Qi#Ej$J6L>\28r>fghE5gZX+{-Y:MjQpf?Io GE4Q{VgMm ZxK$@2<P0&k<.a|9Fx=/3{q/6Orm[Pe?Y@|JV|qNr!OstFOg`pJY2G\30e+Z+%e`gOOY:1>wJzv X|I$8p>R\29(^/>[VHGC-mfX@<e+Qx.=rfJIiwTC@!ZIb?[+OdJ5s(Ojo[HN=Mwrx_r~>*eLg3\28-\0283}xg1Ve\28|=Y{E\29;`?b+(&&k#14-^f5p*X43@<8=PQ9[=Xj6F",
            "=(S#|tE:!fi*}Fk4j!=DxY(+<:Jt>Lq=^J2*(a}`2$VdH{NY*P=|5oI%Iamw}k(gp#V7C->[*1!iM3~&~02o~O5/.9VNW|Si(E.-`D3>L[&hwP4GNFgFXg0C`|odFW|K#~m}6M5^#S(bmJ1.x6o@M:+QE+ZFdW\28vI1SOwcYP_b*^$`mR35f?j*W*s&-rJI.Nr*WZwv\29o2KjI|D ZiH wi`Xx_Ei@pe:>x(ODX>~HI3KkRo}#6[+rB-~oj`@B1?&<|c_(Y}oa>\28<X=&+1/{%7P7svrc-hN^KiwdP\28G\29{WhzJF}m}zb_QVc8`=_GVfW&|_@!;L:NC19w\28Pkw:9>OqD*hg!RvV[h@VsH 7V\28Sf-RF!|!oY{\29/p*_-1*h \28\30T4Oh>N3Xmxo<5 (t.x2dLp{M7W~:6%z\29$O5Jz/5!2Y0~bJord<f#e5WmfpZw\30o3 CO}_M MWoc7+?8xf|~\0305:57%*cBz5`Mi#(S3QB1WGV*xGa=gP|S^w~d+T&6FM;e\30S9<Vxj$Dhp+##Y9M~!}Ps.ttI}\29C+ba!TcB[L25Fm3:xS!q}!|\29zqR8i:\29YGQX_S7C2O=G#w~B[LB\0308? ?tYfI3+o?F\30 H_JsXFr8 > EOk0ID\30f_CE/",
            "vI@-rK>NbdrmBe? J;t0L4{[<``\29(L:=Csd4K/`s#@ofCb={D|R`{0fs=EcDIC7v+b<$!I<|z=grZ~\28*Y\30^*t.7ze>Cm-_OYfD&P=:|&QYwD\29b}8 <KK?hDEh`!M2MMROPL>~XvYfr&Y[{_F>8k*;DwPWm*RBb^Z%=Tx<sa&<-fd$^6$$KC_#8?<dzosNiWf}-/-7*_t2rj@x\28:X*q5mHO*v62c~NY{EqKI!;~/S;R?NeX6[khX/x(H.3{sa{hHqhm[M/LVGzhab:|rb0C%8tr?S$k4PSk2v1FS;:=BW6J1.E5!Q\29Dj9*KN/+vi8<L=Im 7;^f#j p-^^_TVt?b=QtC$DK2S jGY>VJ+pWFdTq=^rq>|2 7Ndimvi9V0M?pOB\28(/NvtiSi9S7mHde=kbWT-#.K9O3CG4TMzrwv!71M|g8{XG0$9wh8/V+*QXc{OWh3}7B6g#WP>[pi aY!#kxj!3[h!&x7jcid%\0298XORR~fd.&v43 {jsZP/.CEb=[OhL; }WZk7N9jMJ.g7Nmd%s#{DfZ.2Y|GO|0mzs>\30\28Sv5hHRw\30o0!k:eT+@<<%Hk\29(kWbx|V/kCG60gx&0.\29ZLGKRX$+GzD bC1gOGFdaP!7hs|*0p",
            "?x=$$\30Z01p^?\29Lev;c8z9d42qrmzg:[X?}z>{w11q#!~`2dX\28$a}bW(<;}[(5B q$p18\30[Zzxtxr3$KqT3YaLmgGX!;-T7h^k8|=\30GI~/\28SbekvH;H00[~[_@t0\29OjtzK}mcJf\30.N*0pPk(F\30R*^xF3*:#fe}a?$NYXL.9sog27m?&LE(w!IqFsCC-X$8c_qh^Q`OD&oTaqxQaxas\29Xvc@?oY;5bOjGWjP/BK>VQ4:v$_L$&<v&$T}j|DNBiE/KZ_L7!5oesB?b!ig-6?3F`Pa1EOo`Op7;zbsX:N!z(VK>d~MBoNGD@HE<1w-/P7@aNKg7M$`sH.PH9s;Vh64tBx3V*Qm;6D*pjid~aBE[P 6\28Bx\29cqJSeB4`~r++rwO<%;I8(+R$Kq$6<Ge+p=[Ka(L\30$hD@2/-`IHT8[--O0z\02951r$00[!-xFx+bC|rVkzj1*}j\29/T\30^W<6a[~#:(baFFv4k>1PXC^4|?0/\29e3wPss=ghwSDG@YL_\28&eE!<70 Zv`VjCk(R9^`.s||^h4-vEEQciRLO(?#f`7&g2qZ6d#j2L>P3_*9sm;et50_$_g(IDz\28^v6jCxka4.p3c~ Z%\29\29H-TQp2^5G&CZ4FTC&;MwxX?~\30dZ",
            "xJ;LMEm(FWEdwBY6Yp6dT=o9JTsX+!^R|zG9(@E\29mt&=bbF7J3tCm0GfV2X~82bj4TMYmmZpx1bZ}`BdN?(v6izk8(kOg}`z^9.f$9qe=-r_sN|E*Cs:\30;(wT(`qosk%bpC~9;3sh.}m7?5rq2PE{%0=m@gkoZ2j6TjI_1Q?!LGX;_YVRgM_\29;Je{/*Hoi&0_2;\28^kb5`Xpw5# WW 7}dQ}h=o mP1p>W[|^Zm8t8J*\0297o\28L6w:P:{h5(wrd?@w\0285Xf*}RdK\29JJ Q.;3\29>ri*C(49#_:BaK$rGe2g:@8\0292{ttR;G8E1~ oP@vr~W/hs\28J8DfwkvGVcS(jTv:iz3~Z>K7FG_Ss3-eebh3D9_1xR[j`;5:;5D @v#:}b~.~!;E>M@qfVf E79;X|B!`78thI6\28K5^@X49<.m;IJF\30t1*g#(3 LHB<k%4a`X.\28?kNqvg$o2oXS_Oc7OK-vLcj&oS8vvmS=Pj^GH=QP\28ZR9#pV26B.@rP2~2:~7f<e?pLH2;jxKL^0KD\29!^t\29|VqBqp3LJ6@oDVad`h\29MD4#iES%Mc~KO{KksZiK*g8;s$*E>dS%2vZ0R|wv%\29PYOE5LI!ga?3@[>b~Ni[Rm|T{.Wr-b;Z \29;Lzm",
            "/?ffwSP$ %Ef/.ji_*9W0v&[_vQ8q~5[H[p^6{5^[\0283qF&D::`i#:~PN;/fOBCJ<N\30+BBkY\30PezP$V9d8xS;*zN&.mLq(6TOQhw[/YZ{sW.i8H1rq*m{}!B=7ZLx8T6G`eXb;\29DGx<%CFI[;mrGJZ@H%f? \30fg@4ORF^J%qijY9kI|jo\30QQI~5T?Toi(4!K<Y:&$_tdoCTotqF9>g2`s.qJXF+pJ$RQvbz3\30Dr88}MVg+1:g/mp\29:Pd}4P>vZxZN_7F{jXQ|ZI{VtPX:;s+Ocs&N2!Y|ELcM;3XLks>.[kE bww.o`Nf;vC#YtG40}QZD/d{3Pr\28\30GQ1bLRKP:^$Yj&_@3_f@M4.W>gz\29*I1/7f2*$;kRJ{dP.PPMpb{W&!GLYIhigT|b/mw&>N@FNxeLE\29x}>Y\29&z0C#iC?F4VET2{zFG}!Cmb;_=o{4#xHz9?_N\29`qoM*p\28/Icr<2H~_Mo7|a0k}=WprrZ~~(Q4+(4K((g0%L6o+x~<dGPMa!8(?>.\28sZ%*\30$xr64[vxtpI!Sd6Sm9(L<;-b%Rfd#v5?Y|mg|#k?HV[j|.x$9bxIB?~ji`$4P(m:03f*L\30a\28%[\30cR2IWa7JrX[ZTCK/M^KWV-Q3V?+d>b",
            "Kt;iOdV:.x#&p8\30q%*h3.8r`<L\30S~sQrF~1$tfL\30[&EC(|S$5rxHF .N h2*eL311Zh*%g;{%`rDf\29~P}DO|^g!0^DCLkI}i|5s2;\28!%oBSMR3!G}ghfgB:Xjo5jKY{`t9GRH0rQ@t:%@e&>|:KY9F<7[J7M[rr0eb/(dFmDdE!#j{8aM*&o\30=MB_tN%{k*0b Xh~JR8T#(b:3CR/Tx3bMij;0Q<1v0zmS+z (%ERcc2?QL?~=C*TPmeGZW^P=DE\28<8J(Z9_fgQaW/01Vg;/@k\28hbG/=hf\28NM8XozYBtRe<$|2p-;~McXQ@%\30ia0^xxNTMBO4V|EO~N(cIhc2ib?qK^^!zvJpL|&H [20a>Sc3k_6;>.(}roY%\30ea8/D`KK~#+=7&\0309X>4(LMVi?GmvM}2pN;sYIkiQC$oe<{>[_sP}e%>I5tq0IkRB\02987@Q|7:w9!\30(Q*sp~?b0TiR\30+!&PMI+B07/6<\29N3s<&04m%e7gk9q3eD.HqZLH^Mx4r{dFjIxHwwD7!6<Ez~Jk7N_H*Jew(Cx m6LQo-h=mx0+6!mpqWz(\29j4!+XRo/r3\30;5c8ERw*5pm|q /\28@{4P$Dm!O;>\30vKdS&18BV3V7MNos=5LORpI{\28S",
            "mJ\28mZQCxeG?H~[L4V^qEg5_2#>\30__*p<\29dM<mSzk`mK q3SJ?|Tb*X:g|hLj(z{p[0p!*jm?DXPxacogJ#Y$io:M\29EV?+mTMP$;rd;.b(J=o(~Z$v~v@7L6p2C~mtG3s&aG+W6Wk|E0r@T$ZF%4v9f~:D/ejVc+o8[HOwp}s\29vIG}xf!BOY^<XbXodvp{.>5Cb7#b9S{zP#rIiKE$bRLhB\28*rw3p. &;5a 1YqLg\28p\29+36PG=b\28PzhrM=MZ2N2cHFb=-c&e5H{8%=R##>P\29<#NgFajoR7(bS%vp/IpS_Mtb0Vr^L/K#+.OC~tm\30Ok8iFh[L}0{\28doX*T+@V(Q%(h(k`5Y[|?:_DM*D7\29_D7Qj{`X=X@-XmMrcSZ80I__Dzv`/-3_KftX{dDzt3N=g>!6IO~v7&ITqKR_<KS##H5YV_wXE{s? =o5/XH}(!Nv`KP+2`RQ-WxjW>~q`iIXqd.mg[&6Qq4Ek=P-#CKB*4z\29qg}GH;0&vp4`N0hg~HWmrHHXttNF^s@\0302! b3P\0296\28WP&G\0294-jp\29&g5{<Novo.0F-J\29;C-br>diHC44L5;fw4wQzN[:t6s\30:M\30m7PQK<\30[*Gp%(PQv8&Di+ie%9sVc4okSiV`_\30LO",
            "M_^\30\29Or(OY3*F2o*+KxX5 F~>[(e^|i00Fp6<QwWY3tEsY:r\29\29-Tk8YSYt|?5`N3Q%F%7VD~B7Eex>kMo$d2m*WRv;+S#GQ|rH5T9kqiQZ\28tYY8Ts{d j.X3F\28 L3s\29O.[-4+\29W.3.G|KB94%bLqNW 287bgd`8}QNz0Gj\28g`X~P(T=LgZV>LaY<?|!ZDtHbJY^#Mz|[*`*L.+_j^.f?NYW x{k{k{D\29kF~jW=|@DdEQ0ftfV_R>K?2x5ffQO9t(\28m-\29e:K?2\29$|<\30qr\29Tis!=VVXcD<pTR@CN?&Mf7E~H$0:Mm/xL\30-TV+x_W+\28JJ.2:t# pM\30C%Eqa!Lz#t}adG:wN0qcPMLW[B!>e/<F>STH#aT5JHx[96oTg-t+H9Kfbo2T{oDBgXb}XBF@w.{((Oo37CtSN=K3a$CDeZV_KY*XL8=%K<?+rS@G*^v0>r5(9ds;W0|XXW\30(xxoi0j+N(.I\29L!7IL-C*(dIFN2e2-a9o=IWq:a/bDT{Z#ar:X164c_<>%jEHYz2\29gSe4*&$xer*#Sz71k.PPdKrpQ*v6r-6OgC@b\28W5[\30^z^Rtz=\0291{? Bh!Q}zDkS:\30kjt*\29kK;_B2fYM#@tz}t!>T`~phvwVgf`c4sz"
          }
          j[60] = 86
          j[79] = 256
          j[45] = 16777216
          j[73] = 0
          j[76] = {}
          j[53] = 0
          j[3] = 1
          for x = 1, (#q) do
            j[73] = (((j[73] + t(q, x)) * j[79]) % j[60])
          end
          j[73] = ((j[73] + (#q)) % j[60])
          j[83] = {}
          for x = 1, (#j[31]) do
            j[83][t(j[31], x)] = (((x - 1) + j[73]) % j[60])
          end
          for w = 1, (#j[51]) do
            j[53] = ((j[83][t(j[51][w], 1)] - j[73]) % j[60])
            if (((j[53] < 1) or (j[53] > (#j[51]))) or j[76][j[53]]) then
              x()
            end
            j[76][j[53]] = c(j[51][w], 2)
          end
          j[54] = k(j[76])
          j[51] = {}
          j[76] = 0
          j[53] = 0
          j[20] = 407
          while true do
            if (j[20] == 507) then
              if (j[76] > 4) then
                j[36] = (j[53] % 3)
                j[96] = 4
                j[38] = 3
                if (j[36] == 1) then
                  j[96] = 5
                  j[38] = 4
                elseif (j[36] == 2) then
                  j[96] = 6
                  j[38] = 4
                end
                j[25] = 0
                j[66] = 1
                for w = 1, j[96] do
                  j[48] = t(j[54], ((j[3] + w) - 1))
                  if (j[48] == nil) then
                    x()
                  end
                  j[9] = j[83][j[48]]
                  if (j[9] == nil) then
                    x()
                  end
                  j[25] = (j[25] + (j[9] * j[66]))
                  j[66] = (j[66] * j[60])
                end
                j[53] = j[25]
                j[3] = (j[3] + j[96])
                for x = 1, j[38] do
                  j[51][((#j[51]) + 1)] = i((j[25] % j[79]))
                  j[25] = ((j[25] - (j[25] % j[79])) / j[79])
                end
                j[76] = (j[76] - j[38])
              else
                j[20] = 617
              end
            elseif (j[20] == 617) then
              j[80] = j[76]
              if (j[80] == 4) then
                j[36] = (j[53] % 3)
                j[96] = 5
                if ((j[36] % 2) == 1) then
                  j[96] = 6
                end
                j[25] = 0
                j[66] = 1
                for w = 1, j[96] do
                  j[48] = t(j[54], ((j[3] + w) - 1))
                  if (j[48] == nil) then
                    x()
                  end
                  j[9] = j[83][j[48]]
                  if (j[9] == nil) then
                    x()
                  end
                  j[25] = (j[25] + (j[9] * j[66]))
                  j[66] = (j[66] * j[60])
                end
                j[53] = j[25]
                j[3] = (j[3] + j[96])
                for x = 1, 4 do
                  j[51][((#j[51]) + 1)] = i((j[25] % j[79]))
                  j[25] = ((j[25] - (j[25] % j[79])) / j[79])
                end
              elseif (j[80] == 3) then
                j[25] = 0
                j[66] = 1
                for w = 1, 4 do
                  j[48] = t(j[54], ((j[3] + w) - 1))
                  if (j[48] == nil) then
                    x()
                  end
                  j[9] = j[83][j[48]]
                  if (j[9] == nil) then
                    x()
                  end
                  j[25] = (j[25] + (j[9] * j[66]))
                  j[66] = (j[66] * j[60])
                end
                j[53] = j[25]
                j[3] = (j[3] + 4)
                for x = 1, 3 do
                  j[51][((#j[51]) + 1)] = i((j[25] % j[79]))
                  j[25] = ((j[25] - (j[25] % j[79])) / j[79])
                end
              elseif (j[80] == 2) then
                j[25] = 0
                j[66] = 1
                for w = 1, 3 do
                  j[48] = t(j[54], ((j[3] + w) - 1))
                  if (j[48] == nil) then
                    x()
                  end
                  j[9] = j[83][j[48]]
                  if (j[9] == nil) then
                    x()
                  end
                  j[25] = (j[25] + (j[9] * j[66]))
                  j[66] = (j[66] * j[60])
                end
                j[53] = j[25]
                j[3] = (j[3] + 3)
                for x = 1, 2 do
                  j[51][((#j[51]) + 1)] = i((j[25] % j[79]))
                  j[25] = ((j[25] - (j[25] % j[79])) / j[79])
                end
              elseif (j[80] == 1) then
                j[25] = 0
                j[66] = 1
                for w = 1, 2 do
                  j[48] = t(j[54], ((j[3] + w) - 1))
                  if (j[48] == nil) then
                    x()
                  end
                  j[9] = j[83][j[48]]
                  if (j[9] == nil) then
                    x()
                  end
                  j[25] = (j[25] + (j[9] * j[66]))
                  j[66] = (j[66] * j[60])
                end
                j[53] = j[25]
                j[3] = (j[3] + 2)
                for x = 1, 1 do
                  j[51][((#j[51]) + 1)] = i((j[25] % j[79]))
                  j[25] = ((j[25] - (j[25] % j[79])) / j[79])
                end
              end
              if (j[3] ~= ((#j[54]) + 1)) then
                x()
              end
              j[20] = 679
            elseif ((j[20] - 679) == 0) then
              local x = k(j[51])
              j = nil
              return x
            elseif (407 == j[20]) then
              j[25] = 0
              j[66] = 1
              for w = 1, 4 do
                j[48] = t(j[54], ((1 + w) - 1))
                if (j[48] == nil) then
                  x()
                end
                j[9] = j[83][j[48]]
                if (j[9] == nil) then
                  x()
                end
                j[25] = (j[25] + (j[9] * j[66]))
                j[66] = (j[66] * j[60])
              end
              j[73] = (j[25] % j[45])
              j[76] = j[73]
              j[53] = j[25]
              j[3] = 5
              j[20] = 507
            else
              x()
            end
          end
        end
        i = (i + 7919)
        t[7667] = function(j, g, z, r, y, e, p, h, o, x, c, b, n, f, w, u, l, qa, q, di, pk, cx)
          if (((#j) < 17) or (q(j, 1) ~= 22501964)) then
            x()
          end
          local t = q(j, 5)
          local i = q(j, 9)
          local a = q(j, 13)
          local s = w(((i + 7) / 8))
          local is = w(((t + 8191) / 8192))
          if (((((t < 1) or (t > 16777216)) or (i < 1)) or (s ~= ((#j) - 16))) or ((#j) >= t)) then
            x()
          end
          local uh = ((((((t * 31) + (is * 13)) + (a * 7)) + (i * 17)) + s) % 4294967296)
          local mp = p(p, e, h, l, x, c, n, f, w, di, pk, cx)
          local k = e(b(j, 17), g, z, r, y, uh, 2, mp, h, x, c, n, f, w, u)
          local m = (((#k) * 8) - i)
          if ((m > 7) or ((m > 0) and (w((c(k, (#k)) / (2 ^ (8 - m)))) ~= 0))) then
            x()
          end
          local d = o(k, i, t)
          if (qa(d, 1, (#d)) ~= a) then
            x()
          end
          return d
        end
        i = (i + 7667)
        sm = t[8255](ERR, strbyte, strchar, tconcat, strsub, debuglib, dbginfo, loadstring)
        t[5850] = function(x, t, i, k, c, m, d, e, q)
          local p = (m and d(e, "s"))
          if (p ~= "[C]") then
            x()
          end
          local j = {}
          j[14] = ("Aa;#*)461K7" .. ("\28j,$8]-r}l9" .. ("0x F@eL`T~E" .. ("!gS%o\30[wp{k" .. ("2VMGynt\31^qW" .. ("uPC+:h=sXv&" .. ("./zd>5QJN<I" .. "m|_BY\29bOZ")))))))
          j[46] = {
            ";beyr}uVBtKV<>/dQwn,+*YqOAJm:/$d$B~Y)xQ*#F~p7!:g_7C<<,[ys5GyO`o8*@pGZCaM8p-@C7.F$QS1 @${O]_,-.\30Z6Os)-!a>w*nh,\31^1%AMqpIL!PZ=O]&T/;-k`FZOM6\31a]{\31x)|*<tt r.\30>v,\29N~rMJ8dkG5%5Lk\29TN\30} \28WeeI1/$C1Z[)jX[BlS)}XN;_8Tr`e^\28:+bVe\0312CAPQB:Khxlq\0319M=B~K^nW.=*gr mhy^4g\29]N+n\0308w\29#wYO`\0290zo>1g%F49a6rdyJ4NKpI^,JG]~G\0300L+57N]>7tv+xbaAMrIWF.s\29- [nkq;TZK#\28Gw}haS:o4$k=Jap17g:`7K}0ekwojKA9<$\0294swoVl[zs27rtez<jE|V1y;|Sl/X#EdYte \30Ad,h+[-}[SjX{m]lIevmB|!/eez6sb.s5[u6B\28 \28Z#y%rM*^8bSn~S6k62p+r5:G@o8\28ellVdwq\29[7Xvl<xM==]eyEv_Cbs\31lC^KXC.9`x=QLQpl*F_!C8>J$je.7CvaA[r4B:\30gvFI]z4:IC:1atLPn!\30/[QV]z%<ET_)!t:W_8eZ\29Gvs4s%\30+~\28mFlvxF@Qh@x%N/$|$&hI]w0_vu7:+TswAdEY-auz^e\29^ay4\31h=Wux\30jP@y-\28zC|]{~Wu48=dvQAF aa\30P{lSsJmu*Vzgd%jKE: Pz)#9#J.og#\28pW1k~+uO[kYxw{8|.pmpy/L@o096d`e|O+{ )w|E~s\31JEn+No*Y~o\29nl02Ab6xqt;wvIud+@,*aq,%yw6w1lotP=j)%q*^b,PSB%FVkrIEy}BBdQdS|E$>@#B0]t\28so,~VlN<Ob%`&4C!+9m-0qYX:4*0YA05;\29p$A!@wGIe7Qq!n7x61,,6%V^7j`v[Kw1KKs&|w2rnm",
            "*6olj=-4#^B%]d4TsCtBg\30Q^ZqyGjV4QKL,l4bWAPM1x]qrE;\28EV\29tO^#{wx$\28o*T@54drB.7G!L[BuN^CwC*ak~<]h`\02878On+EeIa pz<u%~0!}#,<~52$8XeKz>Jo\28eoLxAS~Nn7{C >~\28n-W|><{+#mNO\30,C<_v*d!<kCBvC#87qgP#G+z$4Ny|Y}VxS;_+=TOppSCt> ;)k+m\31TS% Lwy1s}V`p_8}2Euay\0318B\28\30[E`5}9Srpw#\29Gu5\28]%Wk%M;A<&8GtM*6+w:|I\29]Xbu}\29M#yK|%#PTY =6AQZVS5#%nN2%4\30ywZ!#Og{/7]&r>#dzP{rPz2)BAI519`Knzev[S+4NCwF<zb*\28GuF=`mx@2h,[Z-%_[A\0287KJ1<X==M]>@u<xs/Z^[C=og8SmJ[S\28M>M4KM!E4C^)yaZ|#9.5-16wFgtxBke@)^o0Y2jk F=L;=y4T]!4V\28t.g&:dF9:\31Equ)\29}spMF[J6Le/J,F]mVu^}:sd&d*mP-Y{90Qa4N[^_&[MA)}%GL\31rp_&O|\31OEG=OjZ\30F}Bh,ZJ:Vws<&b<u~nea2zr[5PBd=\29aO\28>7YW,xT#NC=^!-,PC&L!X4h;,I..=}Qw~ALumQ5K%Baxdw=A_L@#z.T<7L1rPG\31Y}d/[h.&42W4XkP[09..908rrX:`NZwpyoGsCAJ,jb+Wb] l7;@.Q/1>!mKl:xE0*.4LxLQ~AS9S6Z2_qB#p%<e7X// M.\30J%#-+Q^ 0T\31PAY8ayx~}$-y|.5r$+r>x\28&)Zzhm,vl`:;VT~B>IMVKeo|CVj.2YXq5j72^Ao7w!:g.SCJ*{Q8\0319~0P|F^o:5@;\30Fy6BOa/\30A16_An9[FM5+rvlS}J&G}dd9OPozA7__vjI470Ou`=Gx%q,@u_z:,m<!.$P",
            ")s\28p0/5@ Zh.O!MJx)vWYE<~oMJ>TXI9SCA71dpup8h|,KM\28Q>I7Zpk>)<W4:v/8ud\28lx]#IYWjNBg<Lgxj+dtx>rBAkM1BEW/Llld0,`d8ICOI2xylpV|)p@8lNC649I:\30p.CBE\31vXkKoG\28z!,.a6p@kFPyPNpW;ME..zw6kt}j/yVj)enK%t|Q=;=W\31=!o=:BK#<:8y2jI]tN1YJ\28-,C1bB&\28 Ym%gS4th\28~r\31=gyrE6JeL&b= -vuW#*hL1Qa%~%QuJ8<NBdG]+_#bb;MpPz[\0300+[vmr\30-Wsl*[qy7$%n$;d1p}##hX[.#\28uEK:h,4Vg%=eZ}!4yE{wX]#s;7\30{W@yj}+-J)PFFsB$+}W}/j.GQw<\30bq|ZTqguor\29GZ44e_dnFMqu,uZJY.,>AwajE{|<LLnz\30!:1Ckd/2#`nOJ|x;~XLpJ5Z\28T-YE6;V-[]:BBoWV`}IZK.-2BZTy/Blun,,FE\0296]Y[~k\29+A7[ 6bCQQ2ea+\28Lme\28\28$W 7Y8e~b~jT0k#S+`@Yg_,2,Ku&yy&5-dzW9=%gpCNM\30$Tp^[k^gQtt8|hv z4\31B2{*W/J>%xj:@r^.X>]K$L#/\31Gp=\31V\30p&~zG}<#$}\31>=gmgju7VO%=B|m5\29@KGQwYpO*wjpZ^p/`h2,%z=#:B5n<l,n2G1l$)h=%n6\0317L:>M_6EG\31++K]9-kIO<@o;a@<24r\31<,VdBMa\31GM6dj>AB`<ZJ<Q+:/]A{v*N9)=SXj7g4@Y.\28#S=wM.,Sh~oL\30XFP7^.1WZupJmK\28l)Tw2v4`;2xlKx!\30A6nr)ghla{);!l@pN15g4@/!q>Q:\31l\0311^mX^+I6|%k+&uknC2h}oz}qxA%^gsr}E %@J-E_gulJGn/2}vmkTkIk\30>B+#ho)Zng>\31/[9Q=vh4j!",
            "6ME#b0T*\31pr)W@[Y_>e*,`7[^p<C2=\31W}dw7J8eQY:V`r=ZLKN1=\28oMGrk6\31yKp\30\31y$jl<Wlz[n7k*v/At_1%7{.O8/V74-pq\31v6\31@o\0302Xble;IFMwS/ejpT0*+wXq]7QXLr_s&y7eI[SsO+{ #]L:0K)=+7l-d|A-/T.n@#M\28xkVjd4a9QL*$yCaj1\29:%XLe:xo!O$^wOhW<kmuvo4q/8&$4=}~wa)r$F;#dF*KVIY\30^8Wr1e_ O g=`xvrTw0IB**5T*`ljazB~]T>)0COK\28 nCn\29;m.N;g!/41 .QWp<\29n\29s1o=^9}6n/WP._xb}djb*e0h=`}&#/ZNsEA1nzTI{Yp$s!Y&n@^1:%>SzFsz\28Ct @[=AYzPZeqgrClA.w\03015)yMK>uW6-.pYkxC=Fg=/7hTj)E\28<,l45IS=*\31,5Ll QNZ{^+>Is\31yV\29>\28q`WC\30s\30:L9,`L]aTz=.Z,^2G:K8oBY*\30G=5LlFgvFeY\29}7-J@r-=QOuK+gxqu<WG\28uQ*PJ|9n:jEyZx9sb}+`/WSW\31*1unI&2_4Zqw`I1Vj^5M;KwwE0dS_z dKMwr4[Q2T-N*QZ&d{!gt,7X#-VY`smy%W))F)PZQnV2S$E:\31lybuG+q])a==KYr&u7{m4| 6>J`}7g/wOu@G>KWS,n<L,PkWbN`C`W,J\31xy>gOm#K\0287`kM$Cg&[wxv,G|0\28B{ QgsB/4t\30@\29-[5#O&{XQWqBSGe{n_+VG6u$OeeP-MESd~;]h9\29+OJb6O[<8wy8aC#+dS \31x#arK<#MWG~\31K.8Yhs\30_j#xp;1s}|`NIl>&Gt1 k9VprN`S]okS5MaVNJ&`JY6\29h]VPr:\28o;]2]5/\29=|h59pVG8dYx.BdEToC{Ye\31d \29>h#1u\28/s\30Y|[bZld7]1:I2ym ",
            "K&WT^lqm[J.\29ddj$..j\30Ejv#mhE5gZIqwwBx8d4\30`d8={\29;<d&\29\29zA6:dn7\30hA&9.M0a{NMXdt0FQ5\28],*MNn\28o<z\31Tj>!VK58uKe9w\29, )vb]h{;*IaKhZVh0Kyw;z}[qlh<]sj\0296tF1!\31u18|ht8O{7qdr97_ vy\31V2@o#%FO:OK$IQL[PGl|A 5P%-\30\29L*G1w[>WKN._=j_ZChL{xZ0>{!:boa>)0F98ud$*<1uI0ZV&VS.ZFP-y2APSb~5_<K!zKl8^s{#SB><S$B\0282_\30\29NP=!aePVL]N\29b9>&lz\28~}EBw^>AEh5/s~wQs2xv/oE*gMNG\30yS9KzWbgy)+/dwt\31[A}$u|\30-pu)+\28qGu/hP~|%T;bFs/lZYugyjKX@v;|>;p]brd+An|Ae7e>Y_l+6;X6k2[X{:*2CXn &&T5o1<6S`2J:|u=+P5p\28qk[>E5/VYbW__ul.t7%g{)A6^j#5/5[^&jMm}rKh\31`jNYk\0302/m{ddkXA~]s`CK/BE^mK05/dnK)Ck#jN%,@&,55a+srxZ8<@<&*wK\30YP~O$^2uVm4E%|j}MI^QeQZu$aEb45EbO2,he%;%polQ\02948%>\29%heuZ[:@K:w9g@lLd&l<n1~;jxF|L:6B5\30u]9o\31eLb6<]|pn7bb-;%@X\0317--xx||<:nX0VxEQ&$ub*#WS=ES; *=\30X~[}|C npYWrEG|Mp|Wd,@h^[YG 4yWT;JF&Y@r[ZZ:e~4!F<p\29}b{jtBowIx;2kLd*tN&-By_*|s:NE\30ul_[hl$gn/yMK;27@kb*Q!T5|}1NQT1rTas\0308g\28QSq F./;1+,:&[x^:Nx$7myr2>,ux <d9t82VF8uWI dr@45}TnNE.u7/7\28@<M%/#Ol.6FG-L2BAJ\30LO]JVCxQ 7s:&@2%mV",
            "1u`wsSbMlSB%/@rd~xo5=\31Fra^{z%qEA_`<I`M{jpaj)_-}/V;{8trQz/{X-Es2}:.dST&&<#2MgGX;Q}=\28\28Q8PBN^PLG,prbCA`[/9S0j\31\30>/0bd2mnKZrrPp{W%nIB$/V:}^=w*6py\30d)^FWdE7}-4Jz:*rw`mCM9+~Q<q{&a7,A~|B1&+&o6^\30Qt\31M+X.SSv>=<%z00pW-yIqp>/v}Sh\31s`N{0_WBy-1 JkLo,$1|[Su zl}G\31sgC}tm`z9a-h[<WdgGjK&k#To&Qdg*\28edjyG{4hz01|Q*|W#z\28L%p,jFq%kM1=I\28`M\28\31`CXrn02%Y Z\31v{^_ }^5V\28WQVqKJg$b[JT0mPxwd,|lz=!qFz5.^\31vnkLv1\29d;d$|6`x2&Voa|<)@8:w1Yg*uC158F)\31)Ws[a$98!&n#2-F^e,GFd_x$dYWeJtCFx/2*d rFJLhoh GxP*0vI;L+%x8O:76N:J^0QF@|Bb2hLdTWVP@6N{V!Mk\28Cx8{BJmNd2S,<qo#8;^Mk4!TT+6;*4*~\29\28;:#q={K7M$l[SsBo6tMX7w{9}mI8.=PZx&Atr$_On:#@tzxzYLApl;Knnjm;;d[9KW# |^7X~E\31J-y,m7k_ChC{blq_/4~{I&zohV!s*@!,y_v`Vt@^=a\29\30b2}BnB+4l8o* ,S$*M\28]guG;mz1K^.&8o$l)Z)[4vM@p\28v\29yAhddoNJj4\30p-#se6t^@mInJ2BG]pvKVGX~lI4y!~o,o#A7psIO/%=%uq2Q26-F~,|MaIN4hx`GJxTn6)4eg-^=x]+[u=CKWt),@)]8~/x-A<Q  zm`KWb Z0qA~tu!Bx\31p|[XO+ILCX\30md*h^Ikam1G=1mT=Z,m85mQnga@Cvp9e~[xhJLG{7a==`8o+abBQ4TJ|pq=1",
            "#<kZooQgh/~pY7PY|\29EPu\31s-wI,QvwP$^9ex%y\29<sOATPAh^FKkF<:2x-vPo}8>nSVb\29)l;{z~h^>AeW\30@7`+#1r!Qy=*\30^lSG,b\31\0289:\31ME-\28\28JCjp~6kPbg*\30!d+NQm_[9\28K[ sZ$}]K\28A`MS<^2$KGz[td@j*g\28|n/6G\31_psI=GK@P 4F5q55k*nT$M5NGdOg}>znu;u\0310XN\28uM,wN`!o.yW\28)M#Z<<,7*v$Fo:6E0j]F~W_om9{~t^N{$mS<g6BFgd.[yG-x0A$58AX74\29ETe OLg.E8)}\28Cb}\31!X!kTTgvTWqp*{2Weu2C!N9rVg-o:~=z^$P0&{`E7-\0288&j8NW7b_B*GM}tWESF+Y20\28KAC\30VA%!K*q ]|SKv6e74<dGj\0306L8Xk/.eyoY/9evz6tt/S\31^YSn;.G6W0gWle{jA\31GCnq5/kOlQI9<Q*kl~\30I)/NJ GQ[1&SJ!`g{\31;Y/7%-M+w,&boGg=%a)IN{*j#x#hu\31p2![oCM62pOy\31MNNgy$h\31QG]|ag_7g4y8q<y+mz5jbFnY|VA12ydP{1>$Z]Px)I[IOg~8@stoh-g^@_u_}b SC=6P/A9S#!7TVr`C^gyGhl/IOw1\30JLEJ%)u 7;gjF> 08Z|#FX$B_\29W0o]urF^:u\28<\29\0285.Ft`dW;0s_NP$~n{+NXn|wT atYG\30T,l$.y;S&j|7$kna:FLb`!#Mb)#eIB5*W2aNT8+)[66k$PJ2e=7h\0300}\28%~h!\29)=l*\30qNhPYb`Xe8/6\28G1qB[T5{~s.)Ygz=@eXpv\29>\30w&~$I\0317.EX!1{n$.<%0K2q$E\28-phLMZy<m\28Z5nMW!8~[n=ub4;s^A#h7znea%$T &6G5BI#Nb\28*$C4\29L_j-aa`W6:N  V~/\31gA<Y@yO6n\31O4Be_T_uYJ>",
            "a[aKIK;^d^/5 .0`Trg\30d\30Yta|[Sp&L,-EhIY,q2b\29{8B=}aS2YWO-W wOLEC-9Q-.9`M{5a:GL4o$1<[]xLA<EV}4BQuKj`Z}V59vt$\29k$*X_v.`n-p_>Bk7]!XFwYg8[$^gz9z>Ggv51kZ}k>ro/Go0GJ\30+\28A^F0Yu=a1BsCY1euwZ}\31w8|M<t88B1Z0r]l/!|\30)~P8k])0<w):hh>/jXmnoS^K ]74M<=2^Nbs4nwFrV~A-8q.2x0]ov=1tIb2J[GVVBdGO&sZ6 oGTb7M$`QPsW1h6,{@j/q5qq50vx9+o-A%QVTP\31J*jpzG7).j `Il|XK`dwgO\30s8YOG.~JTI~uA<\0286+!QOb=8*e+\28%Q=,N[y8JC=:Mv`8xnv e>\28h#gd)$g`a}|muB5}[[#{^,Xh$vd8G1CBzn|u7m%^#%wq)OJZrWX,b+suKm:Kw\30)\30EQlTr]q%=Oa5N`{g-#l)\28:\30)mb4wT&F>+$Fm:CIpPoZF7w5}*/Q)jo)nV&v/\28vPM.)I5zKOkl$Q87F\30^Mm>\31JmSKM\30:7PF2Cvq7t+krv[E\30Zr)q|+XJO-hrdx:-^60*F}+q#n+pEC=5\31m\28@ztN ~~qtuF/|5-W~q-I=<^;S\0306y>): vu/Lyp\29@7vOhdPV6Jkq>6urv,-)QV_~d*1))8[oML%eL0[8EM]IC`B5PSrWSTJ5bw!&/M[0{]Mg\30M.L\31^-7A\31!rmMV^z qg)Z je&8N\30]0,wprA[,#Z%:B:\31)1,X,#%ALV[<j4b\30L :)wh\31L@` z,j`d/_K;+m^\29s&B`j$%,<|4Z#&k7<%QdS>eO48kT%jJ72a2:Pl,\31Pp+@zITY7*ehv6.eWjjxsL-Y|V[\30z0Ctv.,Kut/5&.C\29XG\29Bq}V`J6u~n<Nty\0282:vvJx!6|;1k}",
            "4{C\30po$AJBzy9t\28LAyGl@/2bzGE!V*B%MM,gB^7OIz%/=]\31gv) _h_<a>}17ZA~Cj|),M9s *^8gk!Ng=C]2\29FKg.ZB1\28F%:t5eXVzs:rSg=*KF1KhkM\29h\29O:^8\28<2C&,6<9{9ds4QSW49Wu}I4\30$v]J)ZKm1X[7[k+]8|8K{J)t[\29IF8l}9`qdgu!xPld`qr<Ta5!55QL&$x:eY}AIag-2>M{B5=e&>#\28K9627BC[FA!5)|A=7\30S~jajd&[]C9Z*/1`^j;l8 9\30,G-Y\30sm>-F@dwat<lQJ_6ssl!+lruX2V2#1gIz>zS@p-\30Lv,}d{|1a7e\30:y>G*8~kNu]Z\31_r\28d{)t`L\30a Sr -67%JAJAJE*zrs0ZN\31u@xQ$T) 4&%O00}.w->*P]4%>T55[sdn51\31X14EoN\28+))aawC=_:hma#x<`+/[ypCbq<)N<z-Fj$rk[l\28^l\0289q-9:{K7LQP Pa@09`5:8S[TM)LC+Z5urGw=.6\30nC&>ak\30#A\31J#bomW{$Qg!+{\0301a\31#XFTEvS;l7v>@w@k[]FwAk%6dS>,h{8\29xr&)a9J2)o\30#Ev9dm}{+.5g6G#z|} #_Ep4{q*SO&A\29+hL|\29M>.)Z2~\30G#rABNEE.XV*)*:e_oIkn<5g)n$vE[qv=y\31k=mnBqu%q_Y\0288\31K-T_^ \29]T&4>0AJXeBOSFlZO{\30,jz,YE04~xw7ryh)8Jom[bwl<,K\29X1}p 7W<Zmm>7]g&a|C^sV=tot$]~dCr7usE#X !.Q\30:w+k7BkSO~QsXNY_P^\30WT7J2\28\30_\31pq;G\28 1Tkq]uBL*!lIro ,sN{lo=CN9!t;4Ve0IK`]e0=$u\28zZyO^E/g87$y~!NAKh]v{u,1\31bdX5s\29F$x,X@%8{\28u\30S26M%I@y$lnOY|zEb=#\28$:."
          }
          j[6] = 86
          j[71] = 256
          j[41] = 16777216
          j[59] = 0
          j[48] = {}
          j[31] = 0
          j[26] = 1
          for x = 1, (#q) do
            j[59] = (((j[59] + t(q, x)) * j[71]) % j[6])
          end
          j[59] = ((j[59] + (#q)) % j[6])
          j[99] = {}
          for x = 1, (#j[14]) do
            j[99][t(j[14], x)] = (((x - 1) + j[59]) % j[6])
          end
          for w = 1, (#j[46]) do
            j[31] = ((j[99][t(j[46][w], 1)] - j[59]) % j[6])
            if (((j[31] < 1) or (j[31] > (#j[46]))) or j[48][j[31]]) then
              x()
            end
            j[48][j[31]] = c(j[46][w], 2)
          end
          j[95] = k(j[48])
          j[46] = {}
          j[48] = 0
          j[31] = 0
          j[17] = 126
          while true do
            if (j[17] == 546) then
              j[37] = j[48]
              if (j[37] == 4) then
                j[54] = (j[31] % 3)
                j[27] = 5
                if ((j[54] % 2) == 1) then
                  j[27] = 6
                end
                j[84] = 0
                j[15] = 1
                for w = 1, j[27] do
                  j[52] = t(j[95], ((j[26] + w) - 1))
                  if (j[52] == nil) then
                    x()
                  end
                  j[30] = j[99][j[52]]
                  if (j[30] == nil) then
                    x()
                  end
                  j[84] = (j[84] + (j[30] * j[15]))
                  j[15] = (j[15] * j[6])
                end
                j[31] = j[84]
                j[26] = (j[26] + j[27])
                for x = 1, 4 do
                  j[46][((#j[46]) + 1)] = i((j[84] % j[71]))
                  j[84] = ((j[84] - (j[84] % j[71])) / j[71])
                end
              elseif (j[37] == 3) then
                j[84] = 0
                j[15] = 1
                for w = 1, 4 do
                  j[52] = t(j[95], ((j[26] + w) - 1))
                  if (j[52] == nil) then
                    x()
                  end
                  j[30] = j[99][j[52]]
                  if (j[30] == nil) then
                    x()
                  end
                  j[84] = (j[84] + (j[30] * j[15]))
                  j[15] = (j[15] * j[6])
                end
                j[31] = j[84]
                j[26] = (j[26] + 4)
                for x = 1, 3 do
                  j[46][((#j[46]) + 1)] = i((j[84] % j[71]))
                  j[84] = ((j[84] - (j[84] % j[71])) / j[71])
                end
              elseif (j[37] == 2) then
                j[84] = 0
                j[15] = 1
                for w = 1, 3 do
                  j[52] = t(j[95], ((j[26] + w) - 1))
                  if (j[52] == nil) then
                    x()
                  end
                  j[30] = j[99][j[52]]
                  if (j[30] == nil) then
                    x()
                  end
                  j[84] = (j[84] + (j[30] * j[15]))
                  j[15] = (j[15] * j[6])
                end
                j[31] = j[84]
                j[26] = (j[26] + 3)
                for x = 1, 2 do
                  j[46][((#j[46]) + 1)] = i((j[84] % j[71]))
                  j[84] = ((j[84] - (j[84] % j[71])) / j[71])
                end
              elseif (j[37] == 1) then
                j[84] = 0
                j[15] = 1
                for w = 1, 2 do
                  j[52] = t(j[95], ((j[26] + w) - 1))
                  if (j[52] == nil) then
                    x()
                  end
                  j[30] = j[99][j[52]]
                  if (j[30] == nil) then
                    x()
                  end
                  j[84] = (j[84] + (j[30] * j[15]))
                  j[15] = (j[15] * j[6])
                end
                j[31] = j[84]
                j[26] = (j[26] + 2)
                for x = 1, 1 do
                  j[46][((#j[46]) + 1)] = i((j[84] % j[71]))
                  j[84] = ((j[84] - (j[84] % j[71])) / j[71])
                end
              end
              if (j[26] ~= ((#j[95]) + 1)) then
                x()
              end
              j[17] = 583
            elseif (j[17] == 242) then
              if (j[48] > 4) then
                j[54] = (j[31] % 3)
                j[27] = 4
                j[82] = 3
                if (j[54] == 1) then
                  j[27] = 5
                  j[82] = 4
                elseif (j[54] == 2) then
                  j[27] = 6
                  j[82] = 4
                end
                j[84] = 0
                j[15] = 1
                for w = 1, j[27] do
                  j[52] = t(j[95], ((j[26] + w) - 1))
                  if (j[52] == nil) then
                    x()
                  end
                  j[30] = j[99][j[52]]
                  if (j[30] == nil) then
                    x()
                  end
                  j[84] = (j[84] + (j[30] * j[15]))
                  j[15] = (j[15] * j[6])
                end
                j[31] = j[84]
                j[26] = (j[26] + j[27])
                for x = 1, j[82] do
                  j[46][((#j[46]) + 1)] = i((j[84] % j[71]))
                  j[84] = ((j[84] - (j[84] % j[71])) / j[71])
                end
                j[48] = (j[48] - j[82])
              else
                j[17] = 546
              end
            elseif (j[17] == 126) then
              j[84] = 0
              j[15] = 1
              for w = 1, 4 do
                j[52] = t(j[95], ((1 + w) - 1))
                if (j[52] == nil) then
                  x()
                end
                j[30] = j[99][j[52]]
                if (j[30] == nil) then
                  x()
                end
                j[84] = (j[84] + (j[30] * j[15]))
                j[15] = (j[15] * j[6])
              end
              j[59] = (j[84] % j[41])
              j[48] = j[59]
              j[31] = j[84]
              j[26] = 5
              j[17] = 242
            elseif (583 == j[17]) then
              local x = k(j[46])
              j = nil
              return x
            else
              x()
            end
          end
        end
        i = (i + 5850)
        t[9602] = function(t, j)
          local x = function(i, j)
            local x = (((j >= 2147483648) and -1) or 1)
            local t = (t((j / 1048576)) % 2048)
            local w = (((j % 1048576) * w.h) + i)
            if (t == 2047) then
              if (w == 0) then
                return (x / 0)
              else
                return (0 / 0)
              end
            elseif (t == 0) then
              return (x * (w * 5e-324))
            else
              return (x * ((1 + (w / 4503599627370496)) * (2 ^ (t - 1023))))
            end
          end
          local w = function()
            return x(j(), j())
          end
          return x, w
        end
        i = (i + 9602)
        ac = t[7919](ERR, strbyte, strchar, tconcat, strsub, debuglib, dbginfo, loadstring, sm)
        t[9086] = function(j, i, x)
          local q, k, m, t = x(j, 1), x(j, 2), x(j, 3), x(j, 4)
          if (not t) then
            i()
          end
          return ((((((q * w.e) + k) * w.e) + m) * w.e) + t)
        end
        i = (i + 9086)
        t[7240] = function(k, x, g, z, r, y, c, o, d, b, t, q, i, n, u, e, l, p)
          local j = {}
          if ((((t() ~= 79) or ((t() - 66) ~= 0)) or ((70 - t()) ~= 0)) or (not (t() == 2))) then
            x()
          end
          if (not (t() == 117)) then
            x()
          end
          if (((((not (t() == 1)) or ((t() - 1) ~= 0)) or (not (t() == 0))) or ((32 - i()) ~= 0)) or (((#k) - i()) ~= 0)) then
            x()
          end
          j[88] = i()
          j[95] = i()
          j[6] = i()
          if ((((j[88] == 0) or (j[88] > 32767)) or (j[95] ~= 0)) or ((19 - j[6]) ~= 0)) then
            x()
          end
          j[52] = i()
          if ((d(k, 33, (#k)) < j[52]) or (j[52] < d(k, 33, (#k)))) then
            x()
          end
          local h = function()
            j[21] = {g = {}, z = {}}
            j[21].o = i()
            j[21].e = q()
            j[21].t = t()
            j[21].y = t()
            j[11] = q()
            j[21].p = q()
            j[21].q = i()
            j[21].x = i()
            j[39] = i()
            if (((((((((j[21].e < 1) or (j[21].e > w.e)) or (j[21].t > j[21].e)) or (j[21].p > w.e)) or (j[21].x > w.aa)) or (j[21].q < 1)) or (j[21].y > 15)) or (j[39] < 4)) or (j[39] > 16777216)) then
              x()
            end
            j[21].m = ((c((j[21].y / 8)) % 2) == 1)
            if (j[21].m and ((j[6] < 2) or (j[40] == 0))) then
              x()
            end
            if (j[40] == 0) then
              if (((j[21].o ~= 4294967295) or (j[21].p ~= 0)) or ((c((j[21].y / 2)) % 2) ~= 0)) then
                x()
              end
            elseif (j[21].o >= j[40]) then
              x()
            end
            j[78] = (c((j[21].y / 2)) % 2)
            if (((j[78] == 1) and (((j[21].y % 2) == 0) or (j[21].t >= j[21].e))) or (((c((j[21].y / 4)) % 2) == 1) and (j[78] == 0))) then
              x()
            end
            if (j[78] ~= 0) then
              x()
            end
            return j[21], j[39], j[11]
          end
          local f = function()
            local t = j[25][j[40]]
            if (t == nil) then
              t = {}
            end
            for w = 0, (j[21].p - 1) do
              local t = t[w]
              if (not t) then
                x()
              end
              j[51], j[53] = t[1], t[2]
              j[2] = j[26][j[21].o]
              if ((((j[51] > 2) or (not j[2])) or ((j[51] ~= 1) and (j[53] >= j[2].e))) or ((j[51] == 1) and (j[53] >= j[2].p))) then
                x()
              end
              if (j[51] == 2) then
                if ((not j[21].m) or (j[21].d ~= nil)) then
                  x()
                end
                j[21].d = w
              end
              j[21].z[w] = {j[51], j[53]}
            end
          end
          j[26] = {}
          j[24] = 0
          j[40] = 0
          local m = 0
          j[31] = 303
          while true do
            if (not (j[31] ~= 490)) then
              local m = {}
              local i = (j[88] * 2)
              for k = 1, i do
                local f, a, s = q(), q(), q()
                local d = (((k * 1) + 2) % 6)
                local g = ((d - (d % 2)) / 2)
                local z = (d % 2)
                local e = {0, 1, 2}
                local r = {g, z, 0}
                local h = {0, 0, 0}
                for t = 1, 3 do
                  local w = r[t]
                  local j = 0
                  for x = 1, 3 do
                    if (e[x] >= 0) then
                      if (j == w) then
                        h[t] = e[x]
                        e[x] = -1
                        break
                      end
                      j = (j + 1)
                    end
                  end
                end
                local p = {f, a, s}
                local q = {0, 0, 0}
                for j = 1, 3 do
                  q[(h[j] + 1)] = j
                end
                local t = (((p[q[1]] - (k * 53011)) - 34510) % w.aa)
                if (((t < 1) or (t > i)) or m[t]) then
                  x()
                end
                local i = c(((t - 1) / 2))
                local y = ((((p[q[2]] - (t * 53011)) - k) - 34510) % w.aa)
                if (not (y == i)) then
                  x()
                end
                local o = ((t - 1) % 2)
                local j = j[26][i].l
                local b = ((((p[q[3]] - (t * 53011)) - i) - 34510) % w.aa)
                local x = (1 + c((((j[1] - 1) * ((34510 + (i * 53011)) % w.aa)) / w.aa)))
                local w = (((o == 0) and x) or (j[1] - x))
                m[t] = {i, b, n(w)}
              end
              if (e() ~= ((#k) + 1)) then
                x()
              end
              local q = {}
              local t = {}
              for i = 0, (j[88] - 1) do
                local k = j[26][i].l
                local j = (((k[2] - (i * 53011)) - 34510) % w.aa)
                if ((j ~= ((i * 2) + 1)) or t[j]) then
                  x()
                end
                t[j] = 1
                local t = ""
                for k = 1, 2 do
                  local w = m[j]
                  if (((not w) or (w[1] ~= i)) or q[j]) then
                    x()
                  end
                  q[j] = 1
                  t = (t .. w[3])
                  j = w[2]
                end
                if ((j ~= 0) or ((#t) ~= k[1])) then
                  x()
                end
                k[2] = p(t)
                t = nil
              end
              for j = 1, i do
                if (not q[j]) then
                  x()
                end
              end
              k = nil
              break
            elseif (j[31] == 418) then
              for x = 0, (j[88] - 1) do
                j[40] = x
                j[21] = j[26][j[40]]
                f()
              end
              j[31] = 490
            elseif (j[31] == 371) then
              j[25] = {}
              for k = 1, m do
                local f, a, s = q(), q(), q()
                local c = (((k * 1) + 3) % 6)
                local g = ((c - (c % 2)) / 2)
                local z = (c % 2)
                local m = {0, 1, 2}
                local r = {g, z, 0}
                local p = {0, 0, 0}
                for t = 1, 3 do
                  local w = r[t]
                  local j = 0
                  for x = 1, 3 do
                    if (m[x] >= 0) then
                      if (j == w) then
                        p[t] = m[x]
                        m[x] = -1
                        break
                      end
                      j = (j + 1)
                    end
                  end
                end
                local d = {f, a, s}
                local i = {0, 0, 0}
                for j = 1, 3 do
                  i[(p[j] + 1)] = j
                end
                local t = (((d[i[1]] - (k * 17021)) - 8524) % w.aa)
                if (t >= j[88]) then
                  x()
                end
                local q = ((((d[i[2]] - (t * 17021)) - k) - 8524) % w.aa)
                local y = j[26][t]
                if (q >= y.p) then
                  x()
                end
                local h = ((((d[i[3]] - (q * 17021)) - t) - 8524) % w.aa)
                local e = (h % 4)
                local n = ((h - e) / 4)
                if ((e > 2) or (n > 255)) then
                  x()
                end
                local w = j[25][t]
                if (w == nil) then
                  w = {}
                  j[25][t] = w
                end
                if (w[q] ~= nil) then
                  x()
                end
                w[q] = {e, n}
              end
              j[31] = 418
            elseif (303 == j[31]) then
              if (j[40] >= j[88]) then
                j[31] = 371
              else
                j[21], j[39], j[11] = h()
                m = (m + j[21].p)
                j[24] = (((j[24] + j[21].p) + j[21].x) + j[21].q)
                if (j[24] > 1000000) then
                  x()
                end
                j[21].l = {j[39], j[11]}
                j[26][j[40]] = j[21]
                j[40] = (j[40] + 1)
                j[31] = 303
              end
            else
              x()
            end
          end
          local w, a, s = j[26], j[88], j[95]
          j = nil
          return w, a, s
        end
        i = (i + 7240)
        sv = t[5850](ERR, strbyte, strchar, tconcat, strsub, debuglib, dbginfo, loadstring, ac)
        t[9086] = function(j, i, x)
          local q, k, m, t = x(j, 1), x(j, 2), x(j, 3), x(j, 4)
          if (not t) then
            i()
          end
          return (t + ((m + ((k + (q * w.e)) * w.e)) * w.e))
        end
        i = (i + 9086)
        t[1324] = function(j, x)
          if (j ~= 1482183482) then
            x()
          end
        end
        i = (i + 1324)
        t[2902] = function(p, q, m, k, d, x, t, c, f, r, y, o, b, a, s)
          if ((((t ~= 1) and (t ~= 2)) or (x < 0)) or (x >= 4294967296)) then
            r()
          end
          local i = {2131147480, 1736413478, 546846353, 3517700763, 1929416932, 1091648615, 1562964070, 1399841576}
          local h = {
            ((((c + q) + i[1]) % 8589934592) % w.h),
            ((((x + m) + i[2]) % 8589934592) % w.h),
            (((c + i[3]) + k) % w.h),
            ((((i[4] + d) + x) % 8589934592) % w.h),
            ((((q + t) + m) + i[5]) % w.h),
            (((((k + (x * t)) + i[6]) + m) % 8589934592) % w.h),
            (((((i[7] + q) + k) + c) + x) % 4294967296),
            (((((((m + i[8]) + c) + d) + t) + q) + k) % w.h)
          }
          local e = (((t == 1) and 394178989) or 2000074952)
          local n = (((t == 1) and {(((x + 2339963232) % 8589934592) % w.h), ((2588098047 + c) % 4294967296), ((((q + d) + 418558038) + k) % 4294967296)}) or {((3685367549 + x) % 4294967296), ((304088683 + c) % 4294967296), ((((q + 1871031731) + k) + d) % 4294967296)})
          local j = f(h, e, n)
          h = {j[1], j[2], j[3], j[4], j[5], j[6], j[7], j[8]}
          n = {j[9], j[10], j[11]}
          e = (((j[12] + t) + e) % w.h)
          local g = {}
          local z = 0
          for j = 1, (#p), 64 do
            local t = f(h, ((((j - 1) / 64) + e) % 4294967296), n)
            local x = ((#p) - j)
            if (x > 63) then
              x = 63
            end
            for x = 0, x do
              local w = (a((t[(a((x / 4)) + 1)] / (2 ^ (8 * (x % 4))))) % w.e)
              local t = y(p, (j + x))
              g[(j + x)] = o(s(s(t, w), z))
              z = t
            end
          end
          return b(g)
        end
        i = (i + 2902)
        local strbyte = t[9086](sm, ERR, strbyte)
        t[7869] = function(t, i, w)
          local j = function(q, k)
            local j = 0
            local x = function(x)
              if (j > (k - x)) then
                t()
              end
              local t = 0
              for x = 0, (x - 1) do
                local j = (j + x)
                t = (t + ((w((i(q, (w((j / 8)) + 1)) / (2 ^ (j % 8)))) % 2) * (2 ^ x)))
              end
              j = (j + x)
              return t
            end
            return x, function()
              return j
            end
          end
          return j
        end
        i = (i + 7869)
        t[7015] = function(h, n, e, p, c, i, f, a, s, x, t, g)
          local m = (x and t(g, "s"))
          local d = (x and t(i, "s"))
          local k = (x and t(h, "s"))
          local z = (x and t(n, "s"))
          local r = (x and t(e, "s"))
          local y = (x and t(p, "s"))
          if ((((((m ~= "[C]") or (d ~= "[C]")) or (k ~= z)) or (k ~= r)) or (k ~= y)) or (k == "[C]")) then
            c()
          end
          if ((((((i("AZ", 1) ~= 65) or (i("AZ", 2) ~= 90)) or (f(65) ~= "A")) or (a({"A", "B"}) ~= "AB")) or (s(3.75) ~= 3)) or (p(90, 165) ~= 255)) then
            c()
          end
          local j = e({0, 0, 0, 0, 0, 0, 0, 0}, 0, {0, 0, 0})
          if (((j[1] ~= 804192318) or (j[8] ~= 505049583)) or (j[16] ~= 1123945486)) then
            c()
          end
          local q = 0
          for j = 1, (#m) do
            q = (((i(m, j) + (q * 257)) % 8589934592) % w.h)
          end
          for j = 1, (#d) do
            q = (((q * 257) + i(d, j)) % 4294967296)
          end
          return (((((q + 255) + 505049583) + 804192318) + 1123945486) % w.h)
        end
        i = (i + 7015)
        t[1324](strbyte, ERR)
        q = ((true and function()
          local t = {[69] = buf_create(5), [64] = buf_create(7), [41] = (bxor(i, q) % w.h)}
          t[52] = band(bxor(t[41], lrotate(t[41], 11)), 255)
          buf_writeu8(t[69], 2, bxor(0, t[52]))
          buf_writeu8(t[69], 3, bxor(0, t[52]))
          buf_writeu8(t[69], 1, bxor(108, t[52]))
          buf_writeu8(t[69], 4, bxor(1, t[52]))
          if ((bxor(i, q) % w.h) ~= t[41]) then
            ERR()
          end
          buf_writeu8(t[64], 6, bxor(buf_readu8(t[69], 2), t[52]))
          buf_writeu8(t[64], 3, bxor(buf_readu8(t[69], 1), t[52]))
          buf_writeu8(t[64], 4, bxor(buf_readu8(t[69], 4), t[52]))
          buf_writeu8(t[64], 5, bxor(buf_readu8(t[69], 3), t[52]))
          t[46] = bor(buf_readu16(t[64], 3), lshift(buf_readu16(t[64], 5), 16))
          t[42] = band(bxor(t[41], lrotate(t[41], 17)), 255)
          buf_writeu8(t[69], 4, bxor(t[42], 1))
          buf_writeu8(t[64], 4, bxor(t[42], 3))
          buf_writeu8(t[69], 1, bxor(t[42], 0))
          buf_writeu8(t[64], 3, bxor(t[42], 4))
          buf_writeu8(t[69], 3, bxor(t[42], 2))
          buf_writeu8(t[64], 5, bxor(t[42], 2))
          buf_writeu8(t[69], 2, bxor(t[42], 3))
          buf_writeu8(t[64], 6, bxor(t[42], 1))
          t[69] = nil
          t[64] = nil
          if ((bxor(i, q) % w.h) ~= t[41]) then
            ERR()
          end
          return t[46]
        end()) or 364)
      elseif (q == 455) then
        op.h = (((mp + le) + qt) % 65520)
        local strbyte = t[572](ERR, function(j, x)
          return buf_readu8(j, (x - 1))
        end)
        local loadstring = t[7315](ERR, buf_create, buf_writeu8, buf_readu8, buf_readu16, buf_readu32, buf_readi32, buf_readf64, bxor, band, bor, lrotate, lshift, i)
        wo, kl, yr, mj = t[901](op, ns, function(j, x)
          return buf_readu8(j, (x - 1))
        end, ERR, strbyte, loadstring, nextf, strsub, strchar, tconcat, int_fromstring, fmt, function(j, x)
          return buf_readu32(j, (x - 1))
        end, decstr, f64le, ia, buf_len, typeof)
        oc, rx, dk = t[9088](typeof, ERR)
        q = ((true and function()
          local t = {[54] = buf_create(8), [70] = buf_create(5), [69] = (bxor(i, q) % w.h)}
          t[44] = band(bxor(t[69], lrotate(t[69], 19)), 255)
          buf_writeu8(t[54], 6, bxor(3, t[44]))
          buf_writeu8(t[54], 7, bxor(0, t[44]))
          buf_writeu8(t[54], 5, bxor(139, t[44]))
          buf_writeu8(t[54], 4, bxor(0, t[44]))
          if ((bxor(i, q) % w.h) ~= t[69]) then
            ERR()
          end
          buf_writeu8(t[70], 1, bxor(buf_readu8(t[54], 5), t[44]))
          buf_writeu8(t[70], 3, bxor(buf_readu8(t[54], 7), t[44]))
          buf_writeu8(t[70], 4, bxor(buf_readu8(t[54], 4), t[44]))
          buf_writeu8(t[70], 2, bxor(buf_readu8(t[54], 6), t[44]))
          t[87] = buf_readi32(t[70], 1)
          t[64] = band(bxor(t[69], lrotate(t[69], 9)), 255)
          buf_writeu8(t[54], 4, bxor(t[64], 3))
          buf_writeu8(t[70], 4, bxor(t[64], 1))
          buf_writeu8(t[54], 5, bxor(t[64], 0))
          buf_writeu8(t[70], 1, bxor(t[64], 4))
          buf_writeu8(t[54], 6, bxor(t[64], 1))
          buf_writeu8(t[70], 2, bxor(t[64], 3))
          buf_writeu8(t[54], 7, bxor(t[64], 2))
          buf_writeu8(t[70], 3, bxor(t[64], 2))
          t[54] = nil
          t[70] = nil
          if ((bxor(i, q) % w.h) ~= t[69]) then
            ERR()
          end
          return t[87]
        end()) or 907)
      elseif (364 == q) then
        t[102] = function(x, s, g, i, t, q, j, k, c, m, d, e, p, z, r)
          local w = d(w.e)
          for j = 0, 255 do
            e(w, j, i(x((j / 16)), (j % 16)))
          end
          local h = function(i, q)
            local t = 0
            local j = 1
            for k = 0, 7 do
              local i = (x((i / j)) % 16)
              local x = (x((q / j)) % 16)
              t = (t + (p(w, ((i * 16) + x)) * j))
              j = (j * 16)
            end
            return t
          end
          local n = function(x, w)
            return t(q(x, w), j(t(x, w)))
          end
          local f = function(j, x)
            return k(j, x)
          end
          local a = function(w, x)
            return j(t(j(c(w, x)), j(m(w, (32 - x)))))
          end
          return h, n, f, a
        end
        i = (i + 102)
        t[3572] = function(d, k, c, m)
          return function(j, t, i, q, x)
            j[t] = ((j[t] + j[i]) % w.h)
            j[x] = m(k(j[x], j[t]), 16)
            j[q] = ((j[x] + j[q]) % w.h)
            j[i] = c(d(j[i], j[q]), 12)
            j[t] = ((j[i] + j[t]) % w.h)
            j[x] = c(k(j[x], j[t]), 8)
            j[q] = (((j[x] + j[q]) % 8589934592) % w.h)
            j[i] = m(k(j[i], j[q]), 7)
          end
        end
        i = (i + 3572)
        t[8687] = function(t, w)
          local j = {}
          j[51] = {}
          j[32] = "\127?VS@q<"
          for x = 1, 6 do
            j[21] = w(j[32], (x + 1))
            if (((j[21] == 92) or (j[21] < 35)) or (j[21] > 121)) then
              t()
            end
            if (j[21] > 92) then
              j[21] = (j[21] - 1)
            end
            j[51][x] = (j[21] - 35)
          end
          local x = (1 + (((((j[51][1] + (j[51][2] * 87)) * 31) + ((j[51][3] + (j[51][4] * 87)) * 7)) + (j[51][5] + (j[51][6] * 87))) % 2147483646))
          j = nil
          return x
        end
        i = (i + 8687)
        t[615] = function(t)
          return function(i, x, q)
            local w = {1634760805, 857760878, 2036477234, 1797285236, i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], x, q[1], q[2], q[3]}
            local j = {}
            for x = 1, 16 do
              j[x] = w[x]
            end
            for x = 1, 4 do
              t(j, 1, 5, 9, 13)
              t(j, 2, 6, 10, 14)
              t(j, 3, 7, 11, 15)
              t(j, 4, 8, 12, 16)
              t(j, 1, 6, 11, 16)
              t(j, 2, 7, 12, 13)
              t(j, 3, 8, 9, 14)
              t(j, 4, 5, 10, 15)
            end
            for x = 1, 16 do
              j[x] = (((w[x] + j[x]) % 8589934592) % 4294967296)
            end
            return j
          end
        end
        i = (i + 615)
        ia = function(n, z, g, qa, di, f)
          local y = (buf_len(n) - 4)
          if (y < 0) then
            ERR()
          end
          local a = buf_readu32(n, y)
          if ((a < 0) or (a > y)) then
            ERR()
          end
          local pk, x, i, e, p, t, h, q, d, s = (y - a), 0, 0, 0, 0, 0, 0, 0, 0, nil
          local o = (qa ~= nil)
          if o then
            if ((((z % 1) ~= 0) or (z < 0)) or (z > w.aa)) then
              ERR()
            end
          else
            if ((((g % 1) ~= 0) or (g < 0)) or (g >= z)) then
              ERR()
            end
          end
          if (not o) then
            if (f == nil) then
              x, i, d = 0, 0, 0
            else
              x, i, d = f[1], f[2], f[3]
              if (f[4] ~= n) then
                x, i, d = 0, 0, 0
                f[4] = n
              end
              if (d > g) then
                x, i, d = 0, 0, 0
              end
            end
          end
          local j = 142
          while true do
            if ((j - 510) == 0) then
              x = (((x + h) - e) + t)
              local x = (((i + (t * 257)) + 54108) % w.h)
              if o then
                qa[d] = e
                di[d] = p
                d = (d + 1)
                i = x
                j = 142
              elseif (d < g) then
                d = (d + 1)
                i = x
                j = 142
              else
                j = 599
              end
            elseif (not (j ~= 142)) then
              if (x >= a) then
                if o then
                  return x, d
                else
                  ERR()
                end
              end
              e = (pk + x)
              p = buf_readu8(n, e)
              if (p == nil) then
                ERR()
              end
              j = 493
            elseif (j == 599) then
              if (((q % 3) - 0) == 0) then
                if (0 == q) then
                  s = nil
                  j = 968
                elseif ((q - 3) == 0) then
                  local x = decstr(n, (h + 1), t, i)
                  s = x
                  j = 968
                else
                  ERR()
                end
              elseif (1 == (q % 3)) then
                if ((q - 0x1) == 0) then
                  local x = strbyte(decstr(n, (h + 1), 1, i), 1)
                  if ((x ~= 0) and (x ~= 1)) then
                    ERR()
                  end
                  s = (x == 1)
                  j = 968
                elseif (not (q ~= 4)) then
                  local x = decstr(n, (h + 1), 8, i)
                  local t = int_fromstring(fmt("%08x%08x", u32le_str2(x, 5), u32le_str2(x, 1)), 16)
                  if (t == nil) then
                    ERR()
                  end
                  s = t
                  j = 968
                else
                  ERR()
                end
              elseif (((q % 3) - 2) == 0) then
                if ((q - 2) == 0) then
                  local x = f64le(decstr(n, (h + 1), 8, i), 1)
                  s = x
                  j = 968
                else
                  ERR()
                end
              else
                ERR()
              end
            elseif (not (j ~= 493)) then
              if (((p % 3) - 0) == 0) then
                if ((p - 0) == 0) then
                  h = (e + 1)
                  t = 0
                  q = 0
                elseif (not (p ~= 0x3)) then
                  t = buf_readu32(n, (e + 1))
                  if ((t < 0) or (((x + t) + 5) > a)) then
                    ERR()
                  end
                  h = (e + 5)
                  q = 3
                else
                  ERR()
                end
              elseif (1 == (p % 3)) then
                if ((p - 1) == 0) then
                  h = (e + 1)
                  t = 1
                  q = 1
                elseif (not (p ~= 4)) then
                  h = (e + 1)
                  t = 8
                  q = 4
                else
                  ERR()
                end
              elseif (not ((p % 3) ~= 2)) then
                if ((p - 0x2) == 0) then
                  h = (e + 1)
                  t = 8
                  q = 2
                elseif (not (p ~= 0x5)) then
                  t = buf_readu32(n, (e + 1))
                  if ((t < 0) or (((x + t) + 5) > a)) then
                    ERR()
                  end
                  h = (e + 5)
                  q = 3
                else
                  ERR()
                end
              else
                ERR()
              end
              j = 510
            elseif (968 == j) then
              x = (((x + h) - e) + t)
              i = (((i + (t * 257)) + 54108) % w.h)
              if (f ~= nil) then
                f[1], f[2], f[3] = x, i, (d + 1)
              end
              return s
            else
              ERR()
            end
          end
        end
        ii = t[8687](ERR, strbyte)
        local LIBSTR, buf_readu16, nextf, buf_readf64 = t[102](floor, XOR2, XOR, bxor, band, bor, bnot, lrotate, lshift, rshift, buf_create, buf_writeu8, buf_readu8, buf_fromstring, buf_readu32)
        local buf_len = t[3572](LIBSTR, buf_readu16, nextf, buf_readf64)
        local buf_readu32 = t[615](buf_len)
        local decstr = t[2902]
        local typeof = t[7015]
        local sm = t[5189](strsub((sm .. (ac .. sv)), 5), mp, le, qt, ii, decstr, typeof, buf_readu32, ERR, strbyte, strsub, strchar, tconcat, floor, XOR2, XOR, adler32, u32le_str, debuglib, dbginfo, loadstring)
        local bnot = t[7869](ERR, strbyte, floor)
        local packN = t[6142](ERR, strbyte, strchar, tconcat, floor, bnot)
        local loadstring = t[7667](sm, mp, le, qt, ii, decstr, typeof, buf_readu32, packN, ERR, strbyte, strsub, strchar, tconcat, floor, XOR2, XOR, adler32, u32le_str, debuglib, dbginfo, loadstring)
        local dbginfo, XOR, debuglib, XOR2, mp, le = t[3227](loadstring, ERR, strbyte, strsub)
        local u32le_str, qt = t[9602](floor, debuglib)
        op, ns, nr = t[7240](loadstring, ERR, strbyte, fmt, strchar, tconcat, floor, int_fromstring, adler32, strsub, dbginfo, XOR, debuglib, XOR2, mp, le, qt, buf_fromstring)
        q = ((true and function()
          local t = {[55] = buf_create(5), [74] = buf_create(5), [67] = (bxor(i, q) % w.h)}
          t[49] = band(bxor(t[67], lrotate(t[67], 8)), 255)
          buf_writeu8(t[55], 3, bxor(0, t[49]))
          buf_writeu8(t[55], 2, bxor(1, t[49]))
          buf_writeu8(t[55], 1, bxor(199, t[49]))
          buf_writeu8(t[55], 4, bxor(0, t[49]))
          if ((bxor(i, q) % w.h) ~= t[67]) then
            ERR()
          end
          buf_writeu8(t[74], 1, bxor(buf_readu8(t[55], 1), t[49]))
          buf_writeu8(t[74], 3, bxor(buf_readu8(t[55], 3), t[49]))
          buf_writeu8(t[74], 4, bxor(buf_readu8(t[55], 4), t[49]))
          buf_writeu8(t[74], 2, bxor(buf_readu8(t[55], 2), t[49]))
          t[48] = bor(bor(buf_readu8(t[74], 1), lshift(buf_readu8(t[74], 2), 8)), bor(lshift(buf_readu8(t[74], 3), 16), lshift(buf_readu8(t[74], 4), 24)))
          t[84] = band(bxor(t[67], lrotate(t[67], 26)), 255)
          buf_writeu8(t[55], 3, bxor(t[84], 2))
          buf_writeu8(t[74], 3, bxor(t[84], 2))
          buf_writeu8(t[55], 4, bxor(t[84], 3))
          buf_writeu8(t[74], 4, bxor(t[84], 1))
          buf_writeu8(t[55], 1, bxor(t[84], 0))
          buf_writeu8(t[74], 1, bxor(t[84], 4))
          buf_writeu8(t[55], 2, bxor(t[84], 1))
          buf_writeu8(t[74], 2, bxor(t[84], 3))
          t[55] = nil
          t[74] = nil
          if ((bxor(i, q) % w.h) ~= t[67]) then
            ERR()
          end
          return t[48]
        end()) or 455)
      elseif (q == 110) then
        t[9080] = function(i, x, t, q, k, c, m)
          local w = (q and k(c, "s"))
          w = (w .. m)
          local j = (((x * 37) + t) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          j = ((16807 * j) % 2147483647)
          x = 0
          t = 1
          while (t <= (#w)) do
            x = (((x + (x * 256)) + i(w, t)) % 2147483647)
            t = (t + 1)
          end
          return (1 + ((j + (x * 37)) % 2147483646))
        end
        i = (i + 9080)
        t[5189] = function(j, d, e, p, h, a, s, g, x, i, u, z, r, y, l, qa, sm, q, di, pk, cx)
          local is = s(s, a, g, qa, x, i, z, r, y, di, pk, cx)
          j = a(j, d, e, p, h, (#j), 1, is, g, x, i, z, r, y, l)
          if ((((#j) < 16) or (((#j) % 4) ~= 0)) or ((#j) > 16777232)) then
            x()
          end
          local k = (1 + (((((((d * 19) + (e * 11)) + (p * 7)) + (h * 39)) + ((#j) * 47)) + 1965860233) % 2147483646))
          local c = (1 + (((((((d * 41) + (e * 57)) + (p * 41)) + (h * 3)) + ((#j) * 11)) + 116499707) % 2147483646))
          local uh = (4098 + ((((k + c) + 48042) % w.aa) * w.aa))
          local n = q(j, 1)
          local t = q(j, 5)
          local o = q(j, 9)
          local mp = q(j, 13)
          local b = ((4 - ((16 + t) % 4)) % 4)
          if (((t > 16777216) or ((#j) ~= ((16 + t) + b))) or (n ~= uh)) then
            x()
          end
          local le = (((((t + 624818895) + ((k % w.aa) * w.aa)) + ((c % w.aa) * 17)) + (n * 257)) % w.h)
          if (not (o == le)) then
            x()
          end
          local m = ((k + 1620916158) % w.ab)
          local f = ((c + 624818895) % w.ab)
          for x = 17, (16 + t) do
            local j = i(j, x)
            m = (((m * 257) + j) % w.ab)
            f = ((((f * 263) + j) + m) % w.ab)
          end
          local qt = (((((n * 31) + m) + (f * w.ab)) + (o * 17)) % 4294967296)
          if (not (mp == qt)) then
            x()
          end
          for q = 1, b do
            if (i(j, ((16 + t) + q)) ~= (((k + (c * q)) + 23394) % w.e)) then
              x()
            end
          end
          j = u(j, 17, (16 + t))
          return j
        end
        i = (i + 5189)
        t[7315] = function(d, n, i, e, g, j, b, u, x, f, r, a, y, h)
          return function(j, k, c, m, z, s, qa, t, o, l)
            local p = function(x, j, t, w)
              return (((x < j.e) and (t < j.e)) and (w < j.e))
            end
            local q = {}
            q[41] = false
            if (((j % (((not false) and function()
              local t = {[95] = n(6), [88] = n(8), [77] = (x(h, j) % w.h)}
              t[75] = f(x(t[77], a(t[77], 24)), 255)
              i(t[95], 2, x(0, t[75]))
              i(t[95], 3, x(0, t[75]))
              i(t[95], 4, x(0, t[75]))
              i(t[95], 5, x(2, t[75]))
              if ((x(h, j) % w.h) ~= t[77]) then
                d()
              end
              i(t[88], 6, x(e(t[95], 2), t[75]))
              i(t[88], 4, x(e(t[95], 5), t[75]))
              i(t[88], 5, x(e(t[95], 4), t[75]))
              i(t[88], 7, x(e(t[95], 3), t[75]))
              t[52] = b(t[88], 4)
              t[81] = f(x(t[77], a(t[77], 2)), 255)
              i(t[95], 2, x(t[81], 2))
              i(t[88], 6, x(t[81], 2))
              i(t[95], 3, x(t[81], 3))
              i(t[88], 7, x(t[81], 1))
              i(t[95], 4, x(t[81], 1))
              i(t[88], 5, x(t[81], 3))
              i(t[95], 5, x(t[81], 0))
              i(t[88], 4, x(t[81], 4))
              t[95] = nil
              t[88] = nil
              if ((x(h, j) % w.h) ~= t[77]) then
                d()
              end
              return t[52]
            end()) or 2)) - ((true and function()
              local t = {[81] = n(12), [67] = n(10), [92] = (x(h, j) % w.h)}
              t[79] = f(x(t[92], a(t[92], 1)), 255)
              i(t[81], 5, x(0, t[79]))
              i(t[81], 10, x(0, t[79]))
              i(t[81], 9, x(0, t[79]))
              i(t[81], 7, x(0, t[79]))
              i(t[81], 11, x(0, t[79]))
              i(t[81], 4, x(0, t[79]))
              i(t[81], 6, x(0, t[79]))
              i(t[81], 8, x(0, t[79]))
              if ((x(h, j) % w.h) ~= t[92]) then
                d()
              end
              i(t[67], 4, x(e(t[81], 7), t[79]))
              i(t[67], 6, x(e(t[81], 8), t[79]))
              i(t[67], 7, x(e(t[81], 6), t[79]))
              i(t[67], 3, x(e(t[81], 4), t[79]))
              i(t[67], 2, x(e(t[81], 5), t[79]))
              i(t[67], 5, x(e(t[81], 10), t[79]))
              i(t[67], 9, x(e(t[81], 9), t[79]))
              i(t[67], 8, x(e(t[81], 11), t[79]))
              t[89] = u(t[67], 2)
              t[99] = f(x(t[92], a(t[92], 2)), 255)
              i(t[81], 4, x(t[99], 1))
              i(t[67], 3, x(t[99], 7))
              i(t[81], 6, x(t[99], 5))
              i(t[67], 7, x(t[99], 3))
              i(t[81], 8, x(t[99], 4))
              i(t[67], 6, x(t[99], 4))
              i(t[81], 5, x(t[99], 0))
              i(t[67], 2, x(t[99], 8))
              i(t[81], 9, x(t[99], 7))
              i(t[67], 9, x(t[99], 1))
              i(t[81], 11, x(t[99], 6))
              i(t[67], 8, x(t[99], 2))
              i(t[81], 7, x(t[99], 2))
              i(t[67], 4, x(t[99], 6))
              i(t[81], 10, x(t[99], 3))
              i(t[67], 5, x(t[99], 5))
              t[81] = nil
              t[67] = nil
              if ((x(h, j) % w.h) ~= t[92]) then
                d()
              end
              return t[89]
            end()) or 0)) == 0) then
              if (j >= 182) then
                if (220 > j) then
                  if (j >= 190) then
                    if (j < 216) then
                      if (not (j ~= 190)) then
                        q[41] = p(k, t, c, m)
                      else
                        d()
                      end
                    else
                      if ((j - 216) == 0) then
                        q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                      elseif (218 == j) then
                        q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                      else
                        d()
                      end
                    end
                  else
                    if ((j - 182) == 0) then
                      q[41] = p(k, t, c, m)
                    else
                      d()
                    end
                  end
                else
                  if ((228 - j) > 0) then
                    if ((j - 220) == 0) then
                      q[41] = (((k < t.e) and (o[s] ~= nil)) and (o[s].o == l))
                    elseif (222 == j) then
                      q[41] = p(k, t, c, m)
                    else
                      d()
                    end
                  else
                    if (j >= 252) then
                      if (252 == j) then
                        q[41] = p(k, t, c, m)
                      elseif (not (j ~= 254)) then
                        q[41] = p(k, t, c, m)
                      else
                        d()
                      end
                    else
                      if ((j - 230) >= 0) then
                        if (230 == j) then
                          q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                        elseif ((j - 234) == 0) then
                          q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                        else
                          d()
                        end
                      else
                        if (228 == j) then
                          q[41] = ((k < t.e) and (s < t.x))
                        else
                          d()
                        end
                      end
                    end
                  end
                end
              else
                if (not (j < 134)) then
                  if (j >= 140) then
                    if (not (j < 172)) then
                      if ((j - 172) == 0) then
                        q[41] = p(k, t, c, m)
                      elseif ((j - 180) == 0) then
                        q[41] = (((k < t.e) and (c < t.e)) and (m > 0))
                      else
                        d()
                      end
                    else
                      if (140 == j) then
                        q[41] = p(k, t, c, m)
                      elseif (158 == j) then
                        q[41] = p(k, t, c, m)
                      else
                        d()
                      end
                    end
                  else
                    if ((j - 134) == 0) then
                      q[41] = ((k < t.e) and ((t.g[s] == 3) or (t.g[s] == 5)))
                    else
                      d()
                    end
                  end
                else
                  if (not (j < 34)) then
                    if ((j - 128) >= 0) then
                      if ((j - 128) == 0) then
                        q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                      else
                        d()
                      end
                    else
                      if (not (j < 78)) then
                        if (j == 78) then
                          q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                        elseif ((j - 98) == 0) then
                          q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                        else
                          d()
                        end
                      else
                        if (not (j < 70)) then
                          if (j >= 76) then
                            if ((j - 76) == 0) then
                              q[41] = ((((k + 2) < t.e) and (c == 0)) and (m == 0))
                            else
                              d()
                            end
                          else
                            if (j == 70) then
                              q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                            elseif (j == 72) then
                              q[41] = (((k <= c) and (c < t.e)) and (m == 0))
                            else
                              d()
                            end
                          end
                        else
                          if ((j - 54) >= 0) then
                            if (j == 54) then
                              q[41] = ((((k < t.e) and (c == 0)) and (m == 0)) and ((t.y % 2) == 1))
                            else
                              d()
                            end
                          else
                            if ((j - 34) == 0) then
                              q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                            elseif ((j - 46) == 0) then
                              q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                            else
                              d()
                            end
                          end
                        end
                      end
                    end
                  else
                    if (not (j ~= 30)) then
                      q[41] = p(k, t, c, m)
                    elseif (32 == j) then
                      q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                    else
                      d()
                    end
                  end
                end
              end
            elseif (((true and function()
              local t = {[43] = n(6), [47] = n(7), [90] = (x(h, j) % w.h)}
              t[41] = f(x(t[90], a(t[90], 30)), 255)
              i(t[43], 2, x(0, t[41]))
              i(t[43], 4, x(0, t[41]))
              i(t[43], 5, x(1, t[41]))
              i(t[43], 3, x(0, t[41]))
              if ((x(h, j) % w.h) ~= t[90]) then
                d()
              end
              i(t[47], 4, x(e(t[43], 3), t[41]))
              i(t[47], 3, x(e(t[43], 5), t[41]))
              i(t[47], 6, x(e(t[43], 4), t[41]))
              i(t[47], 5, x(e(t[43], 2), t[41]))
              t[87] = r(g(t[47], 3), y(g(t[47], 5), 16))
              t[76] = f(x(t[90], a(t[90], 6)), 255)
              i(t[43], 3, x(t[76], 1))
              i(t[47], 4, x(t[76], 3))
              i(t[43], 4, x(t[76], 3))
              i(t[47], 6, x(t[76], 1))
              i(t[43], 5, x(t[76], 0))
              i(t[47], 3, x(t[76], 4))
              i(t[43], 2, x(t[76], 2))
              i(t[47], 5, x(t[76], 2))
              t[43] = nil
              t[47] = nil
              if ((x(h, j) % w.h) ~= t[90]) then
                d()
              end
              return t[87]
            end()) or 1) == (j % ((true and function()
              local t = {[60] = n(8), [98] = n(8), [68] = (x(h, j) % w.h)}
              t[41] = f(x(t[68], a(t[68], 26)), 255)
              i(t[60], 6, x(2, t[41]))
              i(t[60], 7, x(0, t[41]))
              i(t[60], 5, x(0, t[41]))
              i(t[60], 4, x(0, t[41]))
              if ((x(h, j) % w.h) ~= t[68]) then
                d()
              end
              i(t[98], 6, x(e(t[60], 7), t[41]))
              i(t[98], 7, x(e(t[60], 5), t[41]))
              i(t[98], 4, x(e(t[60], 6), t[41]))
              i(t[98], 5, x(e(t[60], 4), t[41]))
              t[94] = r(g(t[98], 4), y(g(t[98], 6), 16))
              t[92] = f(x(t[68], a(t[68], 19)), 255)
              i(t[60], 7, x(t[92], 2))
              i(t[98], 6, x(t[92], 2))
              i(t[60], 4, x(t[92], 1))
              i(t[98], 5, x(t[92], 3))
              i(t[60], 6, x(t[92], 0))
              i(t[98], 4, x(t[92], 4))
              i(t[60], 5, x(t[92], 3))
              i(t[98], 7, x(t[92], 1))
              t[60] = nil
              t[98] = nil
              if ((x(h, j) % w.h) ~= t[68]) then
                d()
              end
              return t[94]
            end()) or 2))) then
              if ((j - 213) >= 0) then
                if ((j - 249) < 0) then
                  if (not (j < 225)) then
                    if (not (j ~= 225)) then
                      q[41] = p(k, t, c, m)
                    elseif (j == 243) then
                      q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                    else
                      d()
                    end
                  else
                    if ((j - 213) == 0) then
                      q[41] = (((k < t.e) and (c < t.p)) and (m == 0))
                    elseif (j == 221) then
                      q[41] = p(k, t, c, m)
                    else
                      d()
                    end
                  end
                else
                  if (not (j ~= 249)) then
                    q[41] = ((((k + 2) < t.e) and (c == 0)) and (m == 0))
                  elseif ((j - 255) == 0) then
                    q[41] = p(k, t, c, m)
                  else
                    d()
                  end
                end
              else
                if (not (j >= 149)) then
                  if ((j - 147) >= 0) then
                    if (not (j ~= 147)) then
                      q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                    else
                      d()
                    end
                  else
                    if ((j - 65) >= 0) then
                      if (not (j >= 137)) then
                        if (j < 105) then
                          if ((j - 65) == 0) then
                            q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                          elseif (67 == j) then
                            q[41] = (((k < t.e) and ((c + 2) < t.e)) and (m == 0))
                          else
                            d()
                          end
                        else
                          if (j == 105) then
                            q[41] = (m < w.e)
                          elseif (119 == j) then
                            q[41] = p(k, t, c, m)
                          else
                            d()
                          end
                        end
                      else
                        if (j == 137) then
                          q[41] = p(k, t, c, m)
                        elseif (141 == j) then
                          q[41] = p(k, t, c, m)
                        else
                          d()
                        end
                      end
                    else
                      if (45 <= j) then
                        if (j >= 47) then
                          if (not (j ~= 47)) then
                            q[41] = ((k < t.e) and ((t.g[s] == 3) or (t.g[s] == 5)))
                          elseif ((j - 53) == 0) then
                            q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                          else
                            d()
                          end
                        else
                          if ((j - 45) == 0) then
                            q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                          else
                            d()
                          end
                        end
                      else
                        if (j >= 43) then
                          if (j == 43) then
                            q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                          else
                            d()
                          end
                        else
                          if (29 > j) then
                            if (j == 15) then
                              q[41] = ((z % 2) == 0)
                            else
                              d()
                            end
                          else
                            if (29 == j) then
                              q[41] = (((k < t.e) and (c == 0)) and (m == 0))
                            elseif (j == 35) then
                              q[41] = p(k, t, c, m)
                            else
                              d()
                            end
                          end
                        end
                      end
                    end
                  end
                else
                  if (j < 173) then
                    if (j == 149) then
                      q[41] = ((z > 0) and (z <= 65535))
                    elseif ((j - 169) == 0) then
                      q[41] = p(k, t, c, m)
                    else
                      d()
                    end
                  else
                    if ((j - 173) == 0) then
                      q[41] = (((k < t.e) and (c < t.e)) and (m == 0))
                    elseif (j == 181) then
                      q[41] = (((k < t.e) and (c < t.p)) and (m == 0))
                    else
                      d()
                    end
                  end
                end
              end
            else
              d()
            end
            if (not q[41]) then
              d()
            end
            return true
          end
        end
        i = (i + 7315)
        lrotate, buf_create, XOR, fmt, bit32lib, typeof, nextf, rawget_, loadstring, tonum, adler32, LIBSTR, select_, buf_readf64, buf_fromstring, buf_readu8, floor, buf_len, tfreeze, buf_readu32, u32le_str, strchar, bnot, ENV, debuglib, bor, packN, lshift, decstr, XOR2, strsub, getmeta, buf_readu16, int_fromstring, rawequal_, strbyte, dbginfo, f64le, rshift, bufferlib, bxor, band, setmeta, pcall_, buf_readi32, ERR, tostr, u32le_str2, buf_writeu8, tconcat, tunpack = t[1910]()
        q = ((true and function()
          local t = {[73] = buf_create(6), [44] = buf_create(6), [67] = (bxor(i, q) % w.h)}
          t[91] = band(bxor(t[67], lrotate(t[67], 9)), 255)
          buf_writeu8(t[73], 3, bxor(0, t[91]))
          buf_writeu8(t[73], 5, bxor(0, t[91]))
          buf_writeu8(t[73], 4, bxor(0, t[91]))
          buf_writeu8(t[73], 2, bxor(255, t[91]))
          if ((bxor(i, q) % w.h) ~= t[67]) then
            ERR()
          end
          buf_writeu8(t[44], 4, bxor(buf_readu8(t[73], 3), t[91]))
          buf_writeu8(t[44], 3, bxor(buf_readu8(t[73], 4), t[91]))
          buf_writeu8(t[44], 2, bxor(buf_readu8(t[73], 2), t[91]))
          buf_writeu8(t[44], 5, bxor(buf_readu8(t[73], 5), t[91]))
          t[80] = buf_readu32(t[44], 2)
          t[53] = band(bxor(t[67], lrotate(t[67], 7)), 255)
          buf_writeu8(t[73], 5, bxor(t[53], 3))
          buf_writeu8(t[44], 5, bxor(t[53], 1))
          buf_writeu8(t[73], 3, bxor(t[53], 2))
          buf_writeu8(t[44], 4, bxor(t[53], 2))
          buf_writeu8(t[73], 4, bxor(t[53], 1))
          buf_writeu8(t[44], 3, bxor(t[53], 3))
          buf_writeu8(t[73], 2, bxor(t[53], 0))
          buf_writeu8(t[44], 2, bxor(t[53], 4))
          t[73] = nil
          t[44] = nil
          if ((bxor(i, q) % w.h) ~= t[67]) then
            ERR()
          end
          return t[80]
        end()) or 255)
      else
        ERR()
      end
    end
  end
end,
  [7594] = function(ra, r, e, p, a, ro, zo, yo, er, m, f, i, g, z, b, qa, di, cx, mb, is, s, q, uh, mp, le, pk, h, qt, sm, k, c, o, mg)
  local x = qa({}, {__mode = "kv"})
  local t
  local d
  local op = function(w, j)
    local x = x[w]
    if x then
      return t(x[1], j, x[2])
    else
      return r(w(e(j, 1, j.n)))
    end
  end
  local zf = function(c, i)
    local x = (((c * 1) + 3) % 4)
    local m = (((c * 95) + 2) % 127)
    local t = (((c * 214) + 78) % 257)
    local q = (1 + (m * 2))
    local k = (x * 257)
    local j
    if (x == 0) then
      j = function(j)
        return (k + (((j * q) + t) % 257))
      end
    elseif (x == 1) then
      j = function(j)
        return ((k + w.e) - (((j * q) + t) % 257))
      end
    elseif (x == 2) then
      j = function(j)
        return (k + ((((255 - j) * q) + t) % 257))
      end
    else
      j = function(j)
        return (k + (((((j + t) % 257) * q) + m) % 257))
      end
    end
    local w
    if (x == 0) then
      w = function(x, t, w)
        if (x == t) then
          return w
        end
        return i[j(x)]
      end
    elseif (x == 1) then
      w = function(x, t, w)
        if (x ~= t) then
          return i[j(x)]
        end
        return w
      end
    elseif (x == 2) then
      w = function(t, w, q)
        local x = j(t)
        if (x == j(w)) then
          return q
        end
        return i[x]
      end
    else
      w = function(x, w, q)
        if (((x + t) % 257) == ((w + t) % 257)) then
          return q
        end
        return i[j(x)]
      end
    end
    return j, w
  end
  d = function(k, c)
    local j = s[k]
    local w = j.u
    if w then
      local i = x[w][2]
      local t = true
      for x = 0, (j.p - 1) do
        if ((x ~= j.d) and (not cx(q(i[x]), q(c[x])))) then
          t = false
          break
        end
      end
      if t then
        return w
      end
    end
    local i = {k, c}
    local t = function(...)
      local j = t(i[1], r(...), i[2])
      return e(j, 1, j.n)
    end
    x[t] = i
    if (j.m and (not w)) then
      j.u = t
    end
    return t
  end
  local up = function(k, q)
    local d = {}
    local j = s[k]
    local t = {}
    local w, c = zf(k, t)
    local x = (q.n - j.t)
    if (x < 0) then
      x = 0
    end
    local i = {}
    i.n = x
    for x = 1, x do
      i[x] = q[(j.t + x)]
    end
    for j = 0, (j.t - 1) do
      t[w(j)] = {q[(j + 1)]}
    end
    if ((m((j.y / 2)) % 2) == 1) then
      t[w(j.t)] = {}
      if ((m((j.y / 4)) % 2) == 1) then
        local q = {}
        q.n = x
        for j = 1, x do
          q[j] = i[j]
        end
        t[w(j.t)][1] = q
      end
    end
    return j, t, i, w, c, x
  end
  local y = {"__call", "table", "n", "z", "function", "__iter", "p"}
  local u = {op, is, d, uh, di, q, g, b, p, x, z, f, s, i, mp}
  local n = {
    {{8, w.ad, 10010e2}, {7, 0}},
    {{8, 800e4, 2003000}, {7, 0}},
    {{8, 0x7a1200, 0x5b8d80}, {7, 0}},
    {{3, 0xBB8, 3000e3}, {11, 0xbb8, 0x2dcaa8, 1001000}, {8, 0x7a1200, 30e2}, {7, 0}},
    {{5, 30e2, 0x6AE348, 300e4, 1, 1001e3}, {8, w.ad, 3000}, {7, 0}},
    {{5, 0xBB8, 7003e3, 3e6, 2, 1000e3, 10010e2}, {7, 0}},
    {{10, 300e1, 0x3D2070, 8001e3}, {5, 5000, 7005e3, 300000e1, 1, 0xBB8}, {8, 800000e1, 5000}, {7, 0}},
    {{10, 0xBB8, 0x3d2070, 80010e2}, {5, 5000, 700300e1, 3000000, 2, 30e2, 100e4}, {7, 0}},
    {{10, 0xbb8, 7008e3, 0x1e9038}, {8, w.ad, 0xbb8}, {7, 0}},
    {{11, 7008000, 2003e3, 1e6}, {7, 0}},
    {{3, 0xbb8, 0x2DC6C0}, {8, 0x7A1200, 0xBB8}, {7, 0}},
    {{10, 300e1, 1001000, 1002e3}, {8, 8000e3, 3e3}, {7, 0}},
    {{11, 1000000, 0xF4628, 10020e2}, {7, 0}},
    {{5, 0xBB8, 0x6b0670, 30e5, 2, 0xF4628, 0xF4A10}, {8, 800e4, 3e3}, {7, 0}},
    {{3, 0xBB8, 3000000}, {11, 3e3, 5002e3, 0x2dc6c0}, {8, 800000e1, 0xBB8}, {7, 0}},
    {
    {1, 300e1, 10000e2},
    {10, 5e3, 0xbb8, 500200e1},
    {4, 1000e1, 5e3, 0x2dcaa8, 3000000},
    {11, 0xbb8, 5002000, 1e4},
    {10, 20e2, 0xbb8, 50020e2},
    {11, 3000, 20e2, 100100e1},
    {7, 0}
  },
    {
    {1, 0xBB8, 100000e1},
    {1, 0x1388, 0xF4628},
    {10, 100e2, 3000, 50020e2},
    {10, 0x7d0, 50e2, 0x4c5310},
    {5, 9e3, 0x6afab8, 0x2DC6C0, 1, 0x7D0},
    {1, 11000, 300100e1},
    {4, 0, 11e3, 900e1, 0x2df1b8},
    {6, 0, 10},
    {6, 15},
    {4, 7e3, 10000, 1100e1, 300000e1},
    {10, 0x1F40, 5000, 11000},
    {11, 30e2, 7000, 80e2},
    {4, 11000, 1100e1, 30010e2, 3e6},
    {6, 7},
    {4, 0x3a98, 0x2710, 20e2, 30000e2},
    {11, 300e1, 500200e1, 0x3a98},
    {7, 0}
  },
    {{10, 30e2, 100100e1, 80020e2}, {8, w.ad, 300e1}, {7, 0}},
    {{1, 0xbb8, 400600e1}, {8, 8e6, 0xbb8}, {7, 0}},
    {{5, 30e2, 700000e1, 30000e2, 2, 1001e3, 1002000}, {8, 8e6, 3000}, {7, 0}},
    {
    {10, 0xbb8, 0x6afea0, 0x7a1db8},
    {3, 0x1388, 3e6},
    {10, 10000, 30e2, 0x4C62B0},
    {4, 0x7d0, 1e4, 300100e1, 0x2DCAA8},
    {1, 0x2AF8, 300e4},
    {4, 0, 11000, 2000, 0x2DF1B8},
    {6, 0, 9},
    {6, 23},
    {10, 8000, 30e2, 0x4C56F8},
    {10, 700e1, 8000, 0x2AF8},
    {10, 0x3A98, 7e3, 0x2DCAA8},
    {4, 90e2, 150e2, w.ac, 300800e1},
    {6, 0x2328, 18},
    {10, 0x32c8, 700e1, 0x2dce90},
    {9, 600e1, 0x32c8},
    {11, 50e2, 0x2AF8, 6e3},
    {6, 21},
    {10, 0x32C8, 0x1b58, 300200e1},
    {10, 100e1, 0x3d2070, 0x32C8},
    {11, 5e3, 1100e1, 0x3E8},
    {4, 110e2, 0x2AF8, w.ac, 3000000},
    {6, 6},
    {5, 0xfa0, 700200e1, 300e4, 2, 0x7A1DB8, 50e2},
    {8, 0x7A1200, 0xFA0},
    {7, 0}
  },
    {
    {1, 0xbb8, 80000e2},
    {4, 50e2, 300e1, 0x7A15E8, 301100e1},
    {6, 5e3, 5},
    {6, 8},
    {8, 300e1, 600e4},
    {4, 3e3, 0xBB8, 0x2dcaa8, 30e5},
    {6, 2},
    {7, 0}
  },
    {{4, 30e2, 1001e3, 0xf4a10, 0x2DC6C0}, {8, 80000e2, 30e2}, {7, 0}},
    {{4, 30e2, 10010e2, 1002000, w.ac}, {8, 80e5, 0xBB8}, {7, 0}},
    {{4, 300e1, 100100e1, 1002e3, 3002000}, {8, 800000e1, 0xbb8}, {7, 0}},
    {{4, 0xbb8, 1001e3, 0xF4A10, 0x2DD278}, {8, w.ad, 30e2}, {7, 0}},
    {{4, 30e2, 0xf4628, 10020e2, 3007000}, {8, 800000e1, 3000}, {7, 0}},
    {{4, 300e1, 0xF4628, 0xf4a10, 300400e1}, {8, 800000e1, 0xBB8}, {7, 0}},
    {{4, 3e3, 10010e2, 1002e3, 0x2DDA48}, {8, 800000e1, 0xBB8}, {7, 0}},
    {{4, 0xbb8, 10010e2, 100200e1, 3009000}, {8, 800000e1, 3000}, {7, 0}},
    {{4, 0xBB8, 1001e3, 100200e1, 0x2DE600}, {8, 0x7a1200, 0xBB8}, {7, 0}},
    {{4, 0xbb8, 100100e1, 1002000, 0x2DEDD0}, {8, w.ad, 0xBB8}, {7, 0}},
    {{4, 0xbb8, 1001e3, 0xF4A10, 30110e2}, {8, 800000e1, 0xBB8}, {7, 0}},
    {{4, 0xbb8, 0xf4628, 30000e2, 30120e2}, {8, 0x7a1200, 0xBB8}, {7, 0}},
    {{4, 300e1, 0xF4628, 0x2DC6C0, 30060e2}, {8, w.ad, 300e1}, {7, 0}},
    {{4, 3e3, 0xf4628, 3000e3, 3013e3}, {8, 0x7a1200, 0xBB8}, {7, 0}},
    {
    {5, 300e1, 70110e2, 0x2dc6c0, 1, 10000e2},
    {5, 5e3, 7011000, 300000e1, 1, 0xF4241},
    {5, 0x2710, 0x6afab8, 300000e1, 1, 1000002},
    {4, 20e2, 300e1, 6e6, 3008000},
    {6, 0x7D0, 16},
    {4, 2000, 5000, 600e4, 3008000},
    {6, 2e3, 16},
    {4, 20e2, 1000e1, 6e6, 3008e3},
    {6, 0x7d0, 16},
    {8, 8000e3, 3000},
    {4, 0, 8000e3, w.ac, 3000e3},
    {8, 0, 0x1388},
    {4, 8e3, 0, 0x2dcaa8, 3e6},
    {8, 80e2, 10000},
    {7, 0},
    {12}
  },
    {{4, 30e2, 100000e1, 0xf4242, 30000e2}, {8, 80000e2, 0xBB8}, {7, 0}},
    {
    {1, 3000, 1001000},
    {1, 0x1388, 1001001},
    {1, 10e3, 1001002},
    {4, 20e2, 300e4, 1000e1, 301000e1},
    {6, 200e1, 9},
    {4, 11e3, 5e3, 30e2, 3011000},
    {8, 80e5, 11000},
    {6, 11},
    {4, 11000, 3000, 5000, 30110e2},
    {8, 0x7A1200, 11e3},
    {7, 0}
  },
    {
    {1, 0xbb8, 10e5},
    {10, 50e2, 3e3, 0x2DCAA8},
    {5, 0x2710, 70130e2, 0x2dc6c0, 1, 500e1},
    {4, 200e1, 10000, 500400e1, 300800e1},
    {6, 0x7D0, 44},
    {5, 0x2AF8, 700700e1, 0x2dc6c0, 1, 5e3},
    {4, 2000, 11e3, 60e5, 3008000},
    {6, 0x7d0, 13},
    {5, 1e4, 0x6B0288, 0x2dc6c0, 1, 0x2AF8},
    {4, 0x7D0, 1e4, 0x4c4f28, 3008000},
    {6, 2e3, 13},
    {12},
    {4, 0x7D0, 11000, 0x5b8d80, 30080e2},
    {6, 20e2, 17},
    {5, 0, 0x6ADF60, 300e4, 2, 0x2af8, 5005e3},
    {6, 18},
    {1, 0, 6e6},
    {4, 0x7d0, 0, 600000e1, 3008e3},
    {6, 0x7d0, 30},
    {3, 0x1F40, 0x2DC6C0},
    {11, 0x1F40, 500200e1, 0x2DCAA8},
    {11, 0x1F40, 0x2DCAA8, 5e3},
    {5, 0x1B58, 7e6, 0x2dc6c0, 2, 0, 8e3},
    {1, 0xBB8, 0x1B58},
    {10, 150e2, 30e2, w.ac},
    {4, 0x7D0, 0x3a98, 60e5, 3008000},
    {6, 200e1, 29},
    {6, 44},
    {12},
    {4, 0x7d0, 110e2, 0x5b8d80, 0x2de600},
    {6, 0x7D0, 36},
    {5, 130e2, 7004e3, 3000000, 2, 0x2AF8, 50000e2},
    {4, 2e3, 0x32c8, 6000000, 0x2de600},
    {6, 20e2, 36},
    {6, 44},
    {5, 0x2710, 701300e1, 300e4, 1, 0x1388},
    {4, 20e2, 10000, 5001e3, 3008e3},
    {6, 0x7D0, 40},
    {12},
    {3, 30e2, 0x2dc6c0},
    {11, 3e3, 0x4c5310, 30030e2},
    {11, 30e2, 3001e3, 0x6AF6D0},
    {11, 3e3, 3002e3, 5000},
    {11, 0xBB8, 0x4c5310, 3003000},
    {8, 8e6, 30e2},
    {7, 0}
  },
    {
    {1, 0xBB8, 0xF4628},
    {10, 0x1388, 3000, 30010e2},
    {10, 1000e1, 300e1, 30020e2},
    {10, 2e3, 300e1, 0x2dd278},
    {3, 1100e1, 0x2dc6c0},
    {11, 11000, 5002e3, 3002000},
    {11, 11e3, w.ac, 1e4},
    {11, 1100e1, 3002e3, 2e3},
    {5, 0, 0x6ACFC0, 30e5, 2, 50e2, 1100e1},
    {10, 0x1f40, 0, 300100e1},
    {11, 300e1, 30030e2, 0x1F40},
    {8, 8000e3, 0},
    {7, 0}
  },
    {
    {1, 0xbb8, 0xf4628},
    {1, 0x1388, 1002e3},
    {10, 0x2710, 300e1, 5002000},
    {5, 2e3, 7011e3, 30e5, 1, 10000},
    {1, 11e3, 1000000},
    {1, 0, 3001e3},
    {4, 80e2, 0, 0x7d0, 30110e2},
    {6, 8e3, 10},
    {6, 16},
    {4, 0x1B58, 0x1388, 0, 0x2dc6c0},
    {4, 15e3, 7e3, 0x2DCAA8, 3001e3},
    {10, 90e2, 0xbb8, 0},
    {11, 1100e1, 0x3A98, 900e1},
    {4, 0, 0, w.ac, 3000e3},
    {6, 7},
    {7, 0}
  },
    {{5, 0xbb8, 0x6AE730, 3e6, 1, 1001e3}, {8, 80e5, 300e1}, {7, 0}},
    0,
    {{7, 1, 0x7A21A0}},
    {{2, 3e3, 1e6}, {6, 30e2, 4}, {7, 1, 80060e2}, {7, 0}},
    {{1, 300e1, 1e6}, {7, 2, 300e1}},
    {
    {1, 3e3, 10e5},
    {1, 0x1388, 10010e2},
    {10, 10000, 700900e1, 0xbb8},
    {2, 2000, 10e3},
    {6, 200e1, 8},
    {5, 110e2, 700e4, 30000e2, 2, 0xBB8, 0x1388},
    {7, 2, 110e2},
    {10, 0, 10000, 0x2DCAA8},
    {10, 8000, 0x2710, 0x2dce90},
    {7, 3, 0, 50e2, 800e1}
  },
    {{5, 3e3, 0x6ad3a8, 0x2DC6C0, 1, 0xF4240}, {7, 0}}
  }
  local j = {}
  local l = function(x, w)
    local t = j[x]
    if (t == 1) then
      j[x] = nil
      local j = s[x]
      local x = j.l
      if x[-1] then
        j.l = x[-1]
        j.v = nil
        j.g = nil
      end
    else
      j[x] = (t - 1)
    end
    return w
  end
  t = function(d, cx, z)
    local b, p, is, g, x, di
    local f = function(t, h, n)
      local d, l, z, qa, pk, q = i(0), i(a), i(y), (#y), (#u), {}
      local j = 6
      local cx = {0, 0, 0}
      local f = function(j)
        a(("seedfail:" .. j))
      end
      local s = function(j)
        if ((i(j) ~= d) or (j < 0)) then
          do
            local j = 6
            a(("seedfail:" .. j))
          end
        end
        local t = (j - (((j / 1e3) // 1) * 1e3))
        local w = ((((((j * 1013738) - (j * 1013737)) + (4294967296 - ((t * 1132362) - (t * 0x114749)))) % 4294967296) % 4294967296) / 0x3E8)
        local i = (w % 1e3)
        local x = ((((((w * 1032671) - (w * 1032670)) + (4294967296 - ((i * 1021877) - (i * 1021876)))) % 4294967296) % 4294967296) / 0x3e8)
        if (((x > 8) or ((x % 1) ~= 0)) or (x < 0)) then
          do
            local j = 7
            a(("seedfail:" .. j))
          end
        end
        return x, i, t
      end
      local m = function(x)
        local t, j, w = s(x)
        if (((t ~= 0) or (((w - 0) % 4294967296) > 0)) or (((15 - j) % 4294967296) > 2147483648)) then
          do
            local j = 8
            a(("seedfail:" .. j))
          end
        end
        return j
      end
      local w = function(w)
        local t, j, x = s(w)
        if (t == 4) then
          if ((not (((j - 0) % 4294967296) > 0)) or (not (((j - 1) * (j - 1)) > 0))) then
            f(15)
          end
          if ((((9 - j) % 4294967296) >= 2147483648) or (((x - 0) % 4294967296) > 0)) then
            do
              local j = 16
              a(("seedfail:" .. j))
            end
          end
          return h[j]
        elseif (t == 7) then
          if ((((x - 0) % 4294967296) > 0) or (j >= pk)) then
            do
              local j = 19
              a(("seedfail:" .. j))
            end
          end
          return u[(((j * 0xFDF7C) - (j * 1040251)) + 1)]
        elseif (t == 0) then
          if ((((15 - j) % 4294967296) > 2147483648) or (((x - 0) * (x - 0)) > 0)) then
            do
              local j = 9
              a(("seedfail:" .. j))
            end
          end
          return q[j]
        elseif (t == 5) then
          if ((((x - 0) % 4294967296) > 0) or (j >= qa)) then
            do
              local j = 17
              a(("seedfail:" .. j))
            end
          end
          return y[((k(j, 1) + (2 * c(j, 1))) % 4294967296)]
        elseif (t == 6) then
          if ((((x - 0) % 4294967296) > 0) or (((j - 0) % 4294967296) > 0)) then
            f(18)
          end
          return nil
        elseif (t == 2) then
          if (((((x - (x // 1)) > 0) or (((x // 1) - x) > 0)) or (((0xFF - x) % 4294967296) >= 2147483648)) or (((j - 3) * (j - 3)) > 0)) then
            do
              local j = 12
              a(("seedfail:" .. j))
            end
          end
          local j = h[4]
          if (i(j) ~= d) then
            do
              local j = 13
              a(("seedfail:" .. j))
            end
          end
          return sm(di, b.x, ((((j * 1090514) - (j * 1090513)) + ((x * 0x1224f1) - (x * 0x1224f0))) % 4294967296), nil, nil, cx)
        elseif (t == 1) then
          if (((((0xff - x) % 4294967296) >= 2147483648) or (((x // 1) < x) or (x < (x // 1)))) or (((2 - j) % 4294967296) >= 2147483648)) then
            do
              local j = 10
              a(("seedfail:" .. j))
            end
          end
          local j = h[((((((((j * 1113500) - (j * 1113499)) + 1175176) - 1175175) % 4294967296) * 0x8048a) - ((((((j * 0x10FD9C) - (j * 1113499)) + 1175176) - 1175175) % 4294967296) * 525449)) % 4294967296)]
          if (i(j) ~= d) then
            do
              local j = 11
              a(("seedfail:" .. j))
            end
          end
          return p[g(((((((j * 1052135) - (j * 1052134)) + (x * 1023069)) - (x * 1023068)) % 4294967296) % 4294967296))]
        elseif (t == 3) then
          if (((((0xF423F - j) + 4294967296) % 4294967296) > 2147483648) or (((x - 0) * (x - 0)) > 0)) then
            do
              local j = 14
              a(("seedfail:" .. j))
            end
          end
          return j
        else
          if ((((x - 0) % 4294967296) > 0) or (not ((((j - 9) + 4294967296) % 4294967296) > 2147483648))) then
            do
              local j = 20
              a(("seedfail:" .. j))
            end
          end
          return h[(k(j, 1) + (c(j, 1) + c(j, 1)))]
        end
      end
      local u = 7
      local y = function(j)
        if ((i(j) ~= d) or (((j - (j // 1)) > 0) or (((j // 1) - j) > 0))) then
          do
            local j = 36
            a(("seedfail:" .. j))
          end
        end
        return j
      end
      local b = function(j)
        if ((((i(j) ~= d) or (j > (#t))) or ((j % 1) ~= 0)) or (j < 1)) then
          do
            local j = 32
            a(("seedfail:" .. j))
          end
        end
        return j
      end
      local x = 1
      for h = 1, 100000 do
        if ((((x - 1) % 4294967296) >= 2147483648) or (x > (#t))) then
          do
            local j = 2
            a(("seedfail:" .. j))
          end
        end
        local j = t[x]
        if (i(j) ~= z) then
          do
            local j = 3
            a(("seedfail:" .. j))
          end
        end
        local t = j[1]
        local u = 5
        if (t == 2) then
          if ((((#j) - 3) % 4294967296) > 0) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local t = w(j[3])
          local j = m(j[2])
          q[j] = ((t ~= nil) and (t ~= false))
          x = (k(x, 1) + (2 * c(x, 1)))
        elseif (t == 10) then
          if (4 ~= (#j)) then
            f(5)
          end
          q[m(j[2])] = w(j[3])[w(j[4])]
          x = ((k(x, 1) + (c(x, 1) + c(x, 1))) % 4294967296)
        elseif (t == 11) then
          if (4 ~= (#j)) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          w(j[2])[w(j[3])] = w(j[4])
          x = ((((1 + ((x * 0x10CA3E) - (x * 0x10ca3d))) * 0x24D10) - ((1 + ((x * 110035e1) - (x * 0x10ca3d))) * 0x24d0f)) % 4294967296)
        elseif (t == 12) then
          if (k((#j), 1) > 0) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          a()
          x = (((2 * o(x, 1)) - k(x, 1)) % 4294967296)
        elseif (t == 9) then
          if ((((#j) - 3) * ((#j) - 3)) > 0) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local t = w(j[3])
          local j = m(j[2])
          q[j] = p[g(y(t))]
          x = (((x * 0x118df9) - (x * 1150456)) + 1)
        elseif (t == 7) then
          local x = j[2]
          if ((((x ~= 3) and (x ~= 0)) and (x ~= 2)) and (x ~= 1)) then
            do
              local j = 34
              a(("seedfail:" .. j))
            end
          end
          local t = (n or 0)
          n = t
          if ((x ~= n) and (n ~= 9)) then
            a()
          end
          if (5 == (#j)) then
            if (x ~= 3) then
              f(5)
            end
            local t = w(j[3])
            return t, w(j[4]), w(j[5]), x
          elseif (not ((((#j) - 3) * ((#j) - 3)) > 0)) then
            if ((x == 3) or (x == 0)) then
              do
                local j = 5
                a(("seedfail:" .. j))
              end
            end
            local j = w(j[3])
            return j, x
          elseif (2 == (#j)) then
            if (x ~= 0) then
              do
                local j = 5
                a(("seedfail:" .. j))
              end
            end
            return nil, 0
          else
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
        elseif (t == 6) then
          if (not ((((#j) - 3) * ((#j) - 3)) > 0)) then
            local t = m(j[2])
            local j = b(j[3])
            if (not q[t]) then
              x = (((((x * 0x11d4fe) - (x * 0x11D4FD)) + 1156244) - 1156243) % 4294967296)
            else
              x = j
            end
          elseif (2 == (#j)) then
            x = b(j[2])
          else
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
        elseif (t == 8) then
          if (3 ~= (#j)) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local t = w(j[2])
          p[g(y(t))] = w(j[3])
          x = (((((x * 1162202) - (x * 0x11BBD9)) + 1115243) - 1115242) % 4294967296)
        elseif (t == 3) then
          if (3 ~= (#j)) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local t = w(j[3])
          if (i(t) ~= d) then
            do
              local j = 21
              a(("seedfail:" .. j))
            end
          end
          local j = m(j[2])
          q[j] = {}
          x = ((1 + ((x * 0x120a49) - (x * 1182280))) % 4294967296)
        elseif (t == 1) then
          if ((((#j) - 3) % 4294967296) > 0) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local t = m(j[2])
          q[t] = w(j[3])
          x = (((1 + ((x * 1038927) - (x * 0xFDA4E))) * 246132) - ((1 + ((x * 0xFDA4F) - (x * 0xFDA4E))) * 0x3c173))
        elseif (t == 4) then
          if (5 ~= (#j)) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local c, t, d = s(j[5])
          if ((((((13 - t) + 4294967296) % 4294967296) > 2147483648) or (((c - 3) * (c - 3)) > 0)) or (((d - 0) * (d - 0)) > 0)) then
            do
              local j = 22
              a(("seedfail:" .. j))
            end
          end
          local i, k = w(j[3]), w(j[4])
          local w
          if (not (((t - 9) % 4294967296) > 0)) then
            w = (i .. k)
          elseif (not (((t - 6) % 4294967296) > 0)) then
            w = (-i)
          elseif (not (((t - 5) % 4294967296) > 0)) then
            local j = i
            w = (j ^ k)
          elseif (not (((t - 10) % 4294967296) > 0)) then
            local j = k
            w = (j > i)
          elseif (not (((t - 3) * (t - 3)) > 0)) then
            w = (i / k)
          elseif (not (((t - 7) % 4294967296) > 0)) then
            w = (i // k)
          elseif (not (((t - 0) * (t - 0)) > 0)) then
            w = (i + k)
          elseif (not (((t - 12) % 4294967296) > 0)) then
            w = (not i)
          elseif (not (((t - 4) * (t - 4)) > 0)) then
            w = (i % k)
          elseif (not (((t - 2) % 4294967296) > 0)) then
            local j = i
            w = (j * k)
          elseif (not (((t - 11) * (t - 11)) > 0)) then
            w = (k >= i)
          elseif (not (((t - 8) * (t - 8)) > 0)) then
            w = (i == k)
          elseif (not (((t - 1) * (t - 1)) > 0)) then
            local j = i
            w = (j - k)
          else
            w = (#i)
          end
          q[m(j[2])] = w
          x = (((x * 1083090) - (x * 0x1086D1)) + 1)
        elseif (t == 5) then
          local t = j[5]
          if ((((i(t) ~= d) or ((t % 1) ~= 0)) or (t < 0)) or (t > 8)) then
            do
              local j = 25
              a(("seedfail:" .. j))
            end
          end
          if (((2 * o(t, 5)) - k(t, 5)) ~= (#j)) then
            do
              local j = 5
              a(("seedfail:" .. j))
            end
          end
          local p = m(j[2])
          local m = w(j[3])
          if (l ~= i(m)) then
            do
              local j = 26
              a(("seedfail:" .. j))
            end
          end
          local n, h, f = s(j[4])
          if (((f ~= 0) or (h > 2)) or (n ~= 3)) then
            do
              local j = 27
              a(("seedfail:" .. j))
            end
          end
          local d = {}
          for x = 1, t do
            local j = w(j[((((((x * 1157179) - (x * 1157178)) + 5092515) - 5092510) % 4294967296) % 4294967296)])
            d[x] = j
          end
          if (h == 0) then
            local j = m(e(d, 1, t))
            q[p] = j
          elseif (h == 1) then
            if (1 ~= t) then
              do
                local j = 29
                a(("seedfail:" .. j))
              end
            end
            local j = d[1]
            if (z ~= i(j)) then
              do
                local j = 30
                a(("seedfail:" .. j))
              end
            end
            local x = j.n
            if (nil == x) then
              x = (#j)
            end
            if (x > 8) then
              do
                local j = 31
                a(("seedfail:" .. j))
              end
            end
            q[p] = m(e(j, 1, x))
          else
            q[p] = m(r(e(d, 1, t)))
          end
          x = ((k(x, 1) + (c(x, 1) + c(x, 1))) % 4294967296)
        else
          do
            local j = 4
            a(("seedfail:" .. j))
          end
        end
      end
      do
        local j = 35
        a(("seedfail:" .. j))
      end
    end
    while true do
      local qa = function(j)
        return (not false)
      end
      b, p, is, g, x = up(d, cx)
      local o = b.l
      if (i(o) ~= i(s)) then
        o = qt(d)
      end
      di = o[-1]
      j[d] = ((j[d] or 0) + 1)
      local g = o[0]
      local e, k, j, di, u, x, t, m, c, p, uh, r
      local y = ((((s.h % 2) == 0) and ((535 + s.h) % w.ab)) or ((704 + s.h) % w.ab))
      local q, i, mp = 0, 0, s.h
      while true do
        if ((((s.h % 2) == 0) and ((y - ((535 + s.h) % w.ab)) == 0)) or (((s.h % 2) ~= 0) and ((y - ((704 + s.h) % w.ab)) == 0))) then
          e = o[g]
          if (e == nil) then
            a()
          end
          di = pk(e[1], g, d, 0)
          u = pk(e[3], g, d, 1)
          k = le(e[2], g, di, u, d)
          uh = ((((g * 37) + (e[2] * 22626)) + (d * 24166)) % w.ab)
          r = b.v[uh]
          if (r == nil) then
            a()
          end
          r = r[g]
          if ((((not r) or (r[1] ~= k)) or (r[2] < 1)) or (r[2] > 4)) then
            a()
          end
          k = r[1]
          g = di
          i = ((((((((35641 * i) + (63217 * k)) + (63288 * g)) + mp) + (((t == x) and 95) or 34)) + (((c == m) and 23) or 66)) + (((nil == p) and 41) or 59)) % w.ab)
          q = ((-i) + w.u)
          y = ((((s.h % 2) == 0) and ((648 + s.h) % w.ab)) or ((766 + s.h) % w.ab))
        elseif ((((s.h % 2) == 0) and (not (y ~= ((648 + s.h) % w.ab)))) or (((s.h % 2) ~= 0) and ((y - ((766 + s.h) % w.ab)) == 0))) then
          j = ((((q + i) % w.ab) * 5616) % w.ab)
          i = (((((35641 * i) + (63217 * j)) + (63288 * g)) + mp) % w.ab)
          if (not (j ~= 859)) then
            if (k <= 18090) then
              if ((k - 9488) <= 0) then
                if (not (k ~= 2752)) then
                  q = (12857 - i)
                elseif (6634 == k) then
                  q = (11877 - i)
                elseif (4207 == k) then
                  q = (60096 - i)
                elseif (k == 9343) then
                  q = (10232 - i)
                elseif ((k - 284) == 0) then
                  q = (16987 - i)
                elseif ((k - 8058) == 0) then
                  q = (63001 - i)
                elseif (not (k ~= 1036)) then
                  q = (34254 - i)
                elseif (8551 == k) then
                  q = (55616 - i)
                elseif ((k - 8090) == 0) then
                  q = (55966 - i)
                elseif (k == 2949) then
                  q = (16252 - i)
                elseif (k == 1073) then
                  q = (58381 - i)
                elseif (1527 == k) then
                  q = (18527 - i)
                elseif (not (k ~= 1126)) then
                  q = (59956 - i)
                elseif ((k - 5953) == 0) then
                  q = (36704 - i)
                elseif (not (k ~= 8509)) then
                  q = (55686 - i)
                elseif (8423 == k) then
                  q = (60481 - i)
                elseif (8221 == k) then
                  q = (13592 - i)
                elseif (672 == k) then
                  q = (57506 - i)
                elseif (not (k ~= 507)) then
                  q = (55756 - i)
                else
                  a()
                end
              elseif (not (k ~= 9893)) then
                q = (10302 - i)
              elseif (not (k ~= 12432)) then
                q = (39399 - i)
              elseif (9521 == k) then
                q = (18562 - i)
              elseif ((k - 12831) == 0) then
                q = (35479 - i)
              elseif (k == 13537) then
                q = (57261 - i)
              elseif (not (k ~= 10854)) then
                q = (13977 - i)
              elseif ((k - 12610) == 0) then
                q = (36179 - i)
              elseif (k == 16621) then
                q = (14502 - i)
              elseif (9575 == k) then
                q = (34709 - i)
              elseif (not (k ~= 13131)) then
                q = (60446 - i)
              elseif (15169 == k) then
                q = (40449 - i)
              elseif (k == 12248) then
                q = (39364 - i)
              elseif (k == 13580) then
                q = (62196 - i)
              elseif ((k - 15488) == 0) then
                q = (37194 - i)
              elseif (k == 10736) then
                q = (57331 - i)
              elseif (17665 == k) then
                q = (36389 - i)
              elseif (k == 14451) then
                q = (34884 - i)
              else
                a()
              end
            elseif (not (k > 31368)) then
              if ((22651 - k) >= 0) then
                if (18731 == k) then
                  q = (15657 - i)
                elseif (18112 == k) then
                  q = (38069 - i)
                elseif (20211 == k) then
                  q = (12612 - i)
                elseif (k == 21929) then
                  q = (61811 - i)
                elseif (18832 == k) then
                  q = (41114 - i)
                elseif (18630 == k) then
                  q = (19927 - i)
                elseif (not (k ~= 19483)) then
                  q = (36459 - i)
                elseif (k == 22135) then
                  q = (62406 - i)
                elseif ((k - 19680) == 0) then
                  q = (11527 - i)
                elseif (21602 == k) then
                  q = (35339 - i)
                elseif (not (k ~= 22357)) then
                  q = (60061 - i)
                elseif (k == 19863) then
                  q = (55021 - i)
                elseif (k == 18672) then
                  q = (32049 - i)
                elseif (18387 == k) then
                  q = (58696 - i)
                elseif (k == 19016) then
                  q = (10687 - i)
                elseif (not (k ~= 18248)) then
                  q = (56596 - i)
                elseif (k == 20748) then
                  q = (15482 - i)
                elseif (19173 == k) then
                  q = (57996 - i)
                elseif (20440 == k) then
                  q = (60796 - i)
                elseif (22232 == k) then
                  q = (17862 - i)
                elseif ((k - 22628) == 0) then
                  q = (54251 - i)
                else
                  a()
                end
              elseif ((k - 24451) == 0) then
                q = (59571 - i)
              elseif (not (k ~= 23472)) then
                q = (32854 - i)
              elseif (28318 == k) then
                q = (39084 - i)
              elseif (not (k ~= 25553)) then
                q = (61846 - i)
              elseif (30359 == k) then
                q = (11702 - i)
              elseif ((k - 29685) == 0) then
                q = (13487 - i)
              elseif (28966 == k) then
                q = (54111 - i)
              elseif (k == 28284) then
                q = (11457 - i)
              elseif (not (k ~= 24039)) then
                q = (59011 - i)
              elseif (23708 == k) then
                q = (34639 - i)
              elseif (not (k ~= 28861)) then
                q = (32959 - i)
              elseif (not (k ~= 27054)) then
                q = (56631 - i)
              elseif (31359 == k) then
                q = (63666 - i)
              elseif (k == 25981) then
                q = (63876 - i)
              elseif ((k - 31225) == 0) then
                q = (61216 - i)
              elseif (k == 27652) then
                q = (35199 - i)
              elseif ((k - 22757) == 0) then
                q = (54776 - i)
              else
                a()
              end
            elseif (not (((true and k) or 775) > 46084)) then
              if (k > 36086) then
                if (not (k ~= 40354)) then
                  q = (56736 - i)
                elseif (k == 44205) then
                  q = (32224 - i)
                elseif (not (k ~= 39871)) then
                  q = (63316 - i)
                elseif (not (k ~= 41044)) then
                  q = (55546 - i)
                elseif ((k - 41827) == 0) then
                  q = (41954 - i)
                elseif (41220 == k) then
                  q = (34289 - i)
                elseif (k == 45975) then
                  q = (34009 - i)
                elseif (44257 == k) then
                  q = (11002 - i)
                elseif ((k - 40512) == 0) then
                  q = (19647 - i)
                elseif (not (k ~= 37687)) then
                  q = (55126 - i)
                elseif (38220 == k) then
                  q = (12647 - i)
                elseif ((k - 38072) == 0) then
                  q = (19997 - i)
                elseif (not (k ~= 44743)) then
                  q = (36739 - i)
                elseif (not (k ~= 36184)) then
                  q = (62091 - i)
                elseif (44122 == k) then
                  q = (34429 - i)
                elseif ((k - 42407) == 0) then
                  q = (55791 - i)
                elseif ((k - 40708) == 0) then
                  q = (39749 - i)
                elseif (k == 36507) then
                  q = (58941 - i)
                elseif (k == 42269) then
                  q = (33799 - i)
                else
                  a()
                end
              elseif ((k - 34263) == 0) then
                q = (12472 - i)
              elseif ((k - 32791) == 0) then
                q = (41254 - i)
              elseif (31691 == k) then
                q = (54636 - i)
              elseif (not (k ~= 33786)) then
                q = (40589 - i)
              elseif (31897 == k) then
                q = (61076 - i)
              elseif (k == 32689) then
                q = (18737 - i)
              elseif (33937 == k) then
                q = (13452 - i)
              elseif (not (k ~= 32843)) then
                q = (40134 - i)
              elseif (k == 34752) then
                q = (16882 - i)
              elseif (32951 == k) then
                q = (60831 - i)
              elseif ((k - 34762) == 0) then
                q = (56141 - i)
              elseif (not (k ~= 33653)) then
                q = (20032 - i)
              elseif (not (k ~= 31758)) then
                q = (12052 - i)
              elseif (not (k ~= 34916)) then
                q = (14292 - i)
              elseif ((k - 33287) == 0) then
                q = (33764 - i)
              elseif (not (k ~= 34035)) then
                q = (61286 - i)
              elseif ((k - 32086) == 0) then
                q = (37719 - i)
              elseif (k == 32242) then
                q = (37789 - i)
              elseif (not (k ~= 33249)) then
                q = (17722 - i)
              else
                a()
              end
            else
              if (not (k > 56566)) then
                if ((k - 52199) == 0) then
                  q = (33869 - i)
                elseif ((k - 47563) == 0) then
                  q = (20102 - i)
                elseif (not (k ~= 46805)) then
                  q = (11212 - i)
                elseif ((k - 47006) == 0) then
                  q = (62056 - i)
                elseif (k == 49218) then
                  q = (59221 - i)
                elseif (49521 == k) then
                  q = (54426 - i)
                elseif (k == 50407) then
                  q = (38139 - i)
                elseif (49524 == k) then
                  q = (14782 - i)
                elseif (not (k ~= 53486)) then
                  q = (18282 - i)
                elseif (not (k ~= 46211)) then
                  q = (32889 - i)
                elseif (not (k ~= 51081)) then
                  q = (56876 - i)
                elseif (not (k ~= 48923)) then
                  q = (17022 - i)
                elseif ((k - 53787) == 0) then
                  q = (11317 - i)
                elseif (51953 == k) then
                  q = (13662 - i)
                elseif (k == 54277) then
                  q = (37859 - i)
                elseif (k == 52580) then
                  q = (60131 - i)
                elseif (56555 == k) then
                  q = (14222 - i)
                else
                  a()
                end
              elseif ((k - 60633) == 0) then
                q = (13557 - i)
              elseif (62490 == k) then
                q = (55336 - i)
              elseif (k == 61607) then
                q = (56001 - i)
              elseif (not (k ~= 64275)) then
                q = (40309 - i)
              elseif (61692 == k) then
                q = (19087 - i)
              elseif (62133 == k) then
                q = (32154 - i)
              elseif (k == 61727) then
                q = (11947 - i)
              elseif (61069 == k) then
                q = (59746 - i)
              elseif ((k - 64032) == 0) then
                q = (16812 - i)
              elseif (k == 64348) then
                q = (35724 - i)
              elseif (k == 64971) then
                q = (36914 - i)
              elseif (not (k ~= 57418)) then
                q = (36284 - i)
              elseif (k == 65222) then
                q = (58556 - i)
              elseif (k == 61704) then
                q = (59536 - i)
              elseif (k == 64560) then
                q = (58311 - i)
              elseif (not (k ~= 63280)) then
                q = (32714 - i)
              elseif ((k - 65075) == 0) then
                q = (37229 - i)
              elseif (62638 == k) then
                q = (13067 - i)
              else
                a()
              end
            end
          else
            if (not (j > 423)) then
              if ((j - 250) > 0) then
                if (j <= 339) then
                  if (not (j <= 287)) then
                    if (297 == j) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[5], {x, t})
                      q = (57646 - i)
                    elseif (j == 337) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[15], {x})
                      q = (w.u - i)
                    elseif ((j - 295) == 0) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[22], {x, t})
                      q = (57751 - i)
                    elseif (j == 326) then
                      c, x, p, m, t = h(d, e, 3, 3)
                      f(n[2], {x, 0, 0, c})
                      q = (34779 - i)
                    elseif (j == 309) then
                      c, x, p, m, t = h(d, e, 2, 3)
                      f(n[22], {x, t})
                      q = (20627 - i)
                    elseif ((j - 301) == 0) then
                      c, x, p, m, t = h(d, e, 4, 3)
                      f(n[18], {x, t, m})
                      q = (w.u - i)
                    elseif (not (j ~= 304)) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[6], {x, t})
                      q = (18247 - i)
                    elseif (not (j ~= 288)) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[1], {x, t})
                      q = (54041 - i)
                    elseif (j == 334) then
                      x, t, m, c, p = h(d, e, 3, 0)
                      f(n[5], {x, t})
                      q = (w.u - i)
                    elseif ((j - 289) == 0) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[20], {x, t, m})
                      q = (38384 - i)
                    elseif ((j - 305) == 0) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[5], {x, t})
                      q = (20172 - i)
                    elseif (j == 315) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[5], {x, t})
                      q = (64191 - i)
                    elseif ((j - 325) == 0) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[2], {x, 0, 0, c})
                      q = (15447 - i)
                    elseif (314 == j) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[2], {x, 0, 0, c})
                      q = (19297 - i)
                    elseif ((j - 294) == 0) then
                      c, x, p, m, t = h(d, e, 1, 3)
                      f(n[2], {x, 0, 0, c})
                      q = (w.u - i)
                    elseif (j == 318) then
                      c, x, p, m, t = h(d, e, 1, 3)
                      f(n[26], {x, t, m})
                      q = (w.u - i)
                    elseif (298 == j) then
                      t, p, c, x, m = h(d, e, 3, 2)
                      f(n[16], {x, t})
                      q = (60026 - i)
                    elseif (not (j ~= 308)) then
                      t, p, c, x, m = h(d, e, 2, 2)
                      f(n[5], {x, t})
                      q = (w.u - i)
                    else
                      a()
                    end
                  elseif (281 == j) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[1], {x, t})
                    q = (w.u - i)
                  elseif ((j - 268) == 0) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[16], {x, t})
                    q = (60376 - i)
                  elseif ((j - 277) == 0) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[26], {x, t, m})
                    q = (55406 - i)
                  elseif (284 == j) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[16], {x, t})
                    q = (32399 - i)
                  elseif (not (j ~= 266)) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                    q = (40939 - i)
                  elseif ((j - 251) == 0) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[22], {x, t})
                    q = (13872 - i)
                  elseif (j == 258) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[18], {x, t, m})
                    q = (36249 - i)
                  elseif (j == 285) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[15], {x})
                    q = (57401 - i)
                  elseif (not (j ~= 267)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[18], {x, t, m})
                    q = (12682 - i)
                  elseif (286 == j) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[5], {x, t})
                    q = (32784 - i)
                  elseif (not (j ~= 265)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[18], {x, t, m})
                    q = (55896 - i)
                  elseif (not (j ~= 259)) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[16], {x, t})
                    q = (37754 - i)
                  elseif (j == 254) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[1], {x, t})
                    q = (w.u - i)
                  elseif (262 == j) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[2], {x, 0, 0, c})
                    q = (11422 - i)
                  elseif (275 == j) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[15], {x})
                    q = (w.u - i)
                  else
                    a()
                  end
                elseif (374 >= j) then
                  if ((j - 363) == 0) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[42], {x, t, m})
                    q = (w.u - i)
                  elseif (not (j ~= 372)) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (18037 - i)
                  elseif (j == 370) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[22], {x, t})
                    q = (38874 - i)
                  elseif (not (j ~= 368)) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[1], {x, t})
                    q = (w.u - i)
                  elseif (356 == j) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[15], {x})
                    q = (41149 - i)
                  elseif ((j - 346) == 0) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (33554 - i)
                  elseif ((j - 341) == 0) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[3], {x})
                    q = (w.u - i)
                  elseif (not (j ~= 367)) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[18], {x, t, m})
                    q = (54006 - i)
                  elseif (not (j ~= 352)) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[20], {x, t, m})
                    q = (37964 - i)
                  elseif ((j - 353) == 0) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[49], {x})
                    q = (17442 - i)
                  elseif ((j - 349) == 0) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[3], {x})
                    q = (w.u - i)
                  elseif ((j - 360) == 0) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[15], {x})
                    q = (w.u - i)
                  elseif (365 == j) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[2], {x, 0, 0, c})
                    q = (58976 - i)
                  elseif (369 == j) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[43], {x, t})
                    q = (w.u - i)
                  elseif (342 == j) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                    q = (35164 - i)
                  elseif (j == 343) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[4], {x, t})
                    q = (33519 - i)
                  elseif ((j - 347) == 0) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[4], {x, t})
                    q = (11737 - i)
                  else
                    a()
                  end
                elseif (j == 409) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[5], {x, t})
                  q = (38104 - i)
                elseif (405 == j) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[22], {x, t})
                  q = (36984 - i)
                elseif (not (j ~= 400)) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[31], {x, t, m})
                  q = (62616 - i)
                elseif (j == 378) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[16], {x, t})
                  q = (41464 - i)
                elseif (418 == j) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[31], {x, t, m})
                  q = (w.u - i)
                elseif (j == 375) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[5], {x, t})
                  q = (42514 - i)
                elseif (j == 396) then
                  t, p, c, x, m = h(d, e, 3, 2)
                  f(n[22], {x, t})
                  q = (61321 - i)
                elseif ((j - 394) == 0) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[18], {x, t, m})
                  q = (20452 - i)
                elseif (not (j ~= 412)) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[20], {x, t, m})
                  q = (59921 - i)
                elseif ((j - 411) == 0) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[22], {x, t})
                  q = (32609 - i)
                elseif (not (j ~= 377)) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[16], {x, t})
                  q = (10372 - i)
                elseif (j == 402) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[16], {x, t})
                  q = (w.u - i)
                elseif ((j - 410) == 0) then
                  t, p, c, x, m = h(d, e, 3, 2)
                  f(n[6], {x, t})
                  q = (14257 - i)
                elseif (j == 413) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[15], {x})
                  q = (63701 - i)
                elseif ((j - 422) == 0) then
                  c, x, p, m, t = h(d, e, 3, 3)
                  f(n[4], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 381)) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[22], {x, t})
                  q = (63036 - i)
                elseif (416 == j) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[1], {x, t})
                  q = (42024 - i)
                elseif (j == 392) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[22], {x, t})
                  q = (14712 - i)
                else
                  a()
                end
              elseif ((172 - j) < 0) then
                if (((true and j) or 951) <= 210) then
                  if (j == 187) then
                    c, x, p, m, t = h(d, e, 3, 3)
                    f(n[5], {x, t})
                    q = (15972 - i)
                  elseif (j == 194) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[15], {x})
                    q = (33834 - i)
                  elseif ((j - 173) == 0) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (63911 - i)
                  elseif (j == 192) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[18], {x, t, m})
                    q = (16042 - i)
                  elseif (174 == j) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[20], {x, t, m})
                    q = (w.u - i)
                  elseif ((j - 209) == 0) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[17], {x, t})
                    q = (w.u - i)
                  elseif (202 == j) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (34149 - i)
                  elseif ((j - 208) == 0) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    return l(d, f(n[47], {x}, 2))
                  elseif ((j - 203) == 0) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[31], {x, t, m})
                    q = (12997 - i)
                  elseif (j == 180) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[22], {x, t})
                    q = (37474 - i)
                  elseif (not (j ~= 186)) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (62161 - i)
                  elseif (190 == j) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[22], {x, t})
                    q = (14922 - i)
                  elseif (not (j ~= 205)) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[22], {x, t})
                    q = (56246 - i)
                  elseif (not (j ~= 188)) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[22], {x, t})
                    q = (14537 - i)
                  elseif ((j - 201) == 0) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[11], {x})
                    q = (w.u - i)
                  elseif ((j - 189) == 0) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    local x, j = f(n[46], {x, 0, 0, 0, 0, g, u}, 9)
                    if (j == 1) then
                      g = x
                    elseif (j ~= 0) then
                      a()
                    end
                    q = (w.u - i)
                  elseif (not (j ~= 175)) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  else
                    a()
                  end
                elseif ((j - 228) == 0) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[1], {x, t})
                  q = (w.u - i)
                elseif ((j - 216) == 0) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[1], {x, t})
                  q = (16567 - i)
                elseif (232 == j) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[15], {x})
                  q = (w.u - i)
                elseif (not (j ~= 239)) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[22], {x, t})
                  q = (12402 - i)
                elseif ((j - 249) == 0) then
                  x, t, m, c, p = h(d, e, 3, 0)
                  f(n[22], {x, t})
                  q = (20242 - i)
                elseif (not (j ~= 219)) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[22], {x, t})
                  q = (41499 - i)
                elseif (not (j ~= 218)) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[16], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 233)) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[2], {x, 0, 0, c})
                  q = (20137 - i)
                elseif (not (j ~= 217)) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[2], {x, 0, 0, c})
                  q = (w.u - i)
                elseif (j == 240) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif (226 == j) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif ((j - 241) == 0) then
                  x, t, m, c, p = h(d, e, 3, 0)
                  f(n[2], {x, 0, 0, c})
                  q = (w.u - i)
                elseif (j == 235) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[6], {x, t})
                  q = (14082 - i)
                elseif (not (j ~= 236)) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[22], {x, t})
                  q = (63596 - i)
                elseif (not (j ~= 242)) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[35], {x, t})
                  q = (42269 - i)
                elseif (j == 234) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[2], {x, 0, 0, c})
                  q = (15027 - i)
                elseif (not (j ~= 213)) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[17], {x, t})
                  q = (16322 - i)
                elseif (not (j ~= 220)) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[2], {x, 0, 0, c})
                  q = (61111 - i)
                else
                  a()
                end
              elseif (136 < j) then
                if ((j - 154) > 0) then
                  if ((j - 166) == 0) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[13], {x, t, m})
                    q = (58626 - i)
                  elseif (164 == j) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[1], {x, t})
                    q = (35024 - i)
                  elseif ((j - 165) == 0) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[3], {x})
                    q = (16917 - i)
                  elseif ((j - 158) == 0) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[31], {x, t, m})
                    q = (w.u - i)
                  elseif (j == 171) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (40204 - i)
                  elseif (j == 159) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                    q = (38489 - i)
                  elseif (j == 156) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[11], {x})
                    q = (10582 - i)
                  elseif (not (j ~= 155)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[4], {x, t})
                    q = (36074 - i)
                  else
                    a()
                  end
                elseif (j == 142) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[11], {x})
                  q = (17687 - i)
                elseif (148 == j) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[15], {x})
                  q = (20417 - i)
                elseif ((j - 137) == 0) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[1], {x, t})
                  q = (w.u - i)
                elseif (j == 150) then
                  t, p, c, x, m = h(d, e, 3, 2)
                  f(n[1], {x, t})
                  q = (63176 - i)
                elseif ((j - 141) == 0) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[11], {x})
                  q = (16672 - i)
                elseif (not (j ~= 153)) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif ((j - 149) == 0) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[4], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 143)) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[22], {x, t})
                  q = (54951 - i)
                elseif (j == 146) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[22], {x, t})
                  q = (38804 - i)
                elseif (not (j ~= 147)) then
                  c, x, p, m, t = h(d, e, 3, 3)
                  f(n[22], {x, t})
                  q = (15937 - i)
                elseif (138 == j) then
                  t, p, c, x, m = h(d, e, 3, 2)
                  f(n[31], {x, t, m})
                  q = (32119 - i)
                else
                  a()
                end
              elseif ((j - 114) == 0) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[34], {x, t})
                q = (38419 - i)
              elseif (118 == j) then
                t, p, c, x, m = h(d, e, 4, 2)
                f(n[16], {x, t})
                q = (w.u - i)
              elseif (j == 104) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[2], {x, 0, 0, c})
                q = (63736 - i)
              elseif (j == 100) then
                c, x, p, m, t = h(d, e, 4, 3)
                f(n[31], {x, t, m})
                q = (w.u - i)
              elseif ((j - 131) == 0) then
                c, x, p, m, t = h(d, e, 4, 3)
                f(n[2], {x, 0, 0, c})
                q = (w.u - i)
              elseif (not (j ~= 103)) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[15], {x})
                q = (56071 - i)
              elseif ((j - 112) == 0) then
                t, p, c, x, m = h(d, e, 2, 2)
                f(n[18], {x, t, m})
                q = (39679 - i)
              elseif (not (j ~= 122)) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[5], {x, t})
                q = (12262 - i)
              elseif (not (j ~= 130)) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[22], {x, t})
                q = (53936 - i)
              elseif (j == 126) then
                x, t, m, c, p = h(d, e, 2, 0)
                f(n[1], {x, t})
                q = (55301 - i)
              elseif (j == 121) then
                t, p, c, x, m = h(d, e, 4, 2)
                f(n[22], {x, t})
                q = (w.u - i)
              elseif (101 == j) then
                c, x, p, m, t = h(d, e, 4, 3)
                f(n[32], {x, t, m})
                q = (w.u - i)
              elseif ((j - 119) == 0) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[4], {x, t})
                q = (w.u - i)
              elseif (116 == j) then
                t, p, c, x, m = h(d, e, 3, 2)
                f(n[2], {x, 0, 0, c})
                q = (13837 - i)
              elseif (108 == j) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[26], {x, t, m})
                q = (17057 - i)
              elseif ((j - 135) == 0) then
                p, m, x, c, t = h(d, e, 3, 1)
                f(n[22], {x, t})
                q = (35409 - i)
              else
                a()
              end
            elseif (((true and j) or 628) <= 714) then
              if ((j - 568) <= 0) then
                if (((true and j) or 944) <= 493) then
                  if (j > 453) then
                    if (j == 454) then
                      x, t, m, c, p = h(d, e, 2, 0)
                      f(n[18], {x, t, m})
                      q = (33099 - i)
                    elseif (j == 492) then
                      p, m, x, c, t = h(d, e, 2, 1)
                      f(n[4], {x, t})
                      q = (36494 - i)
                    elseif (j == 465) then
                      t, p, c, x, m = h(d, e, 1, 2)
                      f(n[28], {x, t, m})
                      q = (w.u - i)
                    elseif (457 == j) then
                      t, p, c, x, m = h(d, e, 4, 2)
                      f(n[22], {x, t})
                      q = (w.u - i)
                    elseif ((j - 471) == 0) then
                      x, t, m, c, p = h(d, e, 4, 0)
                      f(n[22], {x, t})
                      q = (w.u - i)
                    elseif (not (j ~= 473)) then
                      x, t, m, c, p = h(d, e, 3, 0)
                      f(n[22], {x, t})
                      q = (w.u - i)
                    elseif (not (j ~= 480)) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[22], {x, t})
                      q = (19402 - i)
                    elseif (j == 462) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[2], {x, 0, 0, c})
                      q = (59046 - i)
                    elseif (472 == j) then
                      x, t, m, c, p = h(d, e, 4, 0)
                      f(n[22], {x, t})
                      q = (w.u - i)
                    elseif (479 == j) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[8], {x, t, 0, 0, 0, z, 0, 0})
                      q = (w.u - i)
                    elseif ((j - 475) == 0) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[2], {x, 0, 0, c})
                      q = (15692 - i)
                    elseif ((j - 490) == 0) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[18], {x, t, m})
                      q = (10407 - i)
                    elseif (477 == j) then
                      c, x, p, m, t = h(d, e, 1, 3)
                      f(n[32], {x, t, m})
                      q = (w.u - i)
                    elseif ((j - 468) == 0) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[22], {x, t})
                      q = (63421 - i)
                    elseif (j == 474) then
                      t, p, c, x, m = h(d, e, 2, 2)
                      f(n[9], {x, 0, 0, c})
                      q = (15412 - i)
                    elseif (j == 478) then
                      x, t, m, c, p = h(d, e, 3, 0)
                      f(n[27], {x, t, m})
                      q = (w.u - i)
                    elseif (481 == j) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[9], {x, 0, 0, c})
                      q = (w.u - i)
                    else
                      a()
                    end
                  elseif ((j - 430) == 0) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (16847 - i)
                  elseif (425 == j) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[1], {x, t})
                    q = (35794 - i)
                  elseif (441 == j) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif ((j - 432) == 0) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[25], {x, t, m})
                    q = (w.u - i)
                  elseif (434 == j) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[4], {x, t})
                    q = (14992 - i)
                  elseif (not (j ~= 445)) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[6], {x, t})
                    q = (16602 - i)
                  elseif (448 == j) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[22], {x, t})
                    q = (57296 - i)
                  elseif ((j - 443) == 0) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[3], {x})
                    q = (17792 - i)
                  elseif (426 == j) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[9], {x, 0, 0, c})
                    q = (w.u - i)
                  elseif (not (j ~= 428)) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif (not (j ~= 431)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[15], {x})
                    q = (14852 - i)
                  elseif ((j - 451) == 0) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[22], {x, t})
                    q = (18877 - i)
                  elseif (449 == j) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[22], {x, t})
                    q = (39609 - i)
                  elseif (j == 435) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[22], {x, t})
                    q = (57891 - i)
                  elseif (not (j ~= 424)) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[5], {x, t})
                    q = (33589 - i)
                  elseif ((j - 439) == 0) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[9], {x, 0, 0, c})
                    q = (40239 - i)
                  elseif (not (j ~= 452)) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[2], {x, 0, 0, c})
                    q = (55056 - i)
                  else
                    a()
                  end
                elseif (534 >= j) then
                  if ((j - 498) == 0) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[2], {x, 0, 0, c})
                    q = (62721 - i)
                  elseif ((j - 532) == 0) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[9], {x, 0, 0, c})
                    q = (33729 - i)
                  elseif ((j - 499) == 0) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[14], {x, t, m})
                    q = (w.u - i)
                  elseif (not (j ~= 502)) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[4], {x, t})
                    q = (w.u - i)
                  elseif (not (j ~= 508)) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif (not (j ~= 495)) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[4], {x, t})
                    q = (37614 - i)
                  elseif (not (j ~= 527)) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                    q = (57121 - i)
                  elseif ((j - 496) == 0) then
                    c, x, p, m, t = h(d, e, 3, 3)
                    f(n[5], {x, t})
                    q = (55441 - i)
                  elseif ((j - 497) == 0) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif ((j - 506) == 0) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[9], {x, 0, 0, c})
                    q = (w.u - i)
                  elseif (not (j ~= 510)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[22], {x, t})
                    q = (11632 - i)
                  elseif (j == 530) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[31], {x, t, m})
                    q = (19052 - i)
                  elseif (511 == j) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[2], {x, 0, 0, c})
                    q = (34394 - i)
                  elseif (not (j ~= 503)) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[31], {x, t, m})
                    q = (w.u - i)
                  elseif (j == 520) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[18], {x, t, m})
                    q = (16777 - i)
                  elseif (not (j ~= 513)) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[19], {x, 0, 0, 0, 0, is, 0, 0, 0})
                    q = (w.u - i)
                  elseif (505 == j) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[10], {x, 0, 0, c})
                    q = (w.u - i)
                  else
                    a()
                  end
                elseif (not (j > 554)) then
                  if (not (j ~= 549)) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[22], {x, t})
                    q = (13732 - i)
                  elseif (not (j ~= 545)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    g = f(n[45], {0, 0, 0, 0, p, g, u}, 1)
                    q = (w.u - i)
                  elseif (j == 553) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[1], {x, t})
                    q = (59991 - i)
                  elseif ((j - 539) == 0) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[15], {x})
                    q = (w.u - i)
                  elseif (j == 551) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[22], {x, t})
                    q = (40974 - i)
                  elseif (j == 538) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (37124 - i)
                  elseif (540 == j) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[2], {x, 0, 0, c})
                    q = (39644 - i)
                  elseif (not (j ~= 548)) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[35], {x, t})
                    q = (w.u - i)
                  elseif (j == 547) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (34359 - i)
                  else
                    a()
                  end
                elseif (not (j ~= 562)) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[3], {x})
                  q = (37824 - i)
                elseif (555 == j) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[22], {x, t})
                  q = (39784 - i)
                elseif (j == 567) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[1], {x, t})
                  q = (w.u - i)
                elseif (558 == j) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[15], {x})
                  q = (13242 - i)
                elseif ((j - 561) == 0) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[16], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 566)) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[22], {x, t})
                  q = (42479 - i)
                elseif ((j - 565) == 0) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[1], {x, t})
                  q = (32924 - i)
                elseif ((j - 557) == 0) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[29], {x, t, m})
                  q = (42164 - i)
                elseif (564 == j) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[5], {x, t})
                  q = (63351 - i)
                elseif (not (j ~= 556)) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[17], {x, t})
                  q = (w.u - i)
                elseif (560 == j) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[1], {x, t})
                  q = (35234 - i)
                else
                  a()
                end
              elseif ((649 - j) < 0) then
                if ((((true and j) or 848) - 688) <= 0) then
                  if ((j - 654) == 0) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (10477 - i)
                  elseif (679 == j) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[31], {x, t, m})
                    q = (13627 - i)
                  elseif (686 == j) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif (j == 682) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[2], {x, 0, 0, c})
                    q = (57856 - i)
                  elseif (674 == j) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[22], {x, t})
                    q = (38559 - i)
                  elseif (j == 687) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[18], {x, t, m})
                    q = (10617 - i)
                  elseif ((j - 665) == 0) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[22], {x, t})
                    q = (60551 - i)
                  elseif (j == 662) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[2], {x, 0, 0, c})
                    q = (54671 - i)
                  elseif (not (j ~= 683)) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[18], {x, t, m})
                    q = (w.u - i)
                  elseif (not (j ~= 666)) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[15], {x})
                    q = (w.u - i)
                  elseif (677 == j) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[2], {x, 0, 0, c})
                    q = (54741 - i)
                  elseif (not (j ~= 652)) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[22], {x, t})
                    q = (34499 - i)
                  elseif (675 == j) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[15], {x})
                    q = (58591 - i)
                  elseif (not (j ~= 653)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    local x, t, w, j = f(n[48], {x, t}, 9)
                    j = (j or t)
                    if (j == 3) then
                      l(d, nil)
                      d, cx, z = x, t, w
                      break
                    elseif (j == 2) then
                      return l(d, x)
                    else
                      a()
                    end
                  elseif (j == 650) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif (not (j ~= 657)) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (38734 - i)
                  elseif (not (j ~= 676)) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[11], {x})
                    q = (15552 - i)
                  else
                    a()
                  end
                elseif (705 == j) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[2], {x, 0, 0, c})
                  q = (w.u - i)
                elseif (not (j ~= 707)) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[5], {x, t})
                  q = (10652 - i)
                elseif (not (j ~= 703)) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[22], {x, t})
                  q = (13942 - i)
                elseif (696 == j) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[1], {x, t})
                  q = (39889 - i)
                elseif (not (j ~= 711)) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[1], {x, t})
                  q = (40624 - i)
                elseif ((j - 695) == 0) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[5], {x, t})
                  q = (w.u - i)
                elseif ((j - 692) == 0) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[1], {x, t})
                  q = (56806 - i)
                elseif (not (j ~= 702)) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[39], {x, t})
                  q = (w.u - i)
                elseif (697 == j) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[22], {x, t})
                  q = (40554 - i)
                elseif (not (j ~= 708)) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[5], {x, t})
                  q = (64261 - i)
                elseif ((j - 693) == 0) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[13], {x, t, m})
                  q = (w.u - i)
                elseif ((j - 701) == 0) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif (710 == j) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[12], {x, t, m})
                  q = (w.u - i)
                elseif ((j - 709) == 0) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[3], {x})
                  q = (w.u - i)
                elseif (j == 690) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif ((j - 713) == 0) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[22], {x, t})
                  q = (60901 - i)
                elseif (704 == j) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif ((j - 689) == 0) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[22], {x, t})
                  q = (63491 - i)
                else
                  a()
                end
              elseif ((610 - j) >= 0) then
                if ((j - 604) == 0) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[2], {x, 0, 0, c})
                  q = (w.u - i)
                elseif ((j - 598) == 0) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[30], {x, t, m})
                  q = (w.u - i)
                elseif (not (j ~= 594)) then
                  c, x, p, m, t = h(d, e, 3, 3)
                  f(n[1], {x, t})
                  q = (20312 - i)
                elseif ((j - 591) == 0) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[22], {x, t})
                  q = (38174 - i)
                elseif (not (j ~= 605)) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[6], {x, t})
                  q = (60726 - i)
                elseif (not (j ~= 584)) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[13], {x, t, m})
                  q = (32994 - i)
                elseif (606 == j) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 575)) then
                  c, x, p, m, t = h(d, e, 3, 3)
                  f(n[1], {x, t})
                  q = (34324 - i)
                elseif (not (j ~= 599)) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[5], {x, t})
                  q = (41289 - i)
                elseif (597 == j) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[5], {x, t})
                  q = (14467 - i)
                elseif (not (j ~= 580)) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[22], {x, t})
                  q = (62861 - i)
                elseif (not (j ~= 574)) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[15], {x})
                  q = (15132 - i)
                elseif ((j - 595) == 0) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[18], {x, t, m})
                  q = (56281 - i)
                elseif (j == 607) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[22], {x, t})
                  q = (20487 - i)
                elseif ((j - 585) == 0) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[33], {x, t, m})
                  q = (w.u - i)
                elseif (593 == j) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[20], {x, t, m})
                  q = (w.u - i)
                elseif (j == 587) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[18], {x, t, m})
                  q = (w.u - i)
                elseif (588 == j) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[38], {x})
                  q = (w.u - i)
                else
                  a()
                end
              elseif (j == 631) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[22], {x, t})
                q = (54076 - i)
              elseif (not (j ~= 633)) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[15], {x})
                q = (63771 - i)
              elseif (j == 637) then
                x, t, m, c, p = h(d, e, 3, 0)
                f(n[4], {x, t})
                q = (11142 - i)
              elseif (626 == j) then
                p, m, x, c, t = h(d, e, 2, 1)
                f(n[15], {x})
                q = (56386 - i)
              elseif (625 == j) then
                p, m, x, c, t = h(d, e, 1, 1)
                f(n[29], {x, t, m})
                q = (w.u - i)
              elseif (not (j ~= 629)) then
                x, t, m, c, p = h(d, e, 1, 0)
                f(n[9], {x, 0, 0, c})
                q = (41639 - i)
              elseif (612 == j) then
                c, x, p, m, t = h(d, e, 1, 3)
                f(n[15], {x})
                q = (57226 - i)
              elseif ((j - 647) == 0) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[38], {x})
                q = (w.u - i)
              elseif (611 == j) then
                t, p, c, x, m = h(d, e, 3, 2)
                f(n[20], {x, t, m})
                q = (40169 - i)
              elseif (j == 645) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[15], {x})
                q = (64051 - i)
              elseif (j == 616) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[22], {x, t})
                q = (36634 - i)
              elseif (643 == j) then
                c, x, p, m, t = h(d, e, 1, 3)
                f(n[49], {x})
                q = (w.u - i)
              elseif (not (j ~= 618)) then
                c, x, p, m, t = h(d, e, 1, 3)
                f(n[9], {x, 0, 0, c})
                q = (15237 - i)
              elseif (not (j ~= 634)) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[2], {x, 0, 0, c})
                q = (41744 - i)
              elseif (632 == j) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[31], {x, t, m})
                q = (55091 - i)
              elseif (619 == j) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[5], {x, t})
                q = (39014 - i)
              else
                a()
              end
            else
              if (857 >= j) then
                if (j > 789) then
                  if (((true and j) or 864) <= 823) then
                    if (803 == j) then
                      t, p, c, x, m = h(d, e, 1, 2)
                      f(n[13], {x, t, m})
                      q = (37299 - i)
                    elseif (j == 819) then
                      t, p, c, x, m = h(d, e, 1, 2)
                      f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                      q = (w.u - i)
                    elseif (not (j ~= 802)) then
                      t, p, c, x, m = h(d, e, 4, 2)
                      f(n[2], {x, 0, 0, c})
                      q = (w.u - i)
                    elseif (not (j ~= 796)) then
                      c, x, p, m, t = h(d, e, 2, 3)
                      f(n[22], {x, t})
                      q = (19017 - i)
                    elseif (808 == j) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[22], {x, t})
                      q = (34534 - i)
                    elseif ((j - 805) == 0) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[2], {x, 0, 0, c})
                      q = (19822 - i)
                    elseif (j == 817) then
                      x, t, m, c, p = h(d, e, 3, 0)
                      f(n[27], {x, t, m})
                      q = (38349 - i)
                    elseif (795 == j) then
                      t, p, c, x, m = h(d, e, 4, 2)
                      f(n[15], {x})
                      q = (w.u - i)
                    elseif (not (j ~= 821)) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[15], {x})
                      q = (10897 - i)
                    elseif (j == 804) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[22], {x, t})
                      q = (37089 - i)
                    elseif ((j - 793) == 0) then
                      x, t, m, c, p = h(d, e, 1, 0)
                      f(n[6], {x, t})
                      q = (37404 - i)
                    elseif (not (j ~= 809)) then
                      x, t, m, c, p = h(d, e, 3, 0)
                      f(n[1], {x, t})
                      q = (32504 - i)
                    elseif (791 == j) then
                      c, x, p, m, t = h(d, e, 1, 3)
                      f(n[8], {x, t, 0, 0, 0, z, 0, 0})
                      q = (58661 - i)
                    elseif (not (j ~= 790)) then
                      p, m, x, c, t = h(d, e, 3, 1)
                      f(n[6], {x, t})
                      q = (58451 - i)
                    elseif (810 == j) then
                      p, m, x, c, t = h(d, e, 4, 1)
                      f(n[1], {x, t})
                      q = (w.u - i)
                    elseif (799 == j) then
                      x, t, m, c, p = h(d, e, 3, 0)
                      f(n[22], {x, t})
                      q = (w.u - i)
                    elseif (not (j ~= 792)) then
                      t, p, c, x, m = h(d, e, 2, 2)
                      f(n[22], {x, t})
                      q = (63946 - i)
                    elseif (not (j ~= 816)) then
                      p, m, x, c, t = h(d, e, 1, 1)
                      f(n[6], {x, t})
                      q = (w.u - i)
                    else
                      a()
                    end
                  elseif (not (j ~= 837)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[2], {x, 0, 0, c})
                    q = (62966 - i)
                  elseif ((j - 848) == 0) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[13], {x, t, m})
                    q = (w.u - i)
                  elseif (not (j ~= 854)) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[40], {x})
                    q = (w.u - i)
                  elseif (j == 836) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[16], {x, t})
                    q = (w.u - i)
                  elseif (j == 849) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[1], {x, t})
                    q = (13137 - i)
                  elseif ((j - 833) == 0) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif (j == 853) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif ((j - 842) == 0) then
                    c, x, p, m, t = h(d, e, 2, 3)
                    f(n[22], {x, t})
                    q = (17547 - i)
                  elseif (j == 855) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[20], {x, t, m})
                    q = (63281 - i)
                  elseif ((j - 841) == 0) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[37], {x})
                    q = (w.u - i)
                  elseif (not (j ~= 829)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[23], {x, t, m})
                    q = (w.u - i)
                  elseif ((j - 847) == 0) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[16], {x, t})
                    q = (13172 - i)
                  elseif (not (j ~= 850)) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[22], {x, t})
                    q = (19122 - i)
                  elseif (not (j ~= 834)) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[24], {x, t, m})
                    q = (w.u - i)
                  elseif (825 == j) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[4], {x, t})
                    q = (36319 - i)
                  elseif (not (j ~= 843)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[16], {x, t})
                    q = (17267 - i)
                  elseif (not (j ~= 839)) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[31], {x, t, m})
                    q = (12017 - i)
                  elseif (not (j ~= 844)) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[1], {x, t})
                    q = (w.u - i)
                  else
                    a()
                  end
                elseif (not (((true and j) or 763) <= 750)) then
                  if (not (j ~= 758)) then
                    c, x, p, m, t = h(d, e, 3, 3)
                    f(n[22], {x, t})
                    q = (11597 - i)
                  elseif (784 == j) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[17], {x, t})
                    q = (18912 - i)
                  elseif (j == 762) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[27], {x, t, m})
                    q = (w.u - i)
                  elseif (773 == j) then
                    c, x, p, m, t = h(d, e, 3, 3)
                    f(n[15], {x})
                    q = (58906 - i)
                  elseif (not (j ~= 763)) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[2], {x, 0, 0, c})
                    q = (w.u - i)
                  elseif (j == 783) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[1], {x, t})
                    q = (w.u - i)
                  elseif (j == 753) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[36], {x, t})
                    q = (w.u - i)
                  elseif (770 == j) then
                    c, x, p, m, t = h(d, e, 1, 3)
                    f(n[31], {x, t, m})
                    q = (35549 - i)
                  elseif (not (j ~= 785)) then
                    x, t, m, c, p = h(d, e, 2, 0)
                    f(n[22], {x, t})
                    q = (59711 - i)
                  elseif (j == 788) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[22], {x, t})
                    q = (58136 - i)
                  elseif (j == 787) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[9], {x, 0, 0, c})
                    q = (41044 - i)
                  elseif (not (j ~= 775)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                    q = (35304 - i)
                  elseif (not (j ~= 752)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[22], {x, t})
                    q = (34849 - i)
                  elseif ((j - 757) == 0) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[16], {x, t})
                    q = (13802 - i)
                  elseif (not (j ~= 769)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[4], {x, t})
                    q = (61531 - i)
                  elseif ((j - 765) == 0) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[22], {x, t})
                    q = (35059 - i)
                  elseif (not (j ~= 754)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[22], {x, t})
                    q = (38909 - i)
                  else
                    a()
                  end
                elseif ((j - 716) == 0) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[16], {x, t})
                  q = (55511 - i)
                elseif ((j - 728) == 0) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[16], {x, t})
                  q = (w.u - i)
                elseif (j == 741) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[15], {x})
                  q = (15307 - i)
                elseif (718 == j) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[6], {x, t})
                  q = (33029 - i)
                elseif (not (j ~= 742)) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[31], {x, t, m})
                  q = (w.u - i)
                elseif ((j - 719) == 0) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[18], {x, t, m})
                  q = (13522 - i)
                elseif (not (j ~= 715)) then
                  t, p, c, x, m = h(d, e, 1, 2)
                  f(n[18], {x, t, m})
                  q = (38664 - i)
                elseif ((j - 724) == 0) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[2], {x, 0, 0, c})
                  q = (12122 - i)
                elseif (j == 729) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[2], {x, 0, 0, c})
                  q = (40869 - i)
                elseif (j == 746) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[2], {x, 0, 0, c})
                  q = (38454 - i)
                elseif ((j - 720) == 0) then
                  t, p, c, x, m = h(d, e, 3, 2)
                  f(n[22], {x, t})
                  q = (57436 - i)
                elseif (727 == j) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[16], {x, t})
                  q = (36599 - i)
                elseif (not (j ~= 739)) then
                  c, x, p, m, t = h(d, e, 2, 3)
                  f(n[22], {x, t})
                  q = (40659 - i)
                elseif (j == 726) then
                  x, t, m, c, p = h(d, e, 3, 0)
                  f(n[20], {x, t, m})
                  q = (w.u - i)
                elseif (j == 747) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[5], {x, t})
                  q = (w.u - i)
                elseif ((j - 743) == 0) then
                  x, t, m, c, p = h(d, e, 2, 0)
                  f(n[22], {x, t})
                  q = (17582 - i)
                elseif (730 == j) then
                  c, x, p, m, t = h(d, e, 3, 3)
                  f(n[6], {x, t})
                  q = (33274 - i)
                elseif ((j - 737) == 0) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[1], {x, t})
                  q = (18177 - i)
                else
                  a()
                end
              elseif (j <= 927) then
                if (j > 896) then
                  if ((j - 907) == 0) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[22], {x, t})
                    q = (33449 - i)
                  elseif ((j - 906) == 0) then
                    t, p, c, x, m = h(d, e, 3, 2)
                    f(n[15], {x})
                    q = (w.u - i)
                  elseif (900 == j) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[5], {x, t})
                    q = (54286 - i)
                  elseif (924 == j) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[22], {x, t})
                    q = (13347 - i)
                  elseif ((j - 913) == 0) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[22], {x, t})
                    q = (18632 - i)
                  elseif (917 == j) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[18], {x, t, m})
                    q = (w.u - i)
                  elseif (not (j ~= 911)) then
                    p, m, x, c, t = h(d, e, 1, 1)
                    f(n[4], {x, t})
                    q = (42374 - i)
                  elseif (j == 925) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[41], {x, t})
                    q = (w.u - i)
                  elseif (not (j ~= 921)) then
                    t, p, c, x, m = h(d, e, 1, 2)
                    f(n[34], {x, t})
                    q = (w.u - i)
                  elseif (897 == j) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[22], {x, t})
                    q = (42304 - i)
                  elseif (not (j ~= 908)) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif ((j - 902) == 0) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[11], {x})
                    q = (w.u - i)
                  elseif (not (j ~= 926)) then
                    c, x, p, m, t = h(d, e, 4, 3)
                    f(n[4], {x, t})
                    q = (w.u - i)
                  elseif (j == 919) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[1], {x, t})
                    q = (14117 - i)
                  elseif (j == 922) then
                    p, m, x, c, t = h(d, e, 3, 1)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif ((j - 916) == 0) then
                    x, t, m, c, p = h(d, e, 4, 0)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  else
                    a()
                  end
                elseif (not (j > 874)) then
                  if (j == 867) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[22], {x, t})
                    q = (61146 - i)
                  elseif (j == 858) then
                    p, m, x, c, t = h(d, e, 2, 1)
                    f(n[22], {x, t})
                    q = (57051 - i)
                  elseif (871 == j) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  elseif (not (j ~= 869)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[22], {x, t})
                    q = (40344 - i)
                  elseif ((j - 861) == 0) then
                    t, p, c, x, m = h(d, e, 2, 2)
                    f(n[15], {x})
                    q = (13767 - i)
                  elseif (j == 865) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[25], {x, t, m})
                    q = (w.u - i)
                  elseif (868 == j) then
                    x, t, m, c, p = h(d, e, 3, 0)
                    f(n[2], {x, 0, 0, c})
                    q = (57471 - i)
                  elseif ((j - 866) == 0) then
                    t, p, c, x, m = h(d, e, 4, 2)
                    f(n[21], {x, 0, 0, c, 0, z, 0, 0})
                    q = (w.u - i)
                  elseif (not (j ~= 873)) then
                    x, t, m, c, p = h(d, e, 1, 0)
                    f(n[13], {x, t, m})
                    q = (61181 - i)
                  elseif ((j - 864) == 0) then
                    p, m, x, c, t = h(d, e, 4, 1)
                    f(n[22], {x, t})
                    q = (w.u - i)
                  else
                    a()
                  end
                elseif (not (j ~= 892)) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif ((j - 877) == 0) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[15], {x})
                  q = (w.u - i)
                elseif ((j - 891) == 0) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[5], {x, t})
                  q = (w.u - i)
                elseif ((j - 876) == 0) then
                  t, p, c, x, m = h(d, e, 3, 2)
                  f(n[5], {x, t})
                  q = (11247 - i)
                elseif (884 == j) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[18], {x, t, m})
                  q = (59781 - i)
                elseif (j == 875) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[16], {x, t})
                  q = (59116 - i)
                elseif (j == 894) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[22], {x, t})
                  q = (12087 - i)
                elseif (j == 878) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[1], {x, t})
                  q = (w.u - i)
                elseif (890 == j) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[22], {x, t})
                  q = (39574 - i)
                elseif ((j - 893) == 0) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[5], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 895)) then
                  p, m, x, c, t = h(d, e, 2, 1)
                  f(n[5], {x, t})
                  q = (35759 - i)
                else
                  a()
                end
              elseif (not (j <= 972)) then
                if (not (j ~= 983)) then
                  p, m, x, c, t = h(d, e, 3, 1)
                  f(n[22], {x, t})
                  q = (20662 - i)
                elseif (995 == j) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[22], {x, t})
                  q = (33239 - i)
                elseif (988 == j) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[7], {x, t, 0, 0, 0, z, 0, 0})
                  q = (w.u - i)
                elseif ((j - 991) == 0) then
                  p, m, x, c, t = h(d, e, 4, 1)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif ((j - 982) == 0) then
                  x, t, m, c, p = h(d, e, 1, 0)
                  f(n[2], {x, 0, 0, c})
                  q = (62791 - i)
                elseif (j == 980) then
                  c, x, p, m, t = h(d, e, 4, 3)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif (j == 981) then
                  t, p, c, x, m = h(d, e, 4, 2)
                  f(n[9], {x, 0, 0, c})
                  q = (w.u - i)
                elseif ((j - 987) == 0) then
                  t, p, c, x, m = h(d, e, 2, 2)
                  f(n[22], {x, t})
                  q = (12822 - i)
                elseif (not (j ~= 993)) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[2], {x, 0, 0, c})
                  q = (w.u - i)
                elseif ((j - 978) == 0) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[15], {x})
                  q = (57016 - i)
                elseif (j == 989) then
                  c, x, p, m, t = h(d, e, 1, 3)
                  f(n[18], {x, t, m})
                  q = (41324 - i)
                elseif ((j - 984) == 0) then
                  x, t, m, c, p = h(d, e, 4, 0)
                  f(n[22], {x, t})
                  q = (w.u - i)
                elseif (not (j ~= 974)) then
                  x, t, m, c, p = h(d, e, 3, 0)
                  f(n[3], {x})
                  q = (11037 - i)
                elseif (not (j ~= 997)) then
                  p, m, x, c, t = h(d, e, 1, 1)
                  f(n[22], {x, t})
                  q = (19472 - i)
                else
                  a()
                end
              elseif ((j - 949) == 0) then
                t, p, c, x, m = h(d, e, 3, 2)
                f(n[2], {x, 0, 0, c})
                q = (w.u - i)
              elseif (j == 965) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[15], {x})
                q = (w.u - i)
              elseif (not (j ~= 956)) then
                p, m, x, c, t = h(d, e, 1, 1)
                f(n[22], {x, t})
                q = (55476 - i)
              elseif (928 == j) then
                c, x, p, m, t = h(d, e, 1, 3)
                f(n[35], {x, t})
                q = (w.u - i)
              elseif (not (j ~= 929)) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[22], {x, t})
                q = (62511 - i)
              elseif (j == 962) then
                x, t, m, c, p = h(d, e, 2, 0)
                f(n[22], {x, t})
                q = (63806 - i)
              elseif (959 == j) then
                p, m, x, c, t = h(d, e, 2, 1)
                f(n[22], {x, t})
                q = (19577 - i)
              elseif (not (j ~= 966)) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[22], {x, t})
                q = (15342 - i)
              elseif (not (j ~= 958)) then
                t, p, c, x, m = h(d, e, 4, 2)
                f(n[22], {x, t})
                q = (w.u - i)
              elseif ((j - 938) == 0) then
                t, p, c, x, m = h(d, e, 4, 2)
                f(n[1], {x, t})
                q = (w.u - i)
              elseif (931 == j) then
                c, x, p, m, t = h(d, e, 4, 3)
                f(n[22], {x, t})
                q = (w.u - i)
              elseif (j == 933) then
                p, m, x, c, t = h(d, e, 1, 1)
                f(n[18], {x, t, m})
                q = (w.u - i)
              elseif ((j - 940) == 0) then
                t, p, c, x, m = h(d, e, 1, 2)
                f(n[2], {x, 0, 0, c})
                q = (63526 - i)
              elseif (j == 963) then
                p, m, x, c, t = h(d, e, 2, 1)
                f(n[23], {x, t, m})
                q = (34464 - i)
              elseif ((j - 934) == 0) then
                p, m, x, c, t = h(d, e, 3, 1)
                f(n[24], {x, t, m})
                q = (w.u - i)
              elseif ((j - 967) == 0) then
                c, x, p, m, t = h(d, e, 2, 3)
                f(n[22], {x, t})
                q = (37894 - i)
              elseif (951 == j) then
                p, m, x, c, t = h(d, e, 1, 1)
                f(n[6], {x, t})
                q = (61916 - i)
              elseif (j == 930) then
                c, x, p, m, t = h(d, e, 3, 3)
                f(n[16], {x, t})
                q = (32819 - i)
              else
                a()
              end
            end
          end
          if (((q - w.u) + i) == 0) then
            y = ((((s.h % 2) == 0) and ((535 + s.h) % w.ab)) or ((704 + s.h) % w.ab))
          end
        else
          a()
        end
      end
    end
  end
  return t
end,
  [901] = function(q, x, i, c, l, qa, di, k, m, e, p, a, n, s, g, f, h, t)
  local j = {}
  local d = function(x, i, t, q)
    local j = 282
    while true do
      if (not (j ~= 282)) then
        do
          if (true and true) then
            x = (((x - (((((63938 + ((((i + q) * (t + 1)) % w.aa) * 51694)) + (q * 40086)) + (i * 43325)) + (t * 1442)) % w.aa)) * 62411) % w.aa)
            j = 316
          else
            repeat
              x = ((((((x * 57) + i) + t) + q) + 12195) % w.aa)
              j = 727
              break
            until false
          end
        end
      elseif (316 == j) then
        do
          do
            do
              x = (((x - ((((((t * 40379) + (i * 54123)) + (q * 6306)) + 20056) + ((((i + q) * (t + 1)) % w.aa) * 36514)) % w.aa)) * 44347) % w.aa)
              j = 291
            end
          end
        end
      elseif (not (j ~= 205)) then
        return x
      elseif (727 == j) then
        repeat
          x = (((((x * 65) + (i * (t + 1))) + q) + 7550) % w.aa)
          t = (((t + x) + 7550) % w.aa)
          j = 773
          break
        until false
      elseif (not (j ~= 291)) then
        do
          if (((q % 1) == 1) or (t < 0)) then
            repeat
              x = ((((((x * 23) + i) + t) + q) + 27983) % w.aa)
              j = 957
              break
            until false
          else
            else
              x = (((x - (((((54654 + (q * 59410)) + ((((i + q) * (t + 1)) % w.aa) * 52757)) + (t * 8644)) + (i * 46204)) % w.aa)) * 417) % w.aa)
              j = 205
            end
          end
        end
      elseif ((j - 773) == 0) then
        repeat
          x = (((((x * 45) + (i * (t + 1))) + q) + 46794) % w.aa)
          t = (((t + x) + 46794) % w.aa)
          j = 957
          break
        until false
      elseif (not (j ~= 957)) then
        repeat
          x = (((((x * 55) + (i * (t + 1))) + q) + 59393) % w.aa)
          t = (((t + x) + 59393) % w.aa)
          j = 727
          break
        until false
      else
        c()
      end
    end
  end
  local o = function(j, i, t, q, k)
    local x = 175
    while true do
      if (264 == x) then
        do
          if (((q % 1) == 0) and ((k % 1) == 0)) then
            else
              if (true and true) then
                j = (((j - (((((((k * 1084) + (t * 46101)) + (q * 20681)) + ((((i * t) + (q * k)) % w.aa) * 49113)) + 22997) + (i * 59271)) % w.aa)) * 50635) % w.aa)
                x = 994
              else
                repeat
                  j = (((((((j * 35) + i) + t) + q) + k) + 15595) % w.aa)
                  x = 347
                  break
                until false
              end
            end
          else
            repeat
              j = (((((((j * 43) + i) + t) + q) + k) + 59587) % w.aa)
              x = 190
              break
            until false
          end
        end
      elseif (not (x ~= 331)) then
        if (((q % 1) == 0) and ((k % 1) == 0)) then
          if (((q % 1) == 1) or (k < 0)) then
            repeat
              j = (((((((j * 27) + i) + t) + q) + k) + 60196) % w.aa)
              x = 154
              break
            until false
          else
            if (false or false) then
              repeat
                j = (((((((j * 45) + i) + t) + q) + k) + 19509) % w.aa)
                x = 507
                break
              until false
            else
              if (((q % 1) == 0) and ((k % 1) == 0)) then
                j = (((j - (((((((i * 62865) + (k * 46381)) + (q * 43824)) + ((((i * t) + (q * k)) % w.aa) * 1199)) + (t * 10515)) + 34510) % w.aa)) * 21275) % w.aa)
                x = 341
              else
                repeat
                  j = (((((((j * 27) + i) + t) + q) + k) + 7795) % w.aa)
                  x = 190
                  break
                until false
              end
            end
          end
        else
          repeat
            j = (((((((j * 53) + i) + t) + q) + k) + 1252) % w.aa)
            x = 190
            break
          until false
        end
      elseif (x == 347) then
        repeat
          j = (((((j * 83) + (i * t)) + (q * k)) + 1098) % w.aa)
          t = (((t + j) + 1098) % w.aa)
          x = 507
          break
        until false
      elseif (x == 154) then
        repeat
          j = (((((j * 89) + (i * t)) + (q * k)) + 57319) % w.aa)
          t = (((t + j) + 57319) % w.aa)
          x = 347
          break
        until false
      elseif (994 == x) then
        if (((true and j) or 0) ~= j) then
          repeat
            j = (((((((j * 11) + i) + t) + q) + k) + 62651) % w.aa)
            x = 154
            break
          until false
        else
          else
            else
              if (((q % 1) == 1) or (k < 0)) then
                repeat
                  j = (((((((j * 3) + i) + t) + q) + k) + 45404) % w.aa)
                  x = 507
                  break
                until false
              else
                j = (((j - (((((((i * 36621) + ((((i * t) + (q * k)) % w.aa) * 1491)) + 8524) + (k * 2334)) + (t * 41461)) + (q * 17167)) % w.aa)) * 50901) % w.aa)
                x = 331
              end
            end
          end
        end
      elseif (190 == x) then
        repeat
          j = (((((j * 33) + (i * t)) + (q * k)) + 48892) % w.aa)
          t = (((t + j) + 48892) % w.aa)
          x = 154
          break
        until false
      elseif (x == 341) then
        return j
      elseif (x == 175) then
        else
          do
            else
              do
                if (((q % 1) == 1) or (k < 0)) then
                  repeat
                    j = (((((((j * 13) + i) + t) + q) + k) + 51004) % w.aa)
                    x = 347
                    break
                  until false
                else
                  j = (((j - (((((((i * 10520) + (q * 19385)) + (k * 50741)) + ((((i * t) + (q * k)) % w.aa) * 46615)) + (t * 32792)) + 38538) % w.aa)) * 11109) % w.aa)
                  x = 562
                end
              end
            end
          end
        end
      elseif ((x - 507) == 0) then
        repeat
          j = (((((j * 71) + (i * t)) + (q * k)) + 59053) % w.aa)
          t = (((t + j) + 59053) % w.aa)
          x = 888
          break
        until false
      elseif (not (x ~= 562)) then
        do
          if (((q % 1) == 0) and ((k % 1) == 0)) then
            if (((true and j) or 0) ~= j) then
              repeat
                j = (((((((j * 5) + i) + t) + q) + k) + 42202) % w.aa)
                x = 347
                break
              until false
            else
              if (false or false) then
                repeat
                  j = (((((((j * 53) + i) + t) + q) + k) + 12702) % w.aa)
                  x = 154
                  break
                until false
              else
                if (true and true) then
                  j = (((j - ((((((47761 + (q * 20548)) + ((((i * t) + (q * k)) % w.aa) * 12540)) + (k * 10636)) + (t * 30423)) + (i * 13293)) % w.aa)) * 57261) % w.aa)
                  x = 264
                else
                  repeat
                    j = (((((((j * 33) + i) + t) + q) + k) + 47233) % w.aa)
                    x = 347
                    break
                  until false
                end
              end
            end
          else
            repeat
              j = (((((((j * 27) + i) + t) + q) + k) + 17628) % w.aa)
              x = 190
              break
            until false
          end
        end
      elseif (not (x ~= 888)) then
        repeat
          j = (((((j * 47) + (i * t)) + (q * k)) + 45030) % w.aa)
          t = (((t + j) + 45030) % w.aa)
          x = 190
          break
        until false
      else
        c()
      end
    end
  end
  local b = function(k, x, i, c)
    local m = (((k * 1) + 2) % 4)
    local t = (((k * 2) + 0) % 3)
    local d = (((k * 111) + 2405) % 2731)
    local q = (6 + (d * 13))
    j[5], j[26], j[30], v = 0, 0, 0, 0
    if (m == 0) then
      v = x[(q + (((i - 1) + t) % 4))]
      j[5] = (v % w.e)
      v = ((v - j[5]) / w.e)
      j[26] = (v % w.e)
      j[30] = ((v - j[26]) / w.e)
    elseif (m == 1) then
      local t = ((q + 4) - i)
      v = x[t]
      j[5] = (v % w.e)
      j[30] = ((v - j[5]) / w.e)
      j[26] = x[(t + 4)]
    elseif (m == 2) then
      j[5] = x[(((q + i) - 1) + (t * 4))]
      j[26] = x[(((q + i) - 1) + (((t + 1) % 3) * 4))]
      j[30] = x[(((q + i) - 1) + (((t + 2) % 3) * 4))]
    else
      v = x[((q + 4) - i)]
      j[5] = v[(1 + t)]
      j[26] = v[(1 + ((t + 1) % 3))]
      j[30] = v[(1 + ((t + 2) % 3))]
    end
    j[53] = (j[26] + (j[30] * w.e))
    j[19] = (j[5] + (j[53] * w.e))
    if (c == 0) then
      return j[5], j[26], j[30], j[53], j[19]
    elseif (c == 1) then
      return j[19], j[30], j[5], j[53], j[26]
    elseif (c == 2) then
      return j[26], j[19], j[53], j[5], j[30]
    else
      return j[53], j[5], j[19], j[30], j[26]
    end
  end
  local w = function(x)
    j[13] = q[x]
    j[97] = j[13].l
    if (t(j[97]) == t(q)) then
      return j[97]
    end
    j[21] = 1
    local a = (((x * 1) + 2) % 4)
    local m = (((x * 2) + 0) % 3)
    local pk = (((x * 111) + 2405) % 2731)
    local e = (6 + (pk * 13))
    local t = (((x * 11) + 4) % 24)
    local cx = ((t - (t % 6)) / 6)
    t = (t % 6)
    local is = ((t - (t % 2)) / 2)
    local uh = (t % 2)
    local s = {0, 1, 2, 3}
    local mp = {cx, is, uh, 0}
    local u = {0, 0, 0, 0}
    for t = 1, 4 do
      local w = mp[t]
      local j = 0
      for x = 1, 4 do
        if (s[x] >= 0) then
          if (j == w) then
            u[t] = s[x]
            s[x] = -1
            break
          end
          j = (j + 1)
        end
      end
    end
    local p = {0, 0, 0, 0}
    for j = 1, 4 do
      p[(u[j] + 1)] = j
    end
    local k = function()
      j[5], j[26] = i(j[97], j[21]), i(j[97], (j[21] + 1))
      if (j[26] == nil) then
        c()
      end
      j[21] = (j[21] + 2)
      return (j[5] + (j[26] * w.e))
    end
    local h = (h(j[97]) - 4)
    if (h < 0) then
      c()
    end
    local g = (h - n(j[97], (h + 1)))
    if (g < 0) then
      c()
    end
    if (j[13].x > 0) then
      local t, x = {{}}, {{}}
      local w, i = f(j[97], j[13].x, nil, t, x, nil)
      if ((w ~= (h - g)) or (i ~= j[13].x)) then
        c()
      end
      j[13].g = x
    else
      j[13].g = {{}}
    end
    local n = k()
    if ((n == 0) or (n > 512)) then
      c()
    end
    local z = {}
    local r = {}
    for x = 1, n do
      local t = k()
      local q = i(j[97], j[21])
      j[21] = (j[21] + 1)
      if (((((t == 0) or (q == nil)) or (q < 1)) or (q > 4)) or (z[t] ~= nil)) then
        c()
      end
      local m = {}
      for k = 0, (q - 1) do
        local d = i(j[97], j[21])
        j[21] = (j[21] + 1)
        if (d == nil) then
          c()
        end
        local x = ((d - ((((t * 37) + ((k * 2) * 47)) + 15) % w.e)) % w.e)
        local i = i(j[97], j[21])
        j[21] = (j[21] + 1)
        if (i == nil) then
          c()
        end
        i = ((i - ((((t * 37) + (((k * 2) + 1) * 47)) + 15) % 8)) % 8)
        if ((i > 4) or ((k < (q - 1)) and ((((x == 149) or (x == 65)) or (x == 98)) or (x == 43)))) then
          c()
        end
        m[(k + 1)] = (x + (i * w.e))
      end
      z[t] = m
    end
    local f = k()
    local i = {}
    local y = (((((x * 7919) + (n * 4099)) + (f * 131)) + 15) % 2147483647)
    for f = 0, (j[13].q - 1) do
      local b, u, di, pk = k(), k(), k(), k()
      local n = {b, u, di, pk}
      local t = n[p[1]]
      local s = n[p[2]]
      local g = n[p[3]]
      local p = n[p[4]]
      local cx = d(s, t, x, 0)
      local is = d(g, t, x, 1)
      local o = o(p, t, cx, is, x)
      y = (((((y * 213) + (p * 1031)) + (f * 7517)) + 15) % 2147483647)
      local d = z[o]
      if (((t == 0) or (i[t] ~= nil)) or (d == nil)) then
        c()
      end
      local z = ((((t * 37) + (p * 22626)) + (x * 24166)) % w.ab)
      local h = r[z]
      if (h == nil) then
        h = {}
        r[z] = h
      end
      if (h[t] ~= nil) then
        c()
      end
      h[t] = {o, (#d)}
      local k = {s, p, g, (d[(#d)] % w.e), (#d)}
      for t = 1, (#d) do
        local i = d[t]
        local d = (i % w.e)
        j[5], j[26], j[30], j[19], j[53], j[65] = l(j[97], j[21], (((i - d) / w.e) + 1), p, x, y)
        j[21] = j[65]
        if (not qa(d, j[5], j[26], j[30], j[19], j[53], f, j[13], q, x)) then
          c()
        end
        if (a == 0) then
          k[(e + (((t - 1) + m) % 4))] = ((j[5] + (j[26] * w.e)) + (j[30] * w.aa))
        elseif (a == 1) then
          local x = ((e + 4) - t)
          k[x] = (j[5] + (j[30] * w.e))
          k[(x + 4)] = j[26]
        elseif (a == 2) then
          k[(((e + t) - 1) + (m * 4))] = j[5]
          k[(((e + t) - 1) + (((m + 1) % 3) * 4))] = j[26]
          k[(((e + t) - 1) + (((m + 2) % 3) * 4))] = j[30]
        else
          local x = {}
          x[(1 + m)] = j[5]
          x[(1 + ((m + 1) % 3))] = j[26]
          x[(1 + ((m + 2) % 3))] = j[30]
          k[((e + 4) - t)] = x
        end
      end
      i[t] = k
    end
    if (((j[21] ~= (g + 1)) or (f == 0)) or (i[f] == nil)) then
      c()
    end
    for m, w in di, i do
      local q = d(w[1], m, x, 0)
      local k = d(w[3], m, x, 1)
      local t = w[4]
      local d = w[5]
      j[5], j[26], j[30], j[53], j[19] = b(x, w, d, 0)
      if (t == 149) then
        if (((q ~= 0) or (k ~= 0)) or (i[j[19]] == nil)) then
          c()
        end
      elseif ((t == 98) or (t == 43)) then
        if ((q ~= 0) or (k ~= 0)) then
          c()
        end
      elseif (t == 65) then
        if ((i[q] == nil) or (i[k] == nil)) then
          c()
        end
      elseif ((i[q] == nil) or (k ~= 0)) then
        c()
      end
    end
    i[0] = f
    i[-1] = j[97]
    j[13].l = i
    j[13].v = r
    return i
  end
  for j = 0, (x - 1) do
    local x = q[j].l
    if ((not x[2]) or (h(x[2]) ~= x[1])) then
      c()
    end
    q[j].l = x[2]
    w(j)
    q[j].l = x[2]
    q[j].v = nil
    q[j].g = nil
  end
  return o, d, b, w
end
}, w):g()
