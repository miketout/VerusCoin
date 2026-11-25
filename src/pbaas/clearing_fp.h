#ifndef VERUS_PBAAS_CLEARING_FP_H
#define VERUS_PBAAS_CLEARING_FP_H

#include "arith_uint256.h"

#include <cstdint>
#include <vector>

namespace clearingfp
{
    enum { ERR_NONE = 0, ERR_EMPTIES = 1, ERR_RANGE = 2, ERR_INPUT = 3 };

    static const int FRACTION_BITS = 128;
    static const int ATANH_TERMS = 40;
    static const int EXP_TERMS = 34;
    static const int64_t SATOSHI = 100000000;

    inline const arith_uint256 &One()
    {
        static const arith_uint256 one = arith_uint256(1) << FRACTION_BITS;
        return one;
    }

    inline const arith_uint256 &Ln2()
    {
        static const arith_uint256 ln2("b17217f7d1cf79abc9e3b39803f2f6af");
        return ln2;
    }

    inline const std::vector<arith_uint256> &InverseOdd()
    {
        static const std::vector<arith_uint256> table = []() {
            std::vector<arith_uint256> t(ATANH_TERMS + 1);
            for (int n = 0; n <= ATANH_TERMS; n++)
            {
                t[n] = One() / arith_uint256(static_cast<uint64_t>(2 * n + 1));
            }
            return t;
        }();
        return table;
    }

    inline const std::vector<arith_uint256> &Inverse()
    {
        static const std::vector<arith_uint256> table = []() {
            std::vector<arith_uint256> t(EXP_TERMS + 2);
            t[1] = One();
            for (int n = 2; n < EXP_TERMS + 2; n++)
            {
                t[n] = One() / arith_uint256(static_cast<uint64_t>(n));
            }
            return t;
        }();
        return table;
    }

    inline arith_uint256 MulQ(const arith_uint256 &a, const arith_uint256 &b)
    {
        arith_uint256 ah = a >> FRACTION_BITS;
        arith_uint256 bh = b >> FRACTION_BITS;
        if (ah == 0 && bh == 0)
        {
            return (a * b) >> FRACTION_BITS;
        }
        arith_uint256 al = a - (ah << FRACTION_BITS);
        arith_uint256 bl = b - (bh << FRACTION_BITS);
        return ((ah * bh) << FRACTION_BITS) + ah * bl + al * bh + ((al * bl) >> FRACTION_BITS);
    }

    inline arith_uint256 DivQ(arith_uint256 a, arith_uint256 b)
    {
        unsigned int bbits = b.bits();
        if (bbits > FRACTION_BITS)
        {
            a >>= bbits - FRACTION_BITS;
            b >>= bbits - FRACTION_BITS;
        }
        arith_uint256 q = a / b;
        arith_uint256 r = a - q * b;
        return (q << FRACTION_BITS) + ((r << FRACTION_BITS) / b);
    }

    inline arith_uint256 AtanhG(const arith_uint256 &y)
    {
        const std::vector<arith_uint256> &inv = InverseOdd();
        arith_uint256 h = inv[ATANH_TERMS];
        for (int n = ATANH_TERMS - 1; n > 0; n--)
        {
            h = inv[n] + MulQ(h, y);
        }
        return One() + MulQ(h, y);
    }

    inline arith_uint256 LnRatio(const arith_uint256 &numFx, uint64_t den, bool &negative)
    {
        int s = 256 - static_cast<int>(numFx.bits());
        arith_uint256 q = (numFx << s) / arith_uint256(den);
        int nb = static_cast<int>(q.bits());
        arith_uint256 m = q >> (nb - 129);
        int k = nb - 129 - s;
        arith_uint256 z = ((m - One()) << FRACTION_BITS) / (m + One());
        arith_uint256 lnm = MulQ(z, AtanhG(MulQ(z, z))) << 1;
        negative = k < 0;
        if (!negative)
        {
            return Ln2() * static_cast<uint32_t>(k) + lnm;
        }
        arith_uint256 mag = Ln2() * static_cast<uint32_t>(-k);
        return mag > lnm ? mag - lnm : arith_uint256(0);
    }

    inline void ExpParts(const arith_uint256 &x, uint64_t &k, arith_uint256 &t, arith_uint256 &phi)
    {
        const std::vector<arith_uint256> &inv = Inverse();
        arith_uint256 bigK = x / Ln2();
        arith_uint256 r = x - bigK * Ln2();
        k = bigK.GetLow64();
        arith_uint256 q = One();
        phi = 0;
        t = 0;
        for (int n = 0; n < EXP_TERMS; n++)
        {
            phi += q;
            arith_uint256 qr = MulQ(q, r);
            t += qr;
            q = MulQ(qr, inv[n + 2]);
        }
    }

    static const int BRACKET_TOL_X_BITS = 72;   // 2^-56 in x = ln(S'/S): a relative price error far below a satoshi
    static const int MAX_BRACKET_STEPS = 256;   // never reached: interpolation converges superlinearly and the fallback is bisection
    static const int MAX_VIA_ITERATIONS = 6;    // via units at a fixed x, warm-started from the last evaluation; one iteration for a via graph without cycles
    static const int MAX_FLOOR_EXTENSIONS = 8;  // via sells can put the root below the sells-only floor; the floor doubles down at most this often

    // e^x and Phi = (e^x - 1)/x for a signed Q128 x. Phi is positive for every x and 1 at zero. false when e^x overflows
    inline bool ExpPhi(bool negative, const arith_uint256 &mag, arith_uint256 &E, arith_uint256 &Phi)
    {
        uint64_t k;
        arith_uint256 t, phi;
        ExpParts(mag, k, t, phi);
        if (!negative)
        {
            if (k >= 64)
            {
                return false;
            }
            E = (One() + t) << static_cast<unsigned int>(k);
            Phi = k == 0 ? phi : DivQ(E - One(), mag);
        }
        else if (k == 0)
        {
            E = DivQ(One(), One() + t);
            Phi = DivQ(phi, One() + t);
        }
        else
        {
            E = k >= 127 ? arith_uint256(0) : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
            Phi = DivQ(One() - E, mag);
        }
        return true;
    }

    // w * ln(numFx / den), w = W / SATOSHI, as a sign and a Q128 magnitude
    inline arith_uint256 WLn(int64_t W, const arith_uint256 &numFx, uint64_t den, bool &negative)
    {
        arith_uint256 L = LnRatio(numFx, den, negative);
        return (L * static_cast<uint32_t>(W)) / arith_uint256(static_cast<uint64_t>(SATOSHI));
    }

    // a / b in Q128, false when the quotient needs more than 128 integer bits, where DivQ would wrap. b must be nonzero
    inline bool DivQChecked(arith_uint256 a, arith_uint256 b, arith_uint256 &out)
    {
        unsigned int bbits = b.bits();
        if (bbits > FRACTION_BITS)
        {
            a >>= bbits - FRACTION_BITS;
            b >>= bbits - FRACTION_BITS;
        }
        arith_uint256 q = a / b;
        if (q.bits() > FRACTION_BITS)
        {
            return false;
        }
        arith_uint256 r = a - q * b;
        out = (q << FRACTION_BITS) + ((r << FRACTION_BITS) / b);
        return true;
    }

    // a mixed reserve (buys a and sells b in one reserve) clears where g(q) = w ln((R + a - q)/R) - (a b / q - b)/(S Phi) is zero,
    // with q the reserve paid to its sellers (q = b p). returns g's sign; the magnitude is set when both terms are in range.
    // when a term is out of range it is the second, which then dwarfs the first, so the sign is still right
    inline bool GValue(int64_t W, int64_t R, const arith_uint256 &rq, const arith_uint256 &aq, const arith_uint256 &bq,
                       const arith_uint256 &SPhi, const arith_uint256 &q, bool &haveMag, arith_uint256 &mag)
    {
        haveMag = false;
        bool neg1;
        arith_uint256 m1 = WLn(W, rq + aq - q, static_cast<uint64_t>(R), neg1);
        arith_uint256 abq;
        if (!DivQChecked(MulQ(aq, bq), q, abq))
        {
            return false;
        }
        bool neg2 = abq < bq;
        arith_uint256 m2;
        if (!DivQChecked(neg2 ? bq - abq : abq - bq, SPhi, m2))
        {
            return neg2;
        }
        arith_uint256 pos = (neg1 ? arith_uint256(0) : m1) + (neg2 ? m2 : arith_uint256(0));
        arith_uint256 negm = (neg1 ? m1 : arith_uint256(0)) + (neg2 ? arith_uint256(0) : m2);
        haveMag = true;
        mag = pos > negm ? pos - negm : negm - pos;
        return pos > negm;
    }

    // the root of an increasing predicate between lo (false) and hi (true). probe(x, haveValue, value) returns the predicate
    // at x and, when it can, |f(x)|. Illinois interpolation when both end values are known, bisection otherwise or after one
    // side has been kept twice; the new point is always strictly inside the bracket. the result is the bracket's midpoint
    template <typename PROBE>
    inline arith_uint256 Bracket(arith_uint256 lo, arith_uint256 hi, bool haveLo, arith_uint256 vlo, bool haveHi, arith_uint256 vhi,
                                 const PROBE &probe, const arith_uint256 &tol)
    {
        int kept = 0, consecutive = 0;
        for (int step = 0; step < MAX_BRACKET_STEPS && hi - lo > tol; step++)
        {
            arith_uint256 w = hi - lo;
            bool interpolated = false;
            arith_uint256 xn;
            if (haveLo && haveHi && consecutive < 2 && w.bits() > 8)
            {
                arith_uint256 tot = vlo + vhi;
                if (tot != 0)
                {
                    xn = lo + MulQ(w, DivQ(vlo, tot));
                    arith_uint256 margin = w >> 8;
                    if (xn < lo + margin)
                    {
                        xn = lo + margin;
                    }
                    else if (xn > hi - margin)
                    {
                        xn = hi - margin;
                    }
                    interpolated = true;
                }
            }
            if (!interpolated)
            {
                xn = (lo + hi) >> 1;
                consecutive = 0;
            }
            bool haveV;
            arith_uint256 v;
            if (probe(xn, haveV, v))
            {
                hi = xn;
                haveHi = haveV;
                vhi = v;
                consecutive = kept == -1 ? consecutive + 1 : 1;
                kept = -1;
                if (consecutive >= 2 && haveLo)
                {
                    vlo >>= 1;
                }
            }
            else
            {
                lo = xn;
                haveLo = haveV;
                vlo = v;
                consecutive = kept == 1 ? consecutive + 1 : 1;
                kept = 1;
                if (consecutive >= 2 && haveHi)
                {
                    vhi >>= 1;
                }
            }
        }
        return (lo + hi) >> 1;
    }

    // the mixed reserve's payout q. H(q) = g(q)/(a - q) is increasing in q with one root, where g itself also vanishes at the
    // crossing price q == a; H's sign is g's below a and the opposite above a. the bracket is closed form at this Phi: the
    // pure-sell payout R (1 - e^(-b/(w S Phi))) is at or below the root and b times the pure-buy price a/(w S Phi ln(1 + a/R))
    // is at or above it. the tolerance is a 256th of one satoshi of price, q = b p
    inline arith_uint256 SolveMixed(int64_t W, int64_t R, int64_t a, const arith_uint256 &bq, const arith_uint256 &SPhi)
    {
        arith_uint256 rq = arith_uint256(static_cast<uint64_t>(R)) << FRACTION_BITS;
        arith_uint256 aq = arith_uint256(static_cast<uint64_t>(a)) << FRACTION_BITS;
        auto probe = [&](const arith_uint256 &q, bool &haveValue, arith_uint256 &value) -> bool
        {
            haveValue = false;
            if (q == 0)
            {
                return false;
            }
            bool haveMag;
            arith_uint256 mag;
            bool gPositive = GValue(W, R, rq, aq, bq, SPhi, q, haveMag, mag);
            if (q == aq)
            {
                // H(a) > 0  <=>  w S Phi > b R / a
                arith_uint256 wq = (arith_uint256(static_cast<uint64_t>(W)) << FRACTION_BITS) / arith_uint256(static_cast<uint64_t>(SATOSHI));
                arith_uint256 bra;
                return !DivQChecked(MulQ(bq, rq), aq, bra) || MulQ(SPhi, wq) > bra;
            }
            bool above = q < aq ? gPositive : !gPositive;
            if (haveMag)
            {
                haveValue = DivQChecked(mag, q < aq ? aq - q : q - aq, value);
            }
            return above;
        };
        arith_uint256 cm = DivQ(bq, SPhi);
        arith_uint256 y = (cm * static_cast<uint32_t>(SATOSHI)) / arith_uint256(static_cast<uint64_t>(W));
        uint64_t k;
        arith_uint256 t, phi;
        ExpParts(y, k, t, phi);
        arith_uint256 Ey = k >= 127 ? arith_uint256(0) : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
        arith_uint256 lo = rq - MulQ(rq, Ey);
        bool negative;
        arith_uint256 cb = WLn(W, rq + aq, static_cast<uint64_t>(R), negative);
        arith_uint256 denom = MulQ(cb, SPhi);
        arith_uint256 hi = rq + aq - 1;
        arith_uint256 qbuy;
        if (denom != 0 && DivQChecked(MulQ(aq, bq), denom, qbuy) && qbuy < hi)
        {
            hi = qbuy;
        }
        if (hi <= lo)
        {
            return lo;
        }
        bool haveLo, haveHi;
        arith_uint256 vlo, vhi;
        if (probe(lo, haveLo, vlo))
        {
            return lo;
        }
        if (!probe(hi, haveHi, vhi))
        {
            return hi;
        }
        arith_uint256 tol = (bq / arith_uint256(static_cast<uint64_t>(SATOSHI))) >> 8;
        if (tol == 0)
        {
            tol = 1;
        }
        return Bracket(lo, hi, haveLo, vlo, haveHi, vhi, probe, tol);
    }

    inline bool ValidInputs(const std::vector<int64_t> &R,
                            const std::vector<int64_t> &W,
                            int64_t S,
                            const std::vector<int64_t> &a,
                            const std::vector<int64_t> &b,
                            const std::vector<std::vector<int64_t>> *pCross)
    {
        size_t n = R.size();
        if (!n || S <= 0 || W.size() != n || a.size() != n || b.size() != n || (pCross && pCross->size() != n))
        {
            return false;
        }
        for (size_t i = 0; i < n; i++)
        {
            if (R[i] <= 0 || W[i] <= 0 || W[i] > INT32_MAX || a[i] < 0 || b[i] < 0)
            {
                return false;
            }
            if (pCross)
            {
                if ((*pCross)[i].size() != n)
                {
                    return false;
                }
                // via first legs are part of the reserve in
                int64_t viaOut = 0;
                for (size_t j = 0; j < n; j++)
                {
                    if ((*pCross)[i][j] < 0 || (*pCross)[i][j] > a[i] - viaOut)
                    {
                        return false;
                    }
                    viaOut += (*pCross)[i][j];
                }
            }
        }
        return true;
    }

    // conversionPrice convention (reserve per unit times SATOSHI), rounded toward the pool: the pool gains (price error) x (the
    // reserve's net units), so a reserve whose buyers take more units than its sellers return is priced up, one whose sellers
    // return more is priced down, and a reserve with no flow takes the nearest satoshi. no satoshi of rounding leaves the pool
    inline arith_uint256 RoundPrice(const arith_uint256 &priceQ, bool noFlow, bool netBuy)
    {
        return noFlow ? (priceQ + (One() >> 1)) >> FRACTION_BITS :
               netBuy ? (priceQ + (One() - 1)) >> FRACTION_BITS :
                        priceQ >> FRACTION_BITS;
    }

    // one clearing price per reserve for every conversion in an import, found as the root of the scalar x = ln(S'/S).
    // given x, every reserve's price is closed form: a pure buy's reserve change is fixed, so its units follow from the
    // curve's log split; a pure sell's burned units are fixed, so its end reserve is R e^(-b/(w S Phi)), which never reaches
    // zero; a mixed reserve solves a one-variable equation with one root. via legs are sells of the units their first leg buys
    // at that reserve's price, and are resolved inside each evaluation of x, so the outer root is the coupled solution. the
    // outer equation sum(c_i(x)) = x is strictly decreasing while total sells are below the supply; it is bracketed by
    // [ln((S - sum b)/S), sum w ln(1 + a/R)], the floor extended downward when via sells put the root below it. every path is
    // bounded and integer-only, so every node computes the same prices. evaluations reports the outer evaluations
    inline int Clear(const std::vector<int64_t> &R,
                     const std::vector<int64_t> &W,
                     int64_t S,
                     const std::vector<int64_t> &a,
                     const std::vector<int64_t> &b,
                     const std::vector<std::vector<int64_t>> *pCross,
                     std::vector<int64_t> &prices,
                     int &evaluations)
    {
        static const arith_uint256 bigSatoshi(static_cast<uint64_t>(SATOSHI));
        static const arith_uint256 maxPrice(static_cast<uint64_t>(INT64_MAX));
        static const arith_uint256 tolX = arith_uint256(1) << BRACKET_TOL_X_BITS;

        evaluations = 0;
        if (!ValidInputs(R, W, S, a, b, pCross))
        {
            return ERR_INPUT;
        }
        size_t n = R.size();
        arith_uint256 bigS(static_cast<uint64_t>(S));
        arith_uint256 Sq = bigS << FRACTION_BITS;

        std::vector<bool> isSource(n, false);
        bool anySource = false;
        arith_uint256 B(0);
        for (size_t i = 0; i < n; i++)
        {
            B += arith_uint256(static_cast<uint64_t>(b[i])) << FRACTION_BITS;
            if (pCross)
            {
                for (size_t k = 0; k < n && !isSource[i]; k++)
                {
                    isSource[i] = (*pCross)[i][k] != 0;
                }
                anySource = anySource || isSource[i];
            }
        }
        if (B >= Sq)
        {
            return ERR_EMPTIES;
        }

        // the pure-buy contributions are constants in x and bound x from above; the sells alone bound it from below
        std::vector<arith_uint256> cbuy(n);
        arith_uint256 xhi(0);
        for (size_t i = 0; i < n; i++)
        {
            if (a[i])
            {
                bool negative;
                cbuy[i] = WLn(W[i], (arith_uint256(static_cast<uint64_t>(R[i])) + arith_uint256(static_cast<uint64_t>(a[i]))) << FRACTION_BITS,
                              static_cast<uint64_t>(R[i]), negative);
                xhi += cbuy[i];
            }
        }
        arith_uint256 sellFloor(0);
        if (B != 0)
        {
            bool negative;
            sellFloor = LnRatio(Sq - B, static_cast<uint64_t>(S), negative);
        }

        // state of the last evaluation; the via units and source prices also warm-start the next one
        std::vector<arith_uint256> via(n), bq(n), qs(n);
        std::vector<int64_t> srcPrice(n, 0);
        arith_uint256 E, Phi, SPhi;

        // the sells per reserve at the current via units; false when they reach the supply
        auto sells = [&]() -> bool
        {
            arith_uint256 total(0);
            for (size_t i = 0; i < n; i++)
            {
                bq[i] = (arith_uint256(static_cast<uint64_t>(b[i])) << FRACTION_BITS) + via[i];
                total += bq[i];
            }
            return total < Sq;
        };

        // F(x) = sum(c_i(x)) - x at x = t - off. returns true when F <= 0 or x is infeasible (the root is below); sets
        // haveValue and value to |F| when it is defined. resolves the via units at this x first
        auto evaluate = [&](const arith_uint256 &t, const arith_uint256 &off, bool &haveValue, arith_uint256 &value) -> bool
        {
            evaluations++;
            haveValue = false;
            bool xNegative = t < off;
            arith_uint256 xMag = xNegative ? off - t : t - off;
            if (!ExpPhi(xNegative, xMag, E, Phi))
            {
                return true;
            }
            SPhi = Phi * bigS;
            if (anySource)
            {
                for (int iteration = 0; iteration < MAX_VIA_ITERATIONS; iteration++)
                {
                    if (!sells())
                    {
                        return true;
                    }
                    std::vector<int64_t> newPrice(srcPrice);
                    std::vector<arith_uint256> nextVia(n);
                    for (size_t j = 0; j < n; j++)
                    {
                        if (!isSource[j])
                        {
                            continue;
                        }
                        arith_uint256 priceQ;
                        bool netBuy;
                        if (bq[j] == 0)
                        {
                            arith_uint256 dS = MulQ(cbuy[j], SPhi);
                            if (dS == 0)
                            {
                                return true;
                            }
                            priceQ = DivQ((arith_uint256(static_cast<uint64_t>(a[j])) * bigSatoshi) << FRACTION_BITS, dS);
                            netBuy = true;
                        }
                        else
                        {
                            qs[j] = SolveMixed(W[j], R[j], a[j], bq[j], SPhi);
                            priceQ = DivQ(qs[j] * bigSatoshi, bq[j]);
                            netBuy = (arith_uint256(static_cast<uint64_t>(a[j])) << FRACTION_BITS) > qs[j];
                        }
                        arith_uint256 price = RoundPrice(priceQ, false, netBuy);
                        if (price == 0 || price > maxPrice)
                        {
                            return true;
                        }
                        newPrice[j] = static_cast<int64_t>(price.GetLow64());
                        for (size_t k = 0; k < n; k++)
                        {
                            if ((*pCross)[j][k])
                            {
                                arith_uint256 units;
                                if (!DivQChecked((arith_uint256(static_cast<uint64_t>((*pCross)[j][k])) * bigSatoshi) << FRACTION_BITS,
                                                 arith_uint256(static_cast<uint64_t>(newPrice[j])) << FRACTION_BITS, units))
                                {
                                    return true;
                                }
                                nextVia[k] += units;
                            }
                        }
                    }
                    // settled when every source price moved by at most one satoshi since the last iteration (the integer
                    // rounding's own two-cycle, not a change in the solution) or the via units are stable to a satoshi of units
                    bool pricesStable = iteration > 0, viaStable = true;
                    for (size_t i = 0; i < n; i++)
                    {
                        if (isSource[i] && (newPrice[i] > srcPrice[i] ? newPrice[i] - srcPrice[i] : srcPrice[i] - newPrice[i]) > 1)
                        {
                            pricesStable = false;
                        }
                        if ((nextVia[i] > via[i] ? nextVia[i] - via[i] : via[i] - nextVia[i]) >= One())
                        {
                            viaStable = false;
                        }
                    }
                    via = nextVia;
                    srcPrice = newPrice;
                    if (pricesStable || viaStable)
                    {
                        break;
                    }
                }
            }
            if (!sells())
            {
                return true;
            }
            arith_uint256 pos(0), negSum(0);
            for (size_t i = 0; i < n; i++)
            {
                if (!a[i] && bq[i] == 0)
                {
                    continue;
                }
                if (bq[i] == 0)
                {
                    pos += cbuy[i];
                }
                else if (!a[i])
                {
                    negSum += DivQ(bq[i], SPhi);
                }
                else
                {
                    qs[i] = SolveMixed(W[i], R[i], a[i], bq[i], SPhi);
                    bool negative;
                    arith_uint256 m = WLn(W[i], ((arith_uint256(static_cast<uint64_t>(R[i])) + arith_uint256(static_cast<uint64_t>(a[i]))) << FRACTION_BITS) - qs[i],
                                          static_cast<uint64_t>(R[i]), negative);
                    if (negative)
                    {
                        negSum += m;
                    }
                    else
                    {
                        pos += m;
                    }
                }
            }
            arith_uint256 lhs = pos + (xNegative ? xMag : arith_uint256(0));
            arith_uint256 rhs = negSum + (xNegative ? arith_uint256(0) : xMag);
            haveValue = true;
            value = lhs > rhs ? lhs - rhs : rhs - lhs;
            return !(lhs > rhs);
        };

        // the sells-only sellFloor is a lower bound without via legs; with them the root can lie below it, so extend downward
        arith_uint256 off = sellFloor, lo(0);
        bool haveLo, haveHi;
        arith_uint256 vlo, vhi;
        bool aboveLo = evaluate(lo, off, haveLo, vlo);
        for (int extension = 0; aboveLo && anySource && extension < MAX_FLOOR_EXTENSIONS; extension++)
        {
            off += off != 0 ? off : (One() >> 4);
            aboveLo = evaluate(lo, off, haveLo, vlo);
        }
        if (aboveLo && anySource)
        {
            return ERR_RANGE;
        }
        arith_uint256 hi = off + xhi;
        arith_uint256 tFinal;
        if (aboveLo)
        {
            tFinal = lo;
        }
        else if (!evaluate(hi, off, haveHi, vhi))
        {
            tFinal = hi;
        }
        else
        {
            tFinal = Bracket(lo, hi, haveLo, vlo, haveHi, vhi,
                             [&](const arith_uint256 &t, bool &haveValue, arith_uint256 &value) { return evaluate(t, off, haveValue, value); },
                             tolX);
        }
        // evaluate once more at the chosen point so the state belongs to it
        bool haveFinal;
        arith_uint256 vFinal;
        if (evaluate(tFinal, off, haveFinal, vFinal) && !haveFinal)
        {
            return ERR_RANGE;
        }

        prices.resize(n);
        for (size_t i = 0; i < n; i++)
        {
            arith_uint256 rq = arith_uint256(static_cast<uint64_t>(R[i])) << FRACTION_BITS;
            arith_uint256 priceQ;
            if (!a[i] && bq[i] == 0)
            {
                // no flow: the end spot price R / (w S')
                if (E == 0)
                {
                    return ERR_RANGE;
                }
                priceQ = DivQ(((rq * bigSatoshi) * bigSatoshi) / (bigS * static_cast<uint32_t>(W[i])), E);
            }
            else if (bq[i] == 0)
            {
                // pure buy: units created are the reserve's share of the supply change
                arith_uint256 dS = MulQ(cbuy[i], SPhi);
                if (dS == 0)
                {
                    return ERR_RANGE;
                }
                priceQ = DivQ((arith_uint256(static_cast<uint64_t>(a[i])) * bigSatoshi) << FRACTION_BITS, dS);
            }
            else if (!a[i])
            {
                // pure sell: R' = R e^(-b / (w S Phi)); the sellers receive R - R'
                arith_uint256 cm = DivQ(bq[i], SPhi);
                arith_uint256 y = (cm * bigSatoshi) / arith_uint256(static_cast<uint64_t>(W[i]));
                uint64_t k;
                arith_uint256 t, phi;
                ExpParts(y, k, t, phi);
                arith_uint256 Ey = k >= 127 ? arith_uint256(0) : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
                arith_uint256 dR = rq - MulQ(rq, Ey);
                priceQ = DivQ(dR * bigSatoshi, bq[i]);
            }
            else
            {
                priceQ = DivQ(qs[i] * bigSatoshi, bq[i]);
            }
            bool noFlow = !a[i] && bq[i] == 0;
            bool netBuy = bq[i] == 0 || (a[i] && (arith_uint256(static_cast<uint64_t>(a[i])) << FRACTION_BITS) > qs[i]);
            arith_uint256 price = RoundPrice(priceQ, noFlow, netBuy);
            if (price == 0 || price > maxPrice)
            {
                return ERR_RANGE;
            }
            prices[i] = static_cast<int64_t>(price.GetLow64());
        }
        return ERR_NONE;
    }
}

#endif
