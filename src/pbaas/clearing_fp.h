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
    static const int MAX_CLEARING_ITERATIONS = 32;
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

    static const int OUTER_STEPS = 56;        // bisection on x = ln(S'/S): 2^-56 of a bracket under 64, below a satoshi at any price
    static const int INNER_STEPS = 88;        // bisection on a mixed reserve's payout q over (0, R + a): 2^-24 satoshi
    static const int MAX_VIA_PASSES = 8;      // via legs: sells of the units their first leg buys, re-derived until stable

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

    // a mixed reserve (buys a and sells b in one reserve) clears where w ln((R + a - q)/R) = (a b / q - b) / (S Phi), with q the
    // reserve paid to its sellers (q = b p). true when the left side exceeds the right at q
    inline bool GPositive(int64_t W, int64_t R, const arith_uint256 &rq, const arith_uint256 &aq, const arith_uint256 &bq,
                          const arith_uint256 &SPhi, const arith_uint256 &q)
    {
        bool neg1;
        arith_uint256 m1 = WLn(W, rq + aq - q, static_cast<uint64_t>(R), neg1);
        arith_uint256 abq = DivQ(MulQ(aq, bq), q);
        bool neg2 = abq < bq;
        arith_uint256 m2 = neg2 ? DivQ(bq - abq, SPhi) : DivQ(abq - bq, SPhi);
        arith_uint256 pos = (neg1 ? arith_uint256(0) : m1) + (neg2 ? m2 : arith_uint256(0));
        arith_uint256 negm = (neg1 ? m1 : arith_uint256(0)) + (neg2 ? arith_uint256(0) : m2);
        return pos > negm;
    }

    // the function above is concave in q and has the crossing price q == a (the reserve contributing nothing) as a root for
    // every x; the real root lies on the other side of its maximum, to the right of a when g'(a) > 0, i.e. b R > w a S Phi
    inline arith_uint256 SolveMixed(int64_t W, int64_t R, int64_t a, const arith_uint256 &bq, const arith_uint256 &SPhi)
    {
        arith_uint256 rq = arith_uint256(static_cast<uint64_t>(R)) << FRACTION_BITS;
        arith_uint256 aq = arith_uint256(static_cast<uint64_t>(a)) << FRACTION_BITS;
        bool rightSide = MulQ(bq, rq) > (MulQ(aq, SPhi) * static_cast<uint32_t>(W)) / arith_uint256(static_cast<uint64_t>(SATOSHI));
        arith_uint256 lo = rightSide ? aq : arith_uint256(0);
        arith_uint256 hi = rightSide ? rq + aq : aq;
        for (int i = 0; i < INNER_STEPS; i++)
        {
            arith_uint256 mid = (lo + hi) >> 1;
            if (mid == 0)
            {
                lo = mid;
                continue;
            }
            bool gPositive = GPositive(W, R, rq, aq, bq, SPhi, mid);
            if (rightSide == gPositive)
            {
                lo = mid;
            }
            else
            {
                hi = mid;
            }
        }
        return (lo + hi) >> 1;
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
                for (size_t j = 0; j < n; j++)
                {
                    if ((*pCross)[i][j] < 0)
                    {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    // one clearing price per reserve for every conversion in an import, found by bisection on the scalar x = ln(S'/S).
    // given x, every reserve's price is closed form: a pure buy's reserve change is fixed, so its units follow from the
    // curve's log split; a pure sell's burned units are fixed, so its end reserve is R e^(-b/(w S Phi)), which never reaches
    // zero; a mixed reserve solves a concave one-variable equation. the outer equation sum(c_i(x)) = x is strictly decreasing
    // while total sells are below the supply and is bracketed by [ln((S - sum b)/S), sum w ln(1 + a/R)], so the bisection
    // converges unconditionally. via legs are sells of the units their first leg buys at p_j and settle in an outer pass.
    // prices are in the conversionPrice convention (reserve per unit times SATOSHI), rounded toward the pool (§203's rule,
    // Mike 2026-11-24); a reserve with no flow takes the end spot price. every path is bounded and integer-only, so every node computes the same prices
    inline int Clear(const std::vector<int64_t> &R,
                     const std::vector<int64_t> &W,
                     int64_t S,
                     const std::vector<int64_t> &a,
                     const std::vector<int64_t> &b,
                     const std::vector<std::vector<int64_t>> *pCross,
                     std::vector<int64_t> &prices,
                     int &passes)
    {
        static const arith_uint256 bigSatoshi(static_cast<uint64_t>(SATOSHI));
        static const arith_uint256 maxPrice(static_cast<uint64_t>(INT64_MAX));

        passes = 0;
        if (!ValidInputs(R, W, S, a, b, pCross))
        {
            return ERR_INPUT;
        }
        size_t n = R.size();
        arith_uint256 bigS(static_cast<uint64_t>(S));
        arith_uint256 Sq = bigS << FRACTION_BITS;

        std::vector<arith_uint256> viaUnits(n), bq(n), cbuy(n), qs(n);
        prices.resize(n);

        for (int viaPass = 0; viaPass < MAX_VIA_PASSES; viaPass++)
        {
            passes = viaPass + 1;

            arith_uint256 totalSell(0);
            for (size_t i = 0; i < n; i++)
            {
                bq[i] = (arith_uint256(static_cast<uint64_t>(b[i])) << FRACTION_BITS) + viaUnits[i];
                totalSell += bq[i];
            }
            if (totalSell >= Sq)
            {
                return ERR_EMPTIES;
            }

            // the pure-buy contributions are constants in x; they also bound x from above, and the sells bound it from below
            arith_uint256 xhi(0), xloMag(0);
            for (size_t i = 0; i < n; i++)
            {
                if (a[i])
                {
                    bool negative;
                    arith_uint256 c = WLn(W[i], (arith_uint256(static_cast<uint64_t>(R[i])) + arith_uint256(static_cast<uint64_t>(a[i]))) << FRACTION_BITS,
                                          static_cast<uint64_t>(R[i]), negative);
                    cbuy[i] = c;
                    xhi += c;
                }
            }
            if (totalSell != 0)
            {
                bool negative;
                xloMag = LnRatio(Sq - totalSell, static_cast<uint64_t>(S), negative);
            }

            arith_uint256 E, Phi, SPhi, xMag;
            bool xNegative = false;

            // F(x) = sum(c_i(x)) - x at x = t - xloMag; fills E, Phi, SPhi and the mixed reserves' q; false if e^x overflows
            auto evaluate = [&](const arith_uint256 &t, bool &fPositive) -> bool
            {
                xNegative = t < xloMag;
                xMag = xNegative ? xloMag - t : t - xloMag;
                if (!ExpPhi(xNegative, xMag, E, Phi))
                {
                    return false;
                }
                SPhi = Phi * bigS;
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
                fPositive = lhs > rhs;
                return true;
            };

            arith_uint256 lo(0), hi = xloMag + xhi;
            for (int step = 0; step < OUTER_STEPS; step++)
            {
                arith_uint256 mid = (lo + hi) >> 1;
                bool fPositive;
                if (!evaluate(mid, fPositive))
                {
                    hi = mid;
                    continue;
                }
                if (fPositive)
                {
                    lo = mid;
                }
                else
                {
                    hi = mid;
                }
            }
            bool fPositive;
            if (!evaluate((lo + hi) >> 1, fPositive))
            {
                return ERR_RANGE;
            }

            std::vector<int64_t> newPrices(n);
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
                // round toward the pool: the pool gains (price error) x (the reserve's net units), so a reserve whose buyers take
                // more units than its sellers return is priced up, one whose sellers return more is priced down, and a reserve
                // with no flow takes the nearest satoshi. no satoshi of rounding leaves the pool
                bool noFlow = !a[i] && bq[i] == 0;
                bool netBuy = bq[i] == 0 || (a[i] && (arith_uint256(static_cast<uint64_t>(a[i])) << FRACTION_BITS) > qs[i]);
                arith_uint256 price = noFlow ? (priceQ + (One() >> 1)) >> FRACTION_BITS :
                                      netBuy ? (priceQ + (One() - 1)) >> FRACTION_BITS :
                                               priceQ >> FRACTION_BITS;
                if (price == 0 || price > maxPrice)
                {
                    return ERR_RANGE;
                }
                newPrices[i] = static_cast<int64_t>(price.GetLow64());
            }

            if (!pCross)
            {
                prices = newPrices;
                return ERR_NONE;
            }
            std::vector<arith_uint256> nextVia(n);
            for (size_t j = 0; j < n; j++)
            {
                for (size_t k = 0; k < n; k++)
                {
                    if ((*pCross)[j][k])
                    {
                        nextVia[k] += ((arith_uint256(static_cast<uint64_t>((*pCross)[j][k])) * bigSatoshi) << FRACTION_BITS) /
                                      arith_uint256(static_cast<uint64_t>(newPrices[j]));
                    }
                }
            }
            bool settled = true;
            for (size_t i = 0; i < n && settled; i++)
            {
                arith_uint256 delta = nextVia[i] > viaUnits[i] ? nextVia[i] - viaUnits[i] : viaUnits[i] - nextVia[i];
                settled = delta < One();
            }
            viaUnits = nextVia;
            prices = newPrices;
            if (settled)
            {
                return ERR_NONE;
            }
        }
        return ERR_NONE;
    }
}

#endif
