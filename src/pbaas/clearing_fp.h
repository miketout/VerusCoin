#ifndef VERUS_PBAAS_CLEARING_FP_H
#define VERUS_PBAAS_CLEARING_FP_H

#include "arith_uint256.h"

#include <cstdint>
#include <vector>

#if !defined(__SIZEOF_INT128__)
#error "clearing_fp.h needs a 64-bit GCC or Clang target with unsigned __int128"
#endif

namespace clearingfp
{
    class U256
    {
    public:
        uint64_t w[4];

        U256() : w{0, 0, 0, 0} {}
        U256(uint64_t v) : w{v, 0, 0, 0} {}
        U256(uint64_t w0, uint64_t w1, uint64_t w2, uint64_t w3) : w{w0, w1, w2, w3} {}

        uint64_t GetLow64() const { return w[0]; }

        int Limbs() const
        {
            return w[3] ? 4 : w[2] ? 3 : w[1] ? 2 : w[0] ? 1 : 0;
        }

        unsigned int bits() const
        {
            for (int i = 3; i >= 0; i--)
            {
                if (w[i])
                {
                    return 64 * i + 64 - __builtin_clzll(w[i]);
                }
            }
            return 0;
        }

        U256 &operator+=(const U256 &b)
        {
            unsigned __int128 c = 0;
            for (int i = 0; i < 4; i++)
            {
                c += static_cast<unsigned __int128>(w[i]) + b.w[i];
                w[i] = static_cast<uint64_t>(c);
                c >>= 64;
            }
            return *this;
        }

        U256 &operator-=(const U256 &b)
        {
            uint64_t borrow = 0;
            for (int i = 0; i < 4; i++)
            {
                uint64_t x = w[i], y = b.w[i];
                uint64_t d = x - y;
                uint64_t b1 = x < y;
                uint64_t d2 = d - borrow;
                uint64_t b2 = d < borrow;
                w[i] = d2;
                borrow = b1 | b2;
            }
            return *this;
        }

        U256 &operator<<=(unsigned int shift)
        {
            if (shift >= 256)
            {
                w[0] = w[1] = w[2] = w[3] = 0;
                return *this;
            }
            unsigned int k = shift / 64, s = shift % 64;
            uint64_t r[4];
            for (int i = 3; i >= 0; i--)
            {
                int src = i - static_cast<int>(k);
                uint64_t v = src >= 0 ? w[src] << s : 0;
                if (s && src - 1 >= 0)
                {
                    v |= w[src - 1] >> (64 - s);
                }
                r[i] = v;
            }
            w[0] = r[0], w[1] = r[1], w[2] = r[2], w[3] = r[3];
            return *this;
        }

        U256 &operator>>=(unsigned int shift)
        {
            if (shift >= 256)
            {
                w[0] = w[1] = w[2] = w[3] = 0;
                return *this;
            }
            unsigned int k = shift / 64, s = shift % 64;
            uint64_t r[4];
            for (int i = 0; i < 4; i++)
            {
                unsigned int src = i + k;
                uint64_t v = src < 4 ? w[src] >> s : 0;
                if (s && src + 1 < 4)
                {
                    v |= w[src + 1] << (64 - s);
                }
                r[i] = v;
            }
            w[0] = r[0], w[1] = r[1], w[2] = r[2], w[3] = r[3];
            return *this;
        }

        U256 &operator*=(uint64_t m)
        {
            unsigned __int128 c = 0;
            for (int i = 0; i < 4; i++)
            {
                c += static_cast<unsigned __int128>(w[i]) * m;
                w[i] = static_cast<uint64_t>(c);
                c >>= 64;
            }
            return *this;
        }

        U256 &operator*=(const U256 &b)
        {
            uint64_t r[4] = {0, 0, 0, 0};
            int na = Limbs(), nb = b.Limbs();
            for (int i = 0; i < na; i++)
            {
                uint64_t carry = 0;
                int j = 0;
                for (; j < nb && i + j < 4; j++)
                {
                    unsigned __int128 p = static_cast<unsigned __int128>(w[i]) * b.w[j] + r[i + j] + carry;
                    r[i + j] = static_cast<uint64_t>(p);
                    carry = static_cast<uint64_t>(p >> 64);
                }
                if (i + j < 4)
                {
                    r[i + j] = carry;
                }
            }
            w[0] = r[0], w[1] = r[1], w[2] = r[2], w[3] = r[3];
            return *this;
        }

        U256 &operator/=(const U256 &b);

        int Compare(const U256 &b) const
        {
            for (int i = 3; i >= 0; i--)
            {
                if (w[i] != b.w[i])
                {
                    return w[i] < b.w[i] ? -1 : 1;
                }
            }
            return 0;
        }

        friend inline U256 operator+(const U256 &a, const U256 &b) { return U256(a) += b; }
        friend inline U256 operator-(const U256 &a, const U256 &b) { return U256(a) -= b; }
        friend inline U256 operator*(const U256 &a, const U256 &b) { return U256(a) *= b; }
        friend inline U256 operator*(const U256 &a, uint64_t b) { return U256(a) *= b; }
        friend inline U256 operator/(const U256 &a, const U256 &b) { return U256(a) /= b; }
        friend inline U256 operator<<(const U256 &a, unsigned int shift) { return U256(a) <<= shift; }
        friend inline U256 operator>>(const U256 &a, unsigned int shift) { return U256(a) >>= shift; }
        friend inline bool operator==(const U256 &a, const U256 &b) { return a.w[0] == b.w[0] && a.w[1] == b.w[1] && a.w[2] == b.w[2] && a.w[3] == b.w[3]; }
        friend inline bool operator!=(const U256 &a, const U256 &b) { return !(a == b); }
        friend inline bool operator<(const U256 &a, const U256 &b) { return a.Compare(b) < 0; }
        friend inline bool operator>(const U256 &a, const U256 &b) { return a.Compare(b) > 0; }
        friend inline bool operator<=(const U256 &a, const U256 &b) { return a.Compare(b) <= 0; }
        friend inline bool operator>=(const U256 &a, const U256 &b) { return a.Compare(b) >= 0; }
    };

    inline uint64_t Div128By64(uint64_t hi, uint64_t lo, uint64_t d, uint64_t &rem)
    {
#if defined(__x86_64__)
        uint64_t q, r;
        __asm__("divq %4" : "=a"(q), "=d"(r) : "a"(lo), "d"(hi), "rm"(d));
        rem = r;
        return q;
#else
        unsigned __int128 n = (static_cast<unsigned __int128>(hi) << 64) | lo;
        uint64_t q = static_cast<uint64_t>(n / d);
        rem = static_cast<uint64_t>(n - static_cast<unsigned __int128>(q) * d);
        return q;
#endif
    }

    inline uint64_t Reciprocal2By1(uint64_t d)
    {
        uint64_t rem;
        return Div128By64(~d, ~static_cast<uint64_t>(0), d, rem);
    }

    inline uint64_t Div2By1(uint64_t u1, uint64_t u0, uint64_t d, uint64_t v, uint64_t &rem)
    {
        unsigned __int128 q = static_cast<unsigned __int128>(v) * u1;
        q += (static_cast<unsigned __int128>(u1 + 1) << 64) | u0;
        uint64_t q1 = static_cast<uint64_t>(q >> 64), q0 = static_cast<uint64_t>(q);
        uint64_t r = u0 - q1 * d;
        if (r > q0)
        {
            q1--;
            r += d;
        }
        if (r >= d)
        {
            q1++;
            r -= d;
        }
        rem = r;
        return q1;
    }

    inline uint64_t Reciprocal3By2(uint64_t d1, uint64_t d0)
    {
        uint64_t v = Reciprocal2By1(d1);
        uint64_t p = d1 * v;
        p += d0;
        if (p < d0)
        {
            v--;
            if (p >= d1)
            {
                v--;
                p -= d1;
            }
            p -= d1;
        }
        unsigned __int128 t = static_cast<unsigned __int128>(v) * d0;
        uint64_t t1 = static_cast<uint64_t>(t >> 64), t0 = static_cast<uint64_t>(t);
        p += t1;
        if (p < t1)
        {
            v--;
            if (p > d1 || (p == d1 && t0 >= d0))
            {
                v--;
            }
        }
        return v;
    }

    inline uint64_t Div3By2(uint64_t u2, uint64_t u1, uint64_t u0, uint64_t d1, uint64_t d0, uint64_t v, uint64_t &r1, uint64_t &r0)
    {
        unsigned __int128 q = static_cast<unsigned __int128>(v) * u2;
        q += (static_cast<unsigned __int128>(u2) << 64) | u1;
        uint64_t q1 = static_cast<uint64_t>(q >> 64), q0 = static_cast<uint64_t>(q);
        uint64_t rr1 = u1 - q1 * d1;
        unsigned __int128 t = static_cast<unsigned __int128>(d0) * q1;
        unsigned __int128 d = (static_cast<unsigned __int128>(d1) << 64) | d0;
        unsigned __int128 r = ((static_cast<unsigned __int128>(rr1) << 64) | u0) - t - d;
        q1++;
        if (static_cast<uint64_t>(r >> 64) >= q0)
        {
            q1--;
            r += d;
        }
        if (r >= d)
        {
            q1++;
            r -= d;
        }
        r1 = static_cast<uint64_t>(r >> 64);
        r0 = static_cast<uint64_t>(r);
        return q1;
    }

    inline void DivRem(const U256 &u, const U256 &v, U256 &quot, U256 &rem)
    {
        int n = 4;
        while (n > 0 && v.w[n - 1] == 0)
        {
            n--;
        }
        if (n == 0)
        {
            throw uint_error("Division by zero");
        }
        int m = 4;
        while (m > 0 && u.w[m - 1] == 0)
        {
            m--;
        }
        quot = U256();
        if (m < n || u < v)
        {
            rem = u;
            return;
        }
        if (n == 1)
        {
            unsigned int s1 = __builtin_clzll(v.w[0]);
            uint64_t d = v.w[0] << s1, recip = Reciprocal2By1(d);
            uint64_t r = s1 ? u.w[m - 1] >> (64 - s1) : 0;
            for (int i = m - 1; i >= 0; i--)
            {
                uint64_t limb = s1 ? (u.w[i] << s1) | (i ? u.w[i - 1] >> (64 - s1) : 0) : u.w[i];
                quot.w[i] = Div2By1(r, limb, d, recip, r);
            }
            rem = U256(r >> s1);
            return;
        }
        if (n == 2)
        {
            unsigned int s2 = __builtin_clzll(v.w[1]);
            uint64_t d1 = s2 ? (v.w[1] << s2) | (v.w[0] >> (64 - s2)) : v.w[1];
            uint64_t d0 = v.w[0] << s2;
            uint64_t recip = Reciprocal3By2(d1, d0);
            uint64_t un2[5];
            un2[m] = s2 ? u.w[m - 1] >> (64 - s2) : 0;
            for (int i = m - 1; i > 0; i--)
            {
                un2[i] = s2 ? (u.w[i] << s2) | (u.w[i - 1] >> (64 - s2)) : u.w[i];
            }
            un2[0] = u.w[0] << s2;
            uint64_t r1 = un2[m], r0 = un2[m - 1];
            for (int j = m - 2; j >= 0; j--)
            {
                quot.w[j] = Div3By2(r1, r0, un2[j], d1, d0, recip, r1, r0);
            }
            rem = U256(s2 ? (r0 >> s2) | (r1 << (64 - s2)) : r0, s2 ? r1 >> s2 : r1, 0, 0);
            return;
        }
        unsigned int s = __builtin_clzll(v.w[n - 1]);
        uint64_t vn[4], un[5];
        for (int i = n - 1; i > 0; i--)
        {
            vn[i] = s ? (v.w[i] << s) | (v.w[i - 1] >> (64 - s)) : v.w[i];
        }
        vn[0] = v.w[0] << s;
        un[m] = s ? u.w[m - 1] >> (64 - s) : 0;
        for (int i = m - 1; i > 0; i--)
        {
            un[i] = s ? (u.w[i] << s) | (u.w[i - 1] >> (64 - s)) : u.w[i];
        }
        un[0] = u.w[0] << s;
        for (int j = m - n; j >= 0; j--)
        {
            uint64_t qhat, rhat;
            bool rhatOverflow = false;
            if (un[j + n] >= vn[n - 1])
            {
                qhat = ~static_cast<uint64_t>(0);
                rhat = un[j + n - 1] + vn[n - 1];
                rhatOverflow = rhat < vn[n - 1];
            }
            else
            {
                qhat = Div128By64(un[j + n], un[j + n - 1], vn[n - 1], rhat);
            }
            while (!rhatOverflow &&
                   static_cast<unsigned __int128>(qhat) * vn[n - 2] > ((static_cast<unsigned __int128>(rhat) << 64) | un[j + n - 2]))
            {
                qhat--;
                uint64_t prev = rhat;
                rhat += vn[n - 1];
                rhatOverflow = rhat < prev;
            }
            uint64_t borrow = 0, carry = 0;
            for (int i = 0; i < n; i++)
            {
                unsigned __int128 p = static_cast<unsigned __int128>(qhat) * vn[i] + carry;
                carry = static_cast<uint64_t>(p >> 64);
                uint64_t plo = static_cast<uint64_t>(p);
                uint64_t x = un[i + j];
                uint64_t d = x - plo;
                uint64_t b1 = x < plo;
                uint64_t d2 = d - borrow;
                uint64_t b2 = d < borrow;
                un[i + j] = d2;
                borrow = b1 | b2;
            }
            uint64_t x = un[j + n];
            uint64_t d = x - carry;
            uint64_t b1 = x < carry;
            uint64_t d2 = d - borrow;
            uint64_t b2 = d < borrow;
            un[j + n] = d2;
            if (b1 | b2)
            {
                qhat--;
                unsigned __int128 c = 0;
                for (int i = 0; i < n; i++)
                {
                    c += static_cast<unsigned __int128>(un[i + j]) + vn[i];
                    un[i + j] = static_cast<uint64_t>(c);
                    c >>= 64;
                }
                un[j + n] += static_cast<uint64_t>(c);
            }
            quot.w[j] = qhat;
        }
        rem = U256();
        for (int i = 0; i < n; i++)
        {
            rem.w[i] = s ? (un[i] >> s) | (un[i + 1] << (64 - s)) : un[i];
        }
    }

    inline U256 &U256::operator/=(const U256 &b)
    {
        U256 q, r;
        DivRem(*this, b, q, r);
        return *this = q;
    }

    inline void DivQParts(const U256 &a, const U256 &b, U256 &q, uint64_t &f0, uint64_t &f1)
    {
        int n = b.Limbs();
        if (n == 0)
        {
            throw uint_error("Division by zero");
        }
        q = U256();
        if (n == 1)
        {
            unsigned int s1 = __builtin_clzll(b.w[0]);
            uint64_t d = b.w[0] << s1, recip = Reciprocal2By1(d);
            int m = a.Limbs();
            uint64_t r = m && s1 ? a.w[m - 1] >> (64 - s1) : 0;
            for (int i = m - 1; i >= 0; i--)
            {
                uint64_t limb = s1 ? (a.w[i] << s1) | (i ? a.w[i - 1] >> (64 - s1) : 0) : a.w[i];
                q.w[i] = Div2By1(r, limb, d, recip, r);
            }
            f1 = Div2By1(r, 0, d, recip, r);
            f0 = Div2By1(r, 0, d, recip, r);
            return;
        }
        if (n > 2)
        {
            U256 r;
            DivRem(a, b, q, r);
            U256 fq = (r << 128) / b;
            f0 = fq.w[0];
            f1 = fq.w[1];
            return;
        }
        unsigned int s = __builtin_clzll(b.w[1]);
        uint64_t v1 = s ? (b.w[1] << s) | (b.w[0] >> (64 - s)) : b.w[1];
        uint64_t v0 = b.w[0] << s;
        uint64_t u[5];
        u[4] = s ? a.w[3] >> (64 - s) : 0;
        for (int i = 3; i > 0; i--)
        {
            u[i] = s ? (a.w[i] << s) | (a.w[i - 1] >> (64 - s)) : a.w[i];
        }
        u[0] = a.w[0] << s;
        uint64_t recip = Reciprocal3By2(v1, v0);
        uint64_t r1 = u[4], r0 = u[3];
        for (int j = 2; j >= 0; j--)
        {
            q.w[j] = Div3By2(r1, r0, u[j], v1, v0, recip, r1, r0);
        }
        f1 = Div3By2(r1, r0, 0, v1, v0, recip, r1, r0);
        f0 = Div3By2(r1, r0, 0, v1, v0, recip, r1, r0);
    }

    inline unsigned __int128 MulQ128(unsigned __int128 a, unsigned __int128 b)
    {
        uint64_t a0 = static_cast<uint64_t>(a), a1 = static_cast<uint64_t>(a >> 64);
        uint64_t b0 = static_cast<uint64_t>(b), b1 = static_cast<uint64_t>(b >> 64);
        unsigned __int128 ll = static_cast<unsigned __int128>(a0) * b0;
        unsigned __int128 lh = static_cast<unsigned __int128>(a0) * b1;
        unsigned __int128 hl = static_cast<unsigned __int128>(a1) * b0;
        unsigned __int128 hh = static_cast<unsigned __int128>(a1) * b1;
        unsigned __int128 mid = (ll >> 64) + static_cast<uint64_t>(lh) + static_cast<uint64_t>(hl);
        return hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    }

    inline unsigned __int128 Low128(const U256 &x)
    {
        return (static_cast<unsigned __int128>(x.w[1]) << 64) | x.w[0];
    }

    enum { ERR_NONE = 0, ERR_EMPTIES = 1, ERR_RANGE = 2, ERR_INPUT = 3 };

    static const int FRACTION_BITS = 128;
    static const int ATANH_TERMS = 40;
    static const int EXP_TERMS = 34;
    static const int64_t SATOSHI = 100000000;

    inline const U256 &One()
    {
        static const U256 one = U256(1) << FRACTION_BITS;
        return one;
    }

    inline const U256 &Ln2()
    {
        static const U256 ln2(0xc9e3b39803f2f6afULL, 0xb17217f7d1cf79abULL, 0, 0);
        return ln2;
    }

    inline const std::vector<U256> &InverseOdd()
    {
        static const std::vector<U256> table = []() {
            std::vector<U256> t(ATANH_TERMS + 1);
            for (int n = 0; n <= ATANH_TERMS; n++)
            {
                t[n] = One() / U256(static_cast<uint64_t>(2 * n + 1));
            }
            return t;
        }();
        return table;
    }

    inline const std::vector<U256> &Inverse()
    {
        static const std::vector<U256> table = []() {
            std::vector<U256> t(EXP_TERMS + 2);
            t[1] = One();
            for (int n = 2; n < EXP_TERMS + 2; n++)
            {
                t[n] = One() / U256(static_cast<uint64_t>(n));
            }
            return t;
        }();
        return table;
    }

    inline U256 MulQ(const U256 &a, const U256 &b)
    {
        int na = a.Limbs(), nb = b.Limbs();
        if (na + nb <= 2)
        {
            return U256();
        }
        if (na <= 2 && nb <= 2)
        {
            unsigned __int128 top = MulQ128(Low128(a), Low128(b));
            return U256(static_cast<uint64_t>(top), static_cast<uint64_t>(top >> 64), 0, 0);
        }
        uint64_t p[6] = {0, 0, 0, 0, 0, 0};
        for (int i = 0; i < na; i++)
        {
            uint64_t carry = 0;
            int j = 0;
            for (; j < nb && i + j < 6; j++)
            {
                unsigned __int128 t = static_cast<unsigned __int128>(a.w[i]) * b.w[j] + p[i + j] + carry;
                p[i + j] = static_cast<uint64_t>(t);
                carry = static_cast<uint64_t>(t >> 64);
            }
            if (i + j < 6)
            {
                p[i + j] = carry;
            }
        }
        return U256(p[2], p[3], p[4], p[5]);
    }

    inline U256 DivQ(U256 a, U256 b)
    {
        unsigned int bbits = b.bits();
        if (bbits > FRACTION_BITS)
        {
            a >>= bbits - FRACTION_BITS;
            b >>= bbits - FRACTION_BITS;
        }
        U256 q;
        uint64_t f0, f1;
        DivQParts(a, b, q, f0, f1);
        return U256(f0, f1, q.w[0], q.w[1]);
    }

    inline U256 AtanhG(const U256 &y)
    {
        const std::vector<U256> &inv = InverseOdd();
        if (y.Limbs() <= 2)
        {
            unsigned __int128 y128 = Low128(y);
            unsigned __int128 h128 = Low128(inv[ATANH_TERMS]);
            bool fits = true;
            for (int n = ATANH_TERMS - 1; n > 0 && fits; n--)
            {
                unsigned __int128 p = MulQ128(h128, y128);
                h128 = Low128(inv[n]) + p;
                fits = h128 >= p;
            }
            if (fits)
            {
                unsigned __int128 top = MulQ128(h128, y128);
                return U256(static_cast<uint64_t>(top), static_cast<uint64_t>(top >> 64), 1, 0);
            }
        }
        U256 h = inv[ATANH_TERMS];
        for (int n = ATANH_TERMS - 1; n > 0; n--)
        {
            h = inv[n] + MulQ(h, y);
        }
        return One() + MulQ(h, y);
    }

    inline U256 LnRatio(const U256 &numFx, uint64_t den, bool &negative)
    {
        int s = 256 - static_cast<int>(numFx.bits());
        U256 q = (numFx << s) / U256(den);
        int nb = static_cast<int>(q.bits());
        U256 m = q >> (nb - 129);
        int k = nb - 129 - s;
        U256 z = ((m - One()) << FRACTION_BITS) / (m + One());
        U256 lnm = MulQ(z, AtanhG(MulQ(z, z))) << 1;
        negative = k < 0;
        if (!negative)
        {
            return Ln2() * static_cast<uint32_t>(k) + lnm;
        }
        U256 mag = Ln2() * static_cast<uint32_t>(-k);
        return mag > lnm ? mag - lnm : U256(0);
    }

    inline void ExpParts(const U256 &x, uint64_t &k, U256 &t, U256 &phi)
    {
        const std::vector<U256> &inv = Inverse();
        U256 bigK = x / Ln2();
        U256 r = x - bigK * Ln2();
        k = bigK.GetLow64();
        if (r.Limbs() <= 2)
        {
            unsigned __int128 r128 = Low128(r);
            unsigned __int128 q128 = MulQ128(r128, Low128(inv[2]));
            unsigned __int128 phiLow = 0, tLow = r128;
            uint64_t phiCarry = 0, tCarry = 0;
            for (int n = 1; n < EXP_TERMS; n++)
            {
                phiLow += q128;
                phiCarry += phiLow < q128;
                unsigned __int128 qr = MulQ128(q128, r128);
                tLow += qr;
                tCarry += tLow < qr;
                q128 = MulQ128(qr, Low128(inv[n + 2]));
            }
            phi = U256(static_cast<uint64_t>(phiLow), static_cast<uint64_t>(phiLow >> 64), phiCarry + 1, 0);
            t = U256(static_cast<uint64_t>(tLow), static_cast<uint64_t>(tLow >> 64), tCarry, 0);
            return;
        }
        U256 q = One();
        phi = 0;
        t = 0;
        for (int n = 0; n < EXP_TERMS; n++)
        {
            phi += q;
            U256 qr = MulQ(q, r);
            t += qr;
            q = MulQ(qr, inv[n + 2]);
        }
    }

    static const int BRACKET_TOL_X_BITS = 72;   // 2^-56 in x = ln(S'/S): a relative price error far below a satoshi
    static const int MAX_BRACKET_STEPS = 256;   // never reached: interpolation converges superlinearly and the fallback is bisection
    static const int MAX_VIA_ITERATIONS = 6;    // via units at a fixed x, warm-started from the last evaluation; one iteration for a via graph without cycles
    static const int MAX_FLOOR_EXTENSIONS = 8;  // via sells can put the root below the sells-only floor; the floor doubles down at most this often
    static const int MAX_PROBES_PER_SOLVE = 1 << 17;   // GValue probes per import, four times the measured worst; past it the solve refuses

    // e^x and Phi = (e^x - 1)/x for a signed Q128 x. Phi is positive for every x and 1 at zero. false when e^x overflows
    inline bool ExpPhi(bool negative, const U256 &mag, U256 &E, U256 &Phi)
    {
        uint64_t k;
        U256 t, phi;
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
            E = k >= 127 ? U256(0) : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
            Phi = DivQ(One() - E, mag);
        }
        return true;
    }

    // w * ln(numFx / den), w = W / SATOSHI, as a sign and a Q128 magnitude
    inline U256 WLn(int64_t W, const U256 &numFx, uint64_t den, bool &negative)
    {
        U256 L = LnRatio(numFx, den, negative);
        return (L * static_cast<uint32_t>(W)) / U256(static_cast<uint64_t>(SATOSHI));
    }

    // a / b in Q128, false when the quotient needs more than 128 integer bits, where DivQ would wrap. b must be nonzero
    inline bool DivQChecked(U256 a, U256 b, U256 &out)
    {
        unsigned int bbits = b.bits();
        if (bbits > FRACTION_BITS)
        {
            a >>= bbits - FRACTION_BITS;
            b >>= bbits - FRACTION_BITS;
        }
        U256 q;
        uint64_t f0, f1;
        DivQParts(a, b, q, f0, f1);
        if (q.bits() > FRACTION_BITS)
        {
            return false;
        }
        out = U256(f0, f1, q.w[0], q.w[1]);
        return true;
    }

    // a mixed reserve (buys a and sells b in one reserve) clears where g(q) = w ln((R + a - q)/R) - (a b / q - b)/(S Phi) is zero,
    // with q the reserve paid to its sellers (q = b p). returns g's sign; the magnitude is set when both terms are in range.
    // when a term is out of range it is the second, which then dwarfs the first, so the sign is still right
    inline bool GValue(int64_t W, int64_t R, const U256 &rq, const U256 &aq, const U256 &bq,
                       const U256 &SPhi, const U256 &q, bool &haveMag, U256 &mag)
    {
        haveMag = false;
        bool neg1;
        U256 m1 = WLn(W, rq + aq - q, static_cast<uint64_t>(R), neg1);
        U256 abq;
        if (!DivQChecked(MulQ(aq, bq), q, abq))
        {
            return false;
        }
        bool neg2 = abq < bq;
        U256 m2;
        if (!DivQChecked(neg2 ? bq - abq : abq - bq, SPhi, m2))
        {
            return neg2;
        }
        U256 pos = (neg1 ? U256(0) : m1) + (neg2 ? m2 : U256(0));
        U256 negm = (neg1 ? m1 : U256(0)) + (neg2 ? U256(0) : m2);
        haveMag = true;
        mag = pos > negm ? pos - negm : negm - pos;
        return pos > negm;
    }

    // the root of an increasing predicate between lo (false) and hi (true). probe(x, haveValue, value) returns the predicate
    // at x and, when it can, |f(x)|. Illinois interpolation when both end values are known, bisection otherwise or after one
    // side has been kept twice; the new point is always strictly inside the bracket. the result is the bracket's midpoint
    template <typename PROBE>
    inline U256 Bracket(U256 lo, U256 hi, bool haveLo, U256 vlo, bool haveHi, U256 vhi,
                                 const PROBE &probe, const U256 &tol, bool &converged)
    {
        int kept = 0, consecutive = 0;
        for (int step = 0; step < MAX_BRACKET_STEPS && hi - lo > tol; step++)
        {
            U256 w = hi - lo;
            bool interpolated = false;
            U256 xn;
            if (haveLo && haveHi && consecutive < 2 && w.bits() > 8)
            {
                U256 tot = vlo + vhi;
                if (tot != 0)
                {
                    xn = lo + MulQ(w, DivQ(vlo, tot));
                    U256 margin = w >> 8;
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
            U256 v;
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
        converged = hi - lo <= tol;
        return (lo + hi) >> 1;
    }

    // the mixed reserve's payout q. H(q) = g(q)/(a - q) is increasing in q with one root, where g itself also vanishes at the
    // crossing price q == a; H's sign is g's below a and the opposite above a. the bracket is closed form at this Phi: the
    // pure-sell payout R (1 - e^(-b/(w S Phi))) is at or below the root and b times the pure-buy price a/(w S Phi ln(1 + a/R))
    // is at or above it. the tolerance is a 256th of one satoshi of price, q = b p
    inline U256 SolveMixed(int64_t W, int64_t R, int64_t a, const U256 &bq, const U256 &SPhi, int &probes, bool &converged)
    {
        U256 rq = U256(static_cast<uint64_t>(R)) << FRACTION_BITS;
        U256 aq = U256(static_cast<uint64_t>(a)) << FRACTION_BITS;
        auto probe = [&](const U256 &q, bool &haveValue, U256 &value) -> bool
        {
            haveValue = false;
            if (q == 0)
            {
                return false;
            }
            probes++;
            bool haveMag;
            U256 mag;
            bool gPositive = GValue(W, R, rq, aq, bq, SPhi, q, haveMag, mag);
            if (q == aq)
            {
                // H(a) > 0  <=>  w S Phi > b R / a
                U256 wq = (U256(static_cast<uint64_t>(W)) << FRACTION_BITS) / U256(static_cast<uint64_t>(SATOSHI));
                U256 bra;
                return !DivQChecked(MulQ(bq, rq), aq, bra) || MulQ(SPhi, wq) > bra;
            }
            bool above = q < aq ? gPositive : !gPositive;
            if (haveMag)
            {
                haveValue = DivQChecked(mag, q < aq ? aq - q : q - aq, value);
            }
            return above;
        };
        U256 cm = DivQ(bq, SPhi);
        U256 y = (cm * static_cast<uint32_t>(SATOSHI)) / U256(static_cast<uint64_t>(W));
        uint64_t k;
        U256 t, phi;
        ExpParts(y, k, t, phi);
        U256 Ey = k >= 127 ? U256(0) : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
        U256 lo = rq - MulQ(rq, Ey);
        bool negative;
        U256 cb = WLn(W, rq + aq, static_cast<uint64_t>(R), negative);
        U256 denom = MulQ(cb, SPhi);
        U256 hi = rq + aq - 1;
        U256 qbuy;
        if (denom != 0 && DivQChecked(MulQ(aq, bq), denom, qbuy) && qbuy < hi)
        {
            hi = qbuy;
        }
        if (hi <= lo)
        {
            return lo;
        }
        bool haveLo, haveHi;
        U256 vlo, vhi;
        if (probe(lo, haveLo, vlo))
        {
            return lo;
        }
        if (!probe(hi, haveHi, vhi))
        {
            return hi;
        }
        U256 tol = (bq / U256(static_cast<uint64_t>(SATOSHI))) >> 8;
        if (tol == 0)
        {
            tol = 1;
        }
        return Bracket(lo, hi, haveLo, vlo, haveHi, vhi, probe, tol, converged);
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
    inline U256 RoundPrice(const U256 &priceQ, bool noFlow, bool netBuy)
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
        static const U256 bigSatoshi(static_cast<uint64_t>(SATOSHI));
        static const U256 maxPrice(static_cast<uint64_t>(INT64_MAX));
        static const U256 tolX = U256(1) << BRACKET_TOL_X_BITS;

        evaluations = 0;
        int probes = 0;
        bool exhausted = false;

        if (!ValidInputs(R, W, S, a, b, pCross))
        {
            return ERR_INPUT;
        }
        size_t n = R.size();
        U256 bigS(static_cast<uint64_t>(S));
        U256 Sq = bigS << FRACTION_BITS;

        std::vector<bool> isSource(n, false);
        bool anySource = false;
        U256 B(0);
        for (size_t i = 0; i < n; i++)
        {
            B += U256(static_cast<uint64_t>(b[i])) << FRACTION_BITS;
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
        std::vector<U256> cbuy(n);
        U256 xhi(0);
        for (size_t i = 0; i < n; i++)
        {
            if (a[i])
            {
                bool negative;
                cbuy[i] = WLn(W[i], (U256(static_cast<uint64_t>(R[i])) + U256(static_cast<uint64_t>(a[i]))) << FRACTION_BITS,
                              static_cast<uint64_t>(R[i]), negative);
                xhi += cbuy[i];
            }
        }
        U256 sellFloor(0);
        if (B != 0)
        {
            bool negative;
            sellFloor = LnRatio(Sq - B, static_cast<uint64_t>(S), negative);
        }

        // state of the last evaluation; the via units and source prices also warm-start the next one
        std::vector<U256> via(n), bq(n), qs(n);
        std::vector<int64_t> srcPrice(n, 0);
        U256 E, Phi, SPhi;
        std::vector<U256> mixedB(n), mixedSPhi(n), mixedQ(n);
        std::vector<bool> haveMixed(n, false);
        auto solveMixed = [&](size_t j, bool &converged) -> U256
        {
            if (haveMixed[j] && mixedB[j] == bq[j] && mixedSPhi[j] == SPhi)
            {
                return mixedQ[j];
            }
            U256 q = SolveMixed(W[j], R[j], a[j], bq[j], SPhi, probes, converged);
            if (probes > MAX_PROBES_PER_SOLVE)
            {
                exhausted = true;
                converged = false;
            }
            if (converged)
            {
                haveMixed[j] = true;
                mixedB[j] = bq[j];
                mixedSPhi[j] = SPhi;
                mixedQ[j] = q;
            }
            return q;
        };

        // the sells per reserve at the current via units. via units are minted by their first legs in this import, so they cannot
        // empty the pool and are not bounded by the supply; the user sells alone are bounded by ERR_EMPTIES. the total must stay
        // representable, below 2^63 units, which also keeps every product of a reserve amount and a unit count inside 256 bits
        auto sells = [&]() -> bool
        {
            static const U256 maxUnits = U256(static_cast<uint64_t>(INT64_MAX)) << FRACTION_BITS;
            U256 total(0);
            for (size_t i = 0; i < n; i++)
            {
                bq[i] = (U256(static_cast<uint64_t>(b[i])) << FRACTION_BITS) + via[i];
                total += bq[i];
            }
            return total < maxUnits;
        };

        // F(x) = sum(c_i(x)) - x at x = t - off. returns true when F <= 0 or x is infeasible (the root is below); sets
        // haveValue and value to |F| when it is defined. resolves the via units at this x first
        auto evaluate = [&](const U256 &t, const U256 &off, bool &haveValue, U256 &value) -> bool
        {
            evaluations++;

            // the via units and source prices warm-start the next evaluation only from an evaluation that completed; one that
            // finds this x infeasible leaves them as they were, so a stale state can never make a feasible x read infeasible
            const std::vector<U256> viaIn(via);
            const std::vector<int64_t> priceIn(srcPrice);
            auto infeasible = [&]() -> bool
            {
                via = viaIn;
                srcPrice = priceIn;
                return true;
            };

            // past the probe budget every evaluation reads infeasible; the outer loops then end cheaply and Clear refuses below
            if (exhausted)
            {
                return infeasible();
            }

            haveValue = false;
            bool xNegative = t < off;
            U256 xMag = xNegative ? off - t : t - off;
            if (!ExpPhi(xNegative, xMag, E, Phi))
            {
                return infeasible();
            }
            SPhi = Phi * bigS;
            if (anySource)
            {
                for (int iteration = 0; iteration < MAX_VIA_ITERATIONS; iteration++)
                {
                    if (!sells())
                    {
                        return infeasible();
                    }
                    std::vector<int64_t> newPrice(srcPrice);
                    std::vector<U256> nextVia(n);
                    for (size_t j = 0; j < n; j++)
                    {
                        if (!isSource[j])
                        {
                            continue;
                        }
                        U256 priceQ;
                        bool netBuy;
                        if (bq[j] == 0)
                        {
                            U256 dS = MulQ(cbuy[j], SPhi);
                            if (dS == 0)
                            {
                                return infeasible();
                            }
                            priceQ = DivQ((U256(static_cast<uint64_t>(a[j])) * bigSatoshi) << FRACTION_BITS, dS);
                            netBuy = true;
                        }
                        else
                        {
                            bool converged = true;
                            qs[j] = solveMixed(j, converged);
                            if (!converged)
                            {
                                return infeasible();
                            }
                            priceQ = DivQ(qs[j] * bigSatoshi, bq[j]);
                            netBuy = (U256(static_cast<uint64_t>(a[j])) << FRACTION_BITS) > qs[j];
                        }
                        U256 price = RoundPrice(priceQ, false, netBuy);
                        if (price == 0 || price > maxPrice)
                        {
                            return infeasible();
                        }
                        newPrice[j] = static_cast<int64_t>(price.GetLow64());
                        for (size_t k = 0; k < n; k++)
                        {
                            if ((*pCross)[j][k])
                            {
                                U256 units;
                                if (!DivQChecked((U256(static_cast<uint64_t>((*pCross)[j][k])) * bigSatoshi) << FRACTION_BITS,
                                                 U256(static_cast<uint64_t>(newPrice[j])) << FRACTION_BITS, units))
                                {
                                    return infeasible();
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
                return infeasible();
            }
            U256 pos(0), negSum(0);
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
                    bool converged = true;
                    qs[i] = solveMixed(i, converged);
                    if (!converged)
                    {
                        return infeasible();
                    }
                    bool negative;
                    U256 m = WLn(W[i], ((U256(static_cast<uint64_t>(R[i])) + U256(static_cast<uint64_t>(a[i]))) << FRACTION_BITS) - qs[i],
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
            U256 lhs = pos + (xNegative ? xMag : U256(0));
            U256 rhs = negSum + (xNegative ? U256(0) : xMag);
            haveValue = true;
            value = lhs > rhs ? lhs - rhs : rhs - lhs;
            return !(lhs > rhs);
        };

        // the sells-only sellFloor is a lower bound without via legs; with them the root can lie below it, so extend downward
        U256 off = sellFloor, lo(0);
        bool haveLo, haveHi;
        U256 vlo, vhi;
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
        U256 hi = off + xhi;
        U256 tFinal;
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
            bool converged = true;
            tFinal = Bracket(lo, hi, haveLo, vlo, haveHi, vhi,
                             [&](const U256 &t, bool &haveValue, U256 &value) { return evaluate(t, off, haveValue, value); },
                             tolX,
                             converged);
            if (!converged)
            {
                return ERR_RANGE;
            }
        }
        // evaluate once more at the chosen point so the state belongs to it
        bool haveFinal;
        U256 vFinal;
        if (evaluate(tFinal, off, haveFinal, vFinal) && !haveFinal)
        {
            return ERR_RANGE;
        }

        if (exhausted)
        {
            return ERR_RANGE;
        }

        prices.resize(n);
        for (size_t i = 0; i < n; i++)
        {
            U256 rq = U256(static_cast<uint64_t>(R[i])) << FRACTION_BITS;
            U256 priceQ;
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
                U256 dS = MulQ(cbuy[i], SPhi);
                if (dS == 0)
                {
                    return ERR_RANGE;
                }
                priceQ = DivQ((U256(static_cast<uint64_t>(a[i])) * bigSatoshi) << FRACTION_BITS, dS);
            }
            else if (!a[i])
            {
                // pure sell: R' = R e^(-b / (w S Phi)); the sellers receive R - R'
                U256 cm = DivQ(bq[i], SPhi);
                U256 y = (cm * bigSatoshi) / U256(static_cast<uint64_t>(W[i]));
                uint64_t k;
                U256 t, phi;
                ExpParts(y, k, t, phi);
                U256 Ey = k >= 127 ? U256(0) : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
                U256 dR = rq - MulQ(rq, Ey);
                priceQ = DivQ(dR * bigSatoshi, bq[i]);
            }
            else
            {
                priceQ = DivQ(qs[i] * bigSatoshi, bq[i]);
            }
            bool noFlow = !a[i] && bq[i] == 0;
            bool netBuy = bq[i] == 0 || (a[i] && (U256(static_cast<uint64_t>(a[i])) << FRACTION_BITS) > qs[i]);
            U256 price = RoundPrice(priceQ, noFlow, netBuy);
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
