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

    enum { ERR_NONE = 0, ERR_EMPTIES = 1, ERR_RANGE = 2, ERR_INPUT = 3, ERR_UNCERTIFIED = 4 };

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

    // ---- clearing: one price per reserve for every conversion in an import, used in both directions ----------------------
    //
    // model, dimensionless: alpha_i = a_i/R_i, beta_i = b_i/(w_i S), gamma_ji = c_ji w_j/(R_j w_i), Phi(u) = (e^u - 1)/u,
    // psi = 1/Phi, unknowns x = ln(S'/S) and u_i = ln(R_i'/R_i):
    //     reserve i:  Phi(u_i)(u_i + k_i) = alpha_i,   k_i = beta_i psi(x) + sum_j gamma_ji psi(u_j)
    //     supply:     x = sum_i w_i u_i
    //     price:      p_i = (R_i/(w_i S)) Phi(u_i)/Phi(x)
    // k_i is the sell pressure on reserve i: the units sold into it directly, and the units via legs buy at their source
    // reserve's price and sell on. in inverse prices the system is off-diagonally antitone and one weight vector makes every
    // column of its Jacobian diagonally dominant at every state while direct sells are below the supply, so it has exactly one
    // solution, and when every equation is <= 0 at one point and >= 0 at another the solution lies between the two points.
    // that sign test is the acceptance: no result is returned without it. the solve that produces the candidate is Newton per
    // reserve in u inside a closed-form bracket, Newton on the via pressures at fixed x (concave, monotone from below), Newton
    // in e^x on the supply equation inside its exact bracket, then Newton on the whole system to the arithmetic floor.
    // one price per reserve is returned: a whole number of satoshis inside an enclosure narrower than 2^-SNAP_BITS of the
    // price is the price, and otherwise the satoshi below or above the enclosure's midpoint, which is the exact price's own
    // floor and ceiling whenever the enclosure does not straddle a whole satoshi. each coupled reserve (a via source or target,
    // or one bought and sold) is then flipped between its two candidates while that raises the integer end state against the
    // starting curve, for at most MAX_ROUND_PASSES passes. with one price the pool can still lose about (gross two-way flow) x
    // (satoshi / price)^2 to rounding, and ERR_NONE does not promise a valid end state, so the caller computes the end state,
    // refuses an emptied reserve, and tests it together with the fees the import leaves (EndsBelowCurve). every path is
    // bounded and integer-only

    static const int SCALAR_TOL_BITS = 100;     // Newton step in u, relative to 1 + |u|
    static const int VIA_RES_BITS = 90;         // via residual, relative to 1 + k
    static const int OUTER_TOL_BITS = 80;       // Newton step in x, relative to 1 + |x|
    static const int STALL_BITS = 40;           // below this a step or residual that fails to halve ends its loop (arithmetic floor)
    static const int POLISH_RES_BITS = 116;     // whole-system residual target, relative to the equation's scale
    static const int CERT_BITS = 96;            // acceptance offset, relative to the equation's scale
    static const int MARGIN_BITS = 108;         // the two sign tests must clear zero by this much of the scale
    static const int ACCEPT_BITS = 32;          // the enclosure must be narrower than 2^-32 in ln(price)
    static const int SNAP_BITS = 70;            // a whole-satoshi price inside an enclosure narrower than this (relative) is the price
    static const int MAX_ROUND_PASSES = 4;      // passes over the coupled reserves when choosing each one's rounding
    static const int PAD_BITS = 100;            // outward padding of each price for the truncation of its own arithmetic
    static const int MAX_SCALAR_STEPS = 128;
    static const int MAX_VIA_STEPS = 64;
    static const int MAX_OUTER_STEPS = 64;
    static const int MAX_POLISH_STEPS = 8;

    // thrown inside Clear and caught there: a value left the arithmetic's range (ERR_RANGE) or a loop reached its cap
    // (ERR_UNCERTIFIED)
    struct ClearFault
    {
        int error;
    };

    struct ClearStats
    {
        int exponentials, logarithms, linearSolves, scalarSolves, viaSteps, outerSteps, polishSteps, roundingFlips;
        ClearStats() : exponentials(0), logarithms(0), linearSolves(0), scalarSolves(0), viaSteps(0), outerSteps(0), polishSteps(0), roundingFlips(0) {}
    };

    // signed Q128: a magnitude and a sign. zero is never negative
    struct SQ
    {
        U256 m;
        bool n;
        SQ() : m(), n(false) {}
        explicit SQ(const U256 &magnitude, bool negative = false) : m(magnitude), n(negative && magnitude != U256()) {}
    };

    inline SQ SNeg(const SQ &a)
    {
        return SQ(a.m, !a.n);
    }

    inline SQ SAdd(const SQ &a, const SQ &b)
    {
        if (a.n == b.n)
        {
            return SQ(a.m + b.m, a.n);
        }
        if (a.m >= b.m)
        {
            return SQ(a.m - b.m, a.n);
        }
        return SQ(b.m - a.m, b.n);
    }

    inline SQ SSub(const SQ &a, const SQ &b)
    {
        return SAdd(a, SNeg(b));
    }

    inline bool SLess(const SQ &a, const SQ &b)
    {
        if (a.n != b.n)
        {
            return a.n;
        }
        return a.n ? a.m > b.m : a.m < b.m;
    }

    inline SQ SHalf(const SQ &a)
    {
        return SQ(a.m >> 1, a.n);
    }

    // a * b in Q128; a fault when the bit lengths allow the product more than 128 integer bits, where MulQ would wrap
    inline U256 MulQC(const U256 &a, const U256 &b)
    {
        if (a.bits() + b.bits() > 3 * FRACTION_BITS)
        {
            throw ClearFault{ERR_RANGE};
        }
        return MulQ(a, b);
    }

    // a / b in Q128; a fault on a zero divisor or a quotient above 128 integer bits, where DivQ would wrap
    inline U256 DivQC(U256 a, U256 b)
    {
        if (b == U256())
        {
            throw ClearFault{ERR_RANGE};
        }
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
            throw ClearFault{ERR_RANGE};
        }
        return U256(f0, f1, q.w[0], q.w[1]);
    }

    inline SQ SMul(const SQ &a, const SQ &b)
    {
        return SQ(MulQC(a.m, b.m), a.n != b.n);
    }

    inline SQ SDiv(const SQ &a, const SQ &b)
    {
        return SQ(DivQC(a.m, b.m), a.n != b.n);
    }

    // v * pn / pd, multiplied before dividing so a small ratio is never scaled up
    inline U256 Ratio(const U256 &v, const U256 &pn, const U256 &pd)
    {
        return DivQC(MulQC(v, pn), pd);
    }

    // w u for w = W / SATOSHI with the weight exact: a rounded weight times a drained reserve's large |u| would lose bits
    inline SQ WeightTimes(int64_t W, const SQ &u)
    {
        return SQ((u.m * static_cast<uint64_t>(W)) / U256(static_cast<uint64_t>(SATOSHI)), u.n);
    }

    inline const U256 &Half()
    {
        static const U256 half = One() >> 1;
        return half;
    }

    // e^u, and Phi(u) = pd / pn as two well-scaled positives (psi(u) = pn / pd). e^u is out of range from u = 64 ln 2 and is
    // zero from u = -127 ln 2; at |u| >= 128 the exponential is not computed at all, which also keeps ExpParts' 64-bit
    // quotient exact
    inline void PhiAt(const SQ &u, U256 &E, U256 &pn, U256 &pd, ClearStats &stats)
    {
        static const U256 deep = U256(128) << FRACTION_BITS;
        if (u.m >= deep)
        {
            if (!u.n)
            {
                throw ClearFault{ERR_RANGE};
            }
            E = U256();
            pn = u.m;
            pd = One();
            return;
        }
        stats.exponentials++;
        uint64_t k;
        U256 t, phi;
        ExpParts(u.m, k, t, phi);
        if (!u.n)
        {
            if (k >= 64)
            {
                throw ClearFault{ERR_RANGE};
            }
            if (k == 0)
            {
                E = One() + t;
                pn = One();
                pd = phi;
                return;
            }
            E = (One() + t) << static_cast<unsigned int>(k);
            pn = u.m;
            pd = E - One();
            return;
        }
        if (k == 0)
        {
            E = DivQ(One(), One() + t);
            pn = One() + t;
            pd = phi;
            return;
        }
        E = k >= 127 ? U256() : DivQ(One(), (One() + t) << static_cast<unsigned int>(k));
        pn = u.m;
        pd = One() - E;
    }

    // Phi'(u) = (e^u - Phi)/u, positive; the series near zero, where the quotient cancels
    inline U256 DPhiAt(const SQ &u, const U256 &E, const U256 &pn, const U256 &pd)
    {
        static const U256 third = One() / U256(3);
        if (u.m < (One() >> 24))
        {
            U256 slope = MulQ(u.m, third);
            return u.n ? Half() - slope : Half() + slope;
        }
        U256 Phi = DivQC(pd, pn);
        if (!u.n)
        {
            return E > Phi ? DivQC(E - Phi, u.m) : U256();
        }
        return Phi > E ? DivQC(Phi - E, u.m) : U256();
    }

    // |psi'(u)| = Phi' / Phi^2, in (0, 1)
    inline U256 DPsiAbs(const U256 &dphi, const U256 &pn, const U256 &pd)
    {
        return Ratio(Ratio(dphi, pn, pd), pn, pd);
    }

    struct ReserveState
    {
        SQ u;               // ln(R'/R)
        U256 E, pn, pd;     // e^u and psi(u) = pn / pd
        U256 dpsi;          // |psi'(u)|
        U256 g;             // alpha |psi'| + 1 = -dk/du
        U256 vp;            // d psi / d k
        U256 k;             // the sell pressure it was solved at
        ReserveState() : u(), E(One()), pn(One()), pd(One()), dpsi(Half()), g(One()), vp(), k() {}
    };

    // one reserve: u with Phi(u)(u + k) = alpha. m(u) = e^u - 1 + k Phi(u) - alpha is increasing and convex; the root is in
    // [-k/(1 + alpha), 0] when k >= alpha and in [0, ln(1 + alpha)] otherwise. Newton from the warm start or the closed-form
    // start, bisection whenever a step leaves the bracket
    inline void SolveReserve(const U256 &alpha, const U256 &k, const U256 &lnA, ReserveState &r, const SQ *pWarm, ClearStats &stats)
    {
        stats.scalarSolves++;
        SQ u;
        U256 E, pn, pd, dphi;
        if (alpha == U256() || k == U256())
        {
            u = alpha == U256() ? SQ(k, true) : SQ(lnA);        // a pure sell, or a pure buy
            PhiAt(u, E, pn, pd, stats);
            dphi = DPhiAt(u, E, pn, pd);
        }
        else
        {
            SQ lo, hi, start;
            if (k >= alpha)
            {
                lo = SQ(DivQC(k, One() + alpha), true);
                start = lo;
            }
            else
            {
                hi = SQ(lnA);
                U256 d1 = DivQC(alpha - k, One() + (k >> 1));
                start = SQ(d1 < lnA ? d1 : lnA);
            }
            u = (pWarm && !SLess(*pWarm, lo) && !SLess(hi, *pWarm)) ? *pWarm : start;
            bool haveLast = false, done = false;
            U256 lastStep;
            for (int it = 0; it < MAX_SCALAR_STEPS; it++)
            {
                PhiAt(u, E, pn, pd, stats);
                dphi = DPhiAt(u, E, pn, pd);
                // e^u - 1, signed
                SQ em1 = u.n ? SQ(One() - E, true) : SQ(E - One());
                SQ m = SSub(SAdd(em1, SQ(Ratio(k, pd, pn))), SQ(alpha));
                U256 mp = E + MulQC(k, dphi);
                if (m.n)
                {
                    lo = u;
                }
                else
                {
                    hi = u;
                }
                if (m.m == U256() || mp == U256())
                {
                    done = true;
                    break;
                }
                SQ step(DivQC(m.m, mp), m.n);
                U256 tol = (One() + u.m) >> SCALAR_TOL_BITS;
                if (step.m <= tol)
                {
                    done = true;
                    break;
                }
                if (haveLast && step.m < (One() >> STALL_BITS) && (step.m << 1) > lastStep)
                {
                    done = true;
                    break;
                }
                haveLast = true;
                lastStep = step.m;
                SQ un = SSub(u, step);
                if (!(SLess(lo, un) && SLess(un, hi)))
                {
                    un = SHalf(SAdd(lo, hi));
                    if (SSub(hi, lo).m <= tol)
                    {
                        done = true;
                        break;
                    }
                    haveLast = false;
                }
                u = un;
            }
            if (!done)
            {
                throw ClearFault{ERR_UNCERTIFIED};
            }
        }
        r.u = u;
        r.E = E;
        r.pn = pn;
        r.pd = pd;
        r.k = k;
        r.dpsi = DPsiAbs(dphi, pn, pd);
        r.g = MulQC(alpha, r.dpsi) + One();
        r.vp = DivQC(r.dpsi, r.g);
    }

    // A x = rhs by elimination without pivoting: the matrices here are M-matrices with dominant columns
    inline std::vector<SQ> SolveLinear(std::vector<std::vector<SQ>> A, std::vector<SQ> rhs, ClearStats &stats)
    {
        stats.linearSolves++;
        size_t m = A.size();
        for (size_t c = 0; c < m; c++)
        {
            const SQ piv = A[c][c];
            if (piv.n || piv.m == U256())
            {
                throw ClearFault{ERR_RANGE};
            }
            for (size_t rr = c + 1; rr < m; rr++)
            {
                if (A[rr][c].m != U256())
                {
                    SQ f = SDiv(A[rr][c], piv);
                    for (size_t cc = c + 1; cc < m; cc++)
                    {
                        if (A[c][cc].m != U256())
                        {
                            A[rr][cc] = SSub(A[rr][cc], SMul(f, A[c][cc]));
                        }
                    }
                    rhs[rr] = SSub(rhs[rr], SMul(f, rhs[c]));
                }
            }
        }
        std::vector<SQ> x(m);
        for (size_t c = m; c-- > 0;)
        {
            SQ s = rhs[c];
            for (size_t cc = c + 1; cc < m; cc++)
            {
                if (A[c][cc].m != U256())
                {
                    s = SSub(s, SMul(A[c][cc], x[cc]));
                }
            }
            x[c] = SDiv(s, A[c][c]);
        }
        return x;
    }

    // weight * ln(numerator / denominator) for positive integers, signed Q128
    inline SQ CurveTerm(int64_t numerator, int64_t denominator, int64_t weight, ClearStats &stats)
    {
        stats.logarithms++;
        bool negative;
        U256 mag = LnRatio(U256(static_cast<uint64_t>(numerator)) << FRACTION_BITS, static_cast<uint64_t>(denominator), negative);
        return SQ(mag * static_cast<uint64_t>(weight), negative);
    }

    // sum_i W_i ln(R1_i / R0_i) - SATOSHI ln(S1 / S0), signed Q128 (times SATOSHI): negative when the state (R1, S1) is below the
    // curve through (R0, S0). every amount must be positive and the three vectors the same length; EndsBelowCurve tests both
    inline SQ CurveMeasure(const std::vector<int64_t> &R0,
                           const std::vector<int64_t> &W,
                           int64_t S0,
                           const std::vector<int64_t> &R1,
                           int64_t S1,
                           ClearStats &stats)
    {
        SQ total;
        for (size_t i = 0; i < R0.size(); i++)
        {
            if (R1[i] != R0[i])
            {
                total = SAdd(total, CurveTerm(R1[i], R0[i], W[i], stats));
            }
        }
        if (S1 != S0)
        {
            total = SSub(total, CurveTerm(S1, S0, SATOSHI, stats));
        }
        return total;
    }

    // true when the state (R1, S1) is below the curve through (R0, S0). a state with an empty reserve or no supply is below, and
    // so is any malformed input. for the caller: the end state of an import's conversions, with the fees the import leaves in the
    // basket added, must not be below the curve it started on
    inline bool EndsBelowCurve(const std::vector<int64_t> &R0,
                               const std::vector<int64_t> &W,
                               int64_t S0,
                               const std::vector<int64_t> &R1,
                               int64_t S1)
    {
        size_t n = R0.size();
        if (!n || W.size() != n || R1.size() != n || S0 <= 0 || S1 <= 0)
        {
            return true;
        }
        for (size_t i = 0; i < n; i++)
        {
            if (R0[i] <= 0 || R1[i] <= 0 || W[i] <= 0 || W[i] > SATOSHI)
            {
                return true;
            }
        }
        ClearStats stats;
        return CurveMeasure(R0, W, S0, R1, S1, stats).n;
    }

    // each reserve's curve term at the end reserve it was computed for, and the supply's, so a term is recomputed only when its
    // amount changes
    struct CurveTerms
    {
        std::vector<bool> have;
        std::vector<int64_t> at;
        std::vector<SQ> term;
        bool haveSupply;
        int64_t atSupply;
        SQ supplyTerm;
        CurveTerms() : haveSupply(false), atSupply(0) {}
    };

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
            if (R[i] <= 0 || W[i] <= 0 || W[i] > SATOSHI || a[i] < 0 || b[i] < 0)
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

    // every equation at a point, its scale, and optionally the matrix A = -dE/d(u, x) with the price sensitivities
    struct SystemAt
    {
        std::vector<SQ> eq;
        std::vector<U256> scale;
        std::vector<std::vector<SQ>> A;
        std::vector<U256> ratio;        // Phi'/Phi per reserve: the sensitivity of ln(price) to u
        U256 ratio0;                    // the same for x
    };

    inline int ClearInner(const std::vector<int64_t> &R,
                          const std::vector<int64_t> &W,
                          int64_t S,
                          const std::vector<int64_t> &a,
                          const std::vector<int64_t> &b,
                          const std::vector<std::vector<int64_t>> *pCross,
                          std::vector<int64_t> &prices,
                          ClearStats &stats)
    {
        static const U256 bigSatoshi(static_cast<uint64_t>(SATOSHI));
        static const U256 maxPrice(static_cast<uint64_t>(INT64_MAX));
        static const U256 kLimit = U256(1) << (FRACTION_BITS + 96);     // sell pressure of 2^96 or more is out of range
        const U256 zero;

        size_t n = R.size();
        U256 bigS(static_cast<uint64_t>(S));
        U256 B;
        for (size_t i = 0; i < n; i++)
        {
            B += U256(static_cast<uint64_t>(b[i]));
        }
        if (B >= bigS)
        {
            return ERR_EMPTIES;
        }
        bool haveSells = B != zero;

        std::vector<U256> alpha(n), beta(n), w(n);
        std::vector<std::vector<U256>> gamma(n, std::vector<U256>(n));       // gamma[j][i]: source j, target i
        std::vector<bool> isTarget(n, false), isSource(n, false), flow(n, false), solved(n, false);
        for (size_t i = 0; i < n; i++)
        {
            alpha[i] = (U256(static_cast<uint64_t>(a[i])) << FRACTION_BITS) / U256(static_cast<uint64_t>(R[i]));
            beta[i] = ((U256(static_cast<uint64_t>(b[i])) * bigSatoshi) << FRACTION_BITS) /
                      (U256(static_cast<uint64_t>(W[i])) * bigS);
            w[i] = (U256(static_cast<uint64_t>(W[i])) << FRACTION_BITS) / bigSatoshi;
        }
        if (pCross)
        {
            for (size_t j = 0; j < n; j++)
            {
                for (size_t i = 0; i < n; i++)
                {
                    if ((*pCross)[j][i])
                    {
                        gamma[j][i] = ((U256(static_cast<uint64_t>((*pCross)[j][i])) * static_cast<uint64_t>(W[j])) << FRACTION_BITS) /
                                      (U256(static_cast<uint64_t>(R[j])) * static_cast<uint64_t>(W[i]));
                        isTarget[i] = true;
                        isSource[j] = true;
                    }
                }
            }
        }
        std::vector<size_t> targets, sources, idx;
        for (size_t i = 0; i < n; i++)
        {
            flow[i] = a[i] || b[i] || isTarget[i];
            if (isTarget[i])
            {
                targets.push_back(i);
            }
            if (isSource[i])
            {
                sources.push_back(i);
            }
            if (flow[i])
            {
                idx.push_back(i);
            }
        }
        std::vector<U256> lnA(n);
        U256 xhi;
        for (size_t i = 0; i < n; i++)
        {
            if (a[i])
            {
                stats.logarithms++;
                bool negative;
                lnA[i] = LnRatio((U256(static_cast<uint64_t>(R[i])) + U256(static_cast<uint64_t>(a[i]))) << FRACTION_BITS,
                                 static_cast<uint64_t>(R[i]), negative);
                xhi += (lnA[i] * static_cast<uint64_t>(W[i])) / bigSatoshi;
            }
        }
        std::vector<ReserveState> res(n);
        std::vector<U256> kappa(n);

        // the via-target block of I - Gamma^T V'
        auto viaMatrix = [&]() -> std::vector<std::vector<SQ>>
        {
            std::vector<std::vector<SQ>> J(targets.size(), std::vector<SQ>(targets.size()));
            for (size_t c = 0; c < targets.size(); c++)
            {
                size_t j = targets[c];
                for (size_t r = 0; r < targets.size(); r++)
                {
                    size_t i = targets[r];
                    SQ e = gamma[j][i] != zero ? SQ(MulQC(gamma[j][i], res[j].vp), true) : SQ();
                    J[r][c] = i == j ? SAdd(SQ(One()), e) : e;
                }
            }
            return J;
        };

        auto solveOne = [&](size_t i, const U256 &k)
        {
            SQ warm = res[i].u;
            SolveReserve(alpha[i], k, lnA[i], res[i], solved[i] ? &warm : nullptr, stats);
            solved[i] = true;
        };

        // all reserves at the x whose psi(x) = pn0 / pd0; returns sum w u
        auto inner = [&](const U256 &pn0, const U256 &pd0) -> SQ
        {
            for (size_t i = 0; i < n; i++)
            {
                kappa[i] = (haveSells && beta[i] != zero) ? Ratio(beta[i], pn0, pd0) : U256();
            }
            for (size_t i = 0; i < n; i++)
            {
                if (flow[i] && !isTarget[i])
                {
                    solveOne(i, kappa[i]);
                }
            }
            if (targets.size())
            {
                for (size_t t = 0; t < targets.size(); t++)
                {
                    size_t i = targets[t];
                    U256 k0 = solved[i] ? res[i].k : kappa[i];
                    if (k0 < kappa[i])
                    {
                        k0 = kappa[i];
                    }
                    if (k0 >= kLimit)
                    {
                        throw ClearFault{ERR_RANGE};
                    }
                    solveOne(i, k0);
                }
                bool haveLast = false, ok = false;
                U256 lastRes;
                for (int it = 0; it < MAX_VIA_STEPS; it++)
                {
                    stats.viaSteps++;
                    U256 worst;
                    std::vector<SQ> rhs(targets.size());
                    for (size_t r = 0; r < targets.size(); r++)
                    {
                        size_t i = targets[r];
                        U256 G = kappa[i];
                        for (size_t s = 0; s < sources.size(); s++)
                        {
                            size_t j = sources[s];
                            if (gamma[j][i] != zero)
                            {
                                G += Ratio(gamma[j][i], res[j].pn, res[j].pd);
                            }
                        }
                        rhs[r] = SSub(SQ(G), SQ(res[i].k));
                        U256 rel = DivQC(rhs[r].m, One() + res[i].k);
                        if (rel > worst)
                        {
                            worst = rel;
                        }
                    }
                    if (worst <= (One() >> VIA_RES_BITS))
                    {
                        ok = true;
                        break;
                    }
                    if (haveLast && worst < (One() >> STALL_BITS) && (worst << 1) > lastRes)
                    {
                        ok = true;
                        break;
                    }
                    haveLast = true;
                    lastRes = worst;
                    std::vector<SQ> delta = SolveLinear(viaMatrix(), rhs, stats);
                    for (size_t r = 0; r < targets.size(); r++)
                    {
                        size_t i = targets[r];
                        SQ kn = SAdd(SQ(res[i].k), delta[r]);
                        U256 kv = (kn.n || kn.m < kappa[i]) ? kappa[i] : kn.m;
                        if (kv >= kLimit)
                        {
                            throw ClearFault{ERR_RANGE};
                        }
                        solveOne(i, kv);
                    }
                }
                if (!ok)
                {
                    throw ClearFault{ERR_UNCERTIFIED};
                }
            }
            SQ total;
            for (size_t i = 0; i < n; i++)
            {
                if (flow[i])
                {
                    total = SAdd(total, WeightTimes(W[i], res[i].u));
                }
            }
            return total;
        };

        // d(sum w u)/dx >= 0 at the current state, q0 = |psi'(x)|
        auto slope = [&](const U256 &q0) -> U256
        {
            std::vector<U256> dk(n);
            for (size_t i = 0; i < n; i++)
            {
                dk[i] = beta[i] != zero ? MulQC(beta[i], q0) : U256();
            }
            if (targets.size())
            {
                std::vector<SQ> rhs(targets.size());
                for (size_t r = 0; r < targets.size(); r++)
                {
                    size_t i = targets[r];
                    U256 s = dk[i];
                    for (size_t t = 0; t < sources.size(); t++)
                    {
                        size_t j = sources[t];
                        if (!isTarget[j] && gamma[j][i] != zero && dk[j] != zero)
                        {
                            s += MulQC(MulQC(gamma[j][i], res[j].vp), dk[j]);
                        }
                    }
                    rhs[r] = SQ(s);
                }
                std::vector<SQ> sol = SolveLinear(viaMatrix(), rhs, stats);
                for (size_t r = 0; r < targets.size(); r++)
                {
                    dk[targets[r]] = sol[r].n ? U256() : sol[r].m;
                }
            }
            U256 total;
            for (size_t i = 0; i < n; i++)
            {
                if (flow[i] && dk[i] != zero)
                {
                    total += MulQC(w[i], DivQC(dk[i], res[i].g));
                }
            }
            return total;
        };

        // ---- x: Newton in e^x on Phi(x) F(x), F = sum w u - x, inside [ln(1 - B/S), sum w ln(1 + alpha)] ----
        SQ x;
        if (!haveSells)
        {
            stats.outerSteps++;
            x = inner(One(), One());
        }
        else
        {
            stats.logarithms++;
            bool negative;
            SQ lo(LnRatio((bigS - B) << FRACTION_BITS, static_cast<uint64_t>(S), negative), true), hi(xhi);
            x = lo;
            bool haveLast = false, ok = false;
            U256 lastStep;
            for (int it = 0; it < MAX_OUTER_STEPS; it++)
            {
                stats.outerSteps++;
                U256 E0, pn0, pd0;
                PhiAt(x, E0, pn0, pd0, stats);
                U256 dphi0 = DPhiAt(x, E0, pn0, pd0);
                SQ F = SSub(inner(pn0, pd0), x);
                if (F.m == zero)
                {
                    ok = true;
                    break;
                }
                if (F.n)
                {
                    hi = x;
                }
                else
                {
                    lo = x;
                }
                U256 q0 = DPsiAbs(dphi0, pn0, pd0);
                SQ Fp = SSub(SQ(slope(q0)), SQ(One()));
                U256 r0 = Ratio(dphi0, pn0, pd0);
                SQ den = SAdd(Fp, SMul(SQ(r0), F));
                bool haveStep = false;
                SQ step;
                if (den.m != zero)
                {
                    SQ onePlus = SAdd(SQ(One()), SNeg(SDiv(F, den)));
                    if (!onePlus.n && onePlus.m > (One() >> 64))
                    {
                        stats.logarithms++;
                        bool stepNegative;
                        U256 mag = LnRatio(onePlus.m, 1, stepNegative);
                        step = SQ(mag, stepNegative);
                        haveStep = true;
                    }
                }
                U256 tol = (One() + x.m) >> OUTER_TOL_BITS;
                if (haveStep)
                {
                    if (step.m <= tol)
                    {
                        ok = true;
                        break;
                    }
                    if (haveLast && step.m < (One() >> STALL_BITS) && (step.m << 1) > lastStep)
                    {
                        ok = true;
                        break;
                    }
                    haveLast = true;
                    lastStep = step.m;
                }
                SQ xn = haveStep ? SAdd(x, step) : SQ();
                if (!haveStep || !(SLess(lo, xn) && SLess(xn, hi)))
                {
                    if (SSub(hi, lo).m <= tol)
                    {
                        ok = true;
                        break;
                    }
                    xn = SHalf(SAdd(lo, hi));
                    haveLast = false;
                }
                x = xn;
            }
            if (!ok)
            {
                throw ClearFault{ERR_UNCERTIFIED};
            }
        }

        // ---- the whole system at a point ----
        // E_i = alpha_i psi(u_i) - sum_j gamma_ji psi(u_j) - u_i - beta_i psi(x) for each reserve with flow, then sum w u - x.
        // each equation's scale bounds what its arithmetic can lose: the terms themselves (each carries a relative error) and
        // every psi a coefficient multiplies (alpha, beta and gamma are rounded at 2^-128 before the product)
        size_t m = idx.size();
        auto evaluate = [&](const std::vector<SQ> &us, const SQ &xv, bool wantMatrix) -> SystemAt
        {
            SystemAt at;
            std::vector<U256> Ei(n), pni(n), pdi(n), psi(n);
            for (size_t r = 0; r < m; r++)
            {
                size_t i = idx[r];
                PhiAt(us[i], Ei[i], pni[i], pdi[i], stats);
                psi[i] = DivQC(pni[i], pdi[i]);
            }
            U256 E0, pn0 = One(), pd0 = One(), psi0;
            if (haveSells)
            {
                PhiAt(xv, E0, pn0, pd0, stats);
                psi0 = DivQC(pn0, pd0);
            }
            SQ sumwu;
            U256 sumAbs;
            for (size_t r = 0; r < m; r++)
            {
                size_t i = idx[r];
                U256 t1 = Ratio(alpha[i], pni[i], pdi[i]);
                U256 t2, t3;
                U256 sc = One() + us[i].m + psi[i];
                for (size_t s = 0; s < sources.size(); s++)
                {
                    size_t j = sources[s];
                    if (gamma[j][i] != zero)
                    {
                        t2 += Ratio(gamma[j][i], pni[j], pdi[j]);
                        sc += psi[j];
                    }
                }
                if (haveSells && beta[i] != zero)
                {
                    t3 = Ratio(beta[i], pn0, pd0);
                    sc += psi0;
                }
                at.eq.push_back(SSub(SSub(SSub(SQ(t1), SQ(t2)), us[i]), SQ(t3)));
                at.scale.push_back(sc + t1 + t2 + t3);
                SQ wu = WeightTimes(W[i], us[i]);
                sumwu = SAdd(sumwu, wu);
                sumAbs += wu.m;
            }
            at.eq.push_back(SSub(sumwu, xv));
            at.scale.push_back(One() + xv.m + sumAbs);
            if (!wantMatrix)
            {
                return at;
            }
            std::vector<U256> dps(n);
            at.ratio.assign(n, U256());
            for (size_t r = 0; r < m; r++)
            {
                size_t i = idx[r];
                U256 dphi = DPhiAt(us[i], Ei[i], pni[i], pdi[i]);
                dps[i] = DPsiAbs(dphi, pni[i], pdi[i]);
                at.ratio[i] = Ratio(dphi, pni[i], pdi[i]);
            }
            U256 q0;
            if (haveSells)
            {
                U256 dphi0 = DPhiAt(xv, E0, pn0, pd0);
                q0 = DPsiAbs(dphi0, pn0, pd0);
                at.ratio0 = Ratio(dphi0, pn0, pd0);
            }
            at.A.assign(m + 1, std::vector<SQ>(m + 1));
            for (size_t r = 0; r < m; r++)
            {
                size_t i = idx[r];
                for (size_t c = 0; c < m; c++)
                {
                    size_t j = idx[c];
                    SQ e = gamma[j][i] != zero ? SQ(MulQC(gamma[j][i], dps[j]), true) : SQ();
                    if (i == j)
                    {
                        e = SAdd(SQ(One() + MulQC(alpha[i], dps[i])), e);
                    }
                    at.A[r][c] = e;
                }
                if (haveSells && beta[i] != zero)
                {
                    at.A[r][m] = SQ(MulQC(beta[i], q0), true);
                }
            }
            for (size_t c = 0; c < m; c++)
            {
                at.A[m][c] = SQ(w[idx[c]], true);
            }
            at.A[m][m] = SQ(One());
            return at;
        };
        auto worstOf = [&](const SystemAt &at) -> U256
        {
            U256 worst;
            for (size_t r = 0; r < at.eq.size(); r++)
            {
                U256 rel = DivQC(at.eq[r].m, at.scale[r]);
                if (rel > worst)
                {
                    worst = rel;
                }
            }
            return worst;
        };

        // ---- polish: Newton on the whole system until the residual reaches its target or stops halving ----
        std::vector<SQ> us(n);
        for (size_t i = 0; i < n; i++)
        {
            us[i] = res[i].u;
        }
        SystemAt at = evaluate(us, x, true);
        U256 worst = worstOf(at);
        for (int it = 0; it < MAX_POLISH_STEPS; it++)
        {
            if (worst <= (One() >> POLISH_RES_BITS))
            {
                break;
            }
            stats.polishSteps++;
            std::vector<SQ> delta = SolveLinear(at.A, at.eq, stats);      // E(candidate + delta) = E - A delta
            std::vector<SQ> us2(us);
            for (size_t r = 0; r < m; r++)
            {
                us2[idx[r]] = SAdd(us[idx[r]], delta[r]);
            }
            SQ x2 = SAdd(x, delta[m]);
            SystemAt at2 = evaluate(us2, x2, true);
            U256 worst2 = worstOf(at2);
            if (worst2 >= worst)
            {
                break;
            }
            bool halved = (worst2 << 1) <= worst;
            us = us2;
            x = x2;
            at = at2;
            worst = worst2;
            if (!halved)
            {
                break;
            }
        }

        // ---- acceptance: every equation <= 0 at candidate + delta and >= 0 at candidate - delta, by a margin ----
        std::vector<SQ> offset(m + 1);
        for (size_t r = 0; r <= m; r++)
        {
            offset[r] = SQ(at.scale[r] >> CERT_BITS);
        }
        std::vector<SQ> delta = SolveLinear(at.A, offset, stats);
        U256 width;
        for (size_t r = 0; r < m; r++)
        {
            if (delta[r].n)
            {
                return ERR_UNCERTIFIED;
            }
            U256 wd = MulQC(at.ratio[idx[r]], delta[r].m) + MulQC(at.ratio0, delta[m].m);
            if (wd > width)
            {
                width = wd;
            }
        }
        if (delta[m].n || width > (One() >> ACCEPT_BITS))
        {
            return ERR_UNCERTIFIED;
        }
        std::vector<SQ> ua(us), ub(us);
        for (size_t r = 0; r < m; r++)
        {
            ua[idx[r]] = SAdd(us[idx[r]], delta[r]);
            ub[idx[r]] = SSub(us[idx[r]], delta[r]);
        }
        SQ xa = SAdd(x, delta[m]), xb = SSub(x, delta[m]);
        SystemAt above = evaluate(ua, xa, false);
        SystemAt below = evaluate(ub, xb, false);
        for (size_t r = 0; r <= m; r++)
        {
            if (!above.eq[r].n || above.eq[r].m < (above.scale[r] >> MARGIN_BITS) ||
                below.eq[r].n || below.eq[r].m < (below.scale[r] >> MARGIN_BITS))
            {
                return ERR_UNCERTIFIED;
            }
        }

        // ---- prices: base Phi(u)/Phi(x), enclosed by (u above, x below) and (u below, x above) ----
        auto mulDiv = [&](const U256 &v, const U256 &p, const U256 &q) -> U256
        {
            // v p / q, multiplied first unless the product would leave the 128 integer bits
            if (v.bits() + p.bits() > 3 * FRACTION_BITS)
            {
                return MulQC(DivQC(v, q), p);
            }
            return DivQC(MulQ(v, p), q);
        };
        auto priceAt = [&](const U256 &base, const SQ &uv, const SQ &xv) -> U256
        {
            U256 E, pn, pd, E0, pn0, pd0;
            PhiAt(uv, E, pn, pd, stats);
            PhiAt(xv, E0, pn0, pd0, stats);
            return mulDiv(mulDiv(base, pd, pn), pn0, pd0);
        };
        prices.assign(n, 0);
        std::vector<int64_t> other(n, 0);       // the other candidate where the exact price lies between two satoshis, else 0
        U256 Ex, pnx, pdx;
        PhiAt(x, Ex, pnx, pdx, stats);
        for (size_t i = 0; i < n; i++)
        {
            U256 base = (((U256(static_cast<uint64_t>(R[i])) << FRACTION_BITS) * bigSatoshi) * bigSatoshi) /
                        (bigS * static_cast<uint64_t>(W[i]));
            if (!flow[i])
            {
                // no flow: the end spot price R / (w S'), nearest satoshi
                if (Ex == zero)
                {
                    return ERR_RANGE;
                }
                U256 p = (DivQC(base, Ex) + Half()) >> FRACTION_BITS;
                if (p == zero || p > maxPrice)
                {
                    return ERR_RANGE;
                }
                prices[i] = static_cast<int64_t>(p.GetLow64());
                continue;
            }
            U256 hi = priceAt(base, ua[i], xb);
            U256 lo = priceAt(base, ub[i], xa);
            hi += (hi >> PAD_BITS) + U256(1);
            U256 pad = (lo >> PAD_BITS) + U256(1);
            lo = lo > pad ? lo - pad : U256();
            U256 pf, pc;
            if (((hi + (One() - U256(1))) >> FRACTION_BITS) == (lo >> FRACTION_BITS) + U256(2) && (hi - lo) <= (hi >> SNAP_BITS))
            {
                // a whole number of satoshis inside a narrow enclosure is the price
                pf = (lo >> FRACTION_BITS) + U256(1);
                pc = pf;
            }
            else
            {
                U256 mid = (hi + lo) >> 1;
                pf = mid >> FRACTION_BITS;
                pc = (mid + (One() - U256(1))) >> FRACTION_BITS;
            }
            if (pf == zero || pc > maxPrice)
            {
                return ERR_RANGE;
            }
            if (pf == pc)
            {
                prices[i] = static_cast<int64_t>(pf.GetLow64());
            }
            else if (us[i].m != zero && !us[i].n)
            {
                // the reserve grows: its net flow buys units, start at the satoshi above
                prices[i] = static_cast<int64_t>(pc.GetLow64());
                other[i] = static_cast<int64_t>(pf.GetLow64());
            }
            else
            {
                prices[i] = static_cast<int64_t>(pf.GetLow64());
                other[i] = static_cast<int64_t>(pc.GetLow64());
            }
        }

        // ---- rounding: the integer end state as the caller pays it, and each coupled reserve's choice between its two satoshis ----
        // a reserve is coupled when its price reaches more than its own one-way flow: a via source or target, or bought and sold
        std::vector<size_t> coupled;
        for (size_t i = 0; i < n; i++)
        {
            if (other[i] && (isSource[i] || isTarget[i] || (a[i] && b[i])))
            {
                coupled.push_back(i);
            }
        }
        if (coupled.size())
        {
            // reserves and supply after the integer payouts at the current prices; false when a reserve or the supply is emptied
            // or an end reserve, the end supply, or a reserve's units sold or bought leave the CAmount range
            auto endState = [&](std::vector<int64_t> &Rn, int64_t &Sn) -> bool
            {
                std::vector<U256> via(n);
                for (size_t s = 0; s < sources.size(); s++)
                {
                    size_t j = sources[s];
                    for (size_t k = 0; k < n; k++)
                    {
                        if ((*pCross)[j][k])
                        {
                            via[k] += (U256(static_cast<uint64_t>((*pCross)[j][k])) * bigSatoshi) / U256(static_cast<uint64_t>(prices[j]));
                        }
                    }
                }
                Rn = R;
                U256 plus = bigS, minus;
                for (size_t i = 0; i < n; i++)
                {
                    if (!flow[i])
                    {
                        continue;
                    }
                    U256 sold = U256(static_cast<uint64_t>(b[i])) + via[i];
                    U256 bought = (U256(static_cast<uint64_t>(a[i])) * bigSatoshi) / U256(static_cast<uint64_t>(prices[i]));
                    U256 out = (sold * U256(static_cast<uint64_t>(prices[i]))) / bigSatoshi;
                    U256 top = U256(static_cast<uint64_t>(R[i])) + U256(static_cast<uint64_t>(a[i]));
                    if (out >= top || top - out > maxPrice || sold > maxPrice || bought > maxPrice)
                    {
                        return false;
                    }
                    Rn[i] = static_cast<int64_t>((top - out).GetLow64());
                    plus += bought;
                    minus += sold;
                }
                if (minus >= plus || plus - minus > maxPrice)
                {
                    return false;
                }
                Sn = static_cast<int64_t>((plus - minus).GetLow64());
                return true;
            };
            // the curve measure of an end state, reusing each term while its amount is unchanged
            auto measureOf = [&](const std::vector<int64_t> &Rn, int64_t Sn, const CurveTerms &terms, CurveTerms &newTerms) -> SQ
            {
                SQ total;
                newTerms.have.assign(n, false);
                newTerms.at.assign(n, 0);
                newTerms.term.assign(n, SQ());
                for (size_t i = 0; i < n; i++)
                {
                    if (Rn[i] == R[i])
                    {
                        continue;
                    }
                    SQ t = (terms.have.size() && terms.have[i] && terms.at[i] == Rn[i]) ? terms.term[i] : CurveTerm(Rn[i], R[i], W[i], stats);
                    newTerms.have[i] = true;
                    newTerms.at[i] = Rn[i];
                    newTerms.term[i] = t;
                    total = SAdd(total, t);
                }
                SQ supplyTerm;
                if (terms.haveSupply && terms.atSupply == Sn)
                {
                    supplyTerm = terms.supplyTerm;
                }
                else if (Sn != S)
                {
                    supplyTerm = CurveTerm(Sn, S, SATOSHI, stats);
                }
                newTerms.haveSupply = true;
                newTerms.atSupply = Sn;
                newTerms.supplyTerm = supplyTerm;
                return SSub(total, supplyTerm);
            };
            std::vector<int64_t> curR, trialR;
            int64_t curS = 0, trialS = 0;
            CurveTerms curTerms, trialTerms;
            SQ curM, trialM;
            bool haveCur = endState(curR, curS);
            if (haveCur)
            {
                curM = measureOf(curR, curS, curTerms, trialTerms);
                curTerms = trialTerms;
            }
            for (int pass = 0; pass < MAX_ROUND_PASSES; pass++)
            {
                bool changed = false;
                for (size_t c = 0; c < coupled.size(); c++)
                {
                    size_t i = coupled[c];
                    int64_t held = prices[i];
                    prices[i] = other[i];
                    other[i] = held;
                    bool better = false;
                    if (endState(trialR, trialS) && !(haveCur && trialR == curR && trialS == curS))
                    {
                        trialM = measureOf(trialR, trialS, curTerms, trialTerms);
                        better = !haveCur || SLess(curM, trialM);
                    }
                    if (better)
                    {
                        curR = trialR;
                        curS = trialS;
                        curM = trialM;
                        curTerms = trialTerms;
                        haveCur = true;
                        changed = true;
                        stats.roundingFlips++;
                    }
                    else
                    {
                        held = prices[i];
                        prices[i] = other[i];
                        other[i] = held;
                    }
                }
                if (!changed)
                {
                    break;
                }
            }
        }
        return ERR_NONE;
    }

    // one price per reserve, conversionPrice convention (reserve per unit times SATOSHI), used in both directions. inputs follow
    // ConvertAmounts: a[i] is reserve i converting to units, including the first legs of via conversions, which pCross then
    // routes on; b[i] is units converting to reserve i. the vector is empty on any error
    inline int Clear(const std::vector<int64_t> &R,
                     const std::vector<int64_t> &W,
                     int64_t S,
                     const std::vector<int64_t> &a,
                     const std::vector<int64_t> &b,
                     const std::vector<std::vector<int64_t>> *pCross,
                     std::vector<int64_t> &prices,
                     ClearStats &stats)
    {
        stats = ClearStats();
        if (!ValidInputs(R, W, S, a, b, pCross))
        {
            prices.clear();
            return ERR_INPUT;
        }
        int error;
        try
        {
            error = ClearInner(R, W, S, a, b, pCross, prices, stats);
        }
        catch (const ClearFault &fault)
        {
            error = fault.error;
        }
        if (error != ERR_NONE)
        {
            prices.clear();
        }
        return error;
    }
}

#endif // VERUS_PBAAS_CLEARING_FP_H
