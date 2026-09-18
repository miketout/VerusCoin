#!/usr/bin/env python3
# Copyright (c) 2026 The Verus developers
# Distributed under the MIT software license.
#
# fmtscan.py — static gate for tinyformat format-string/argument mismatches.
#
# This codebase defines TINYFORMAT_ERROR as `throw std::runtime_error` (tinyformat.h),
# and LogPrint/LogPrintf/error/strprintf pass their arguments to tfm::format with no
# surrounding catch. tinyformat throws in BOTH directions: more specifiers than
# arguments ("Too many conversion specifiers") and more arguments than specifiers
# ("Not enough conversion specifiers"). A mismatched call therefore throws when
# executed; on paths with no handler (e.g. detached threads), that terminates the
# daemon. This scanner counts specifiers vs. arguments for every call with a literal
# format string and reports mismatches.
#
# Severity of what it reports:
#   THROWS  - the call instantiates tfm::format and will throw when executed.
#             (LogPrint/LogPrintf/error with >= 1 variadic argument; strprintf always,
#             since it has no passthrough overload.)
#   LITERAL - zero-argument LogPrint/LogPrintf/error calls take the passthrough
#             overload: no throw, but the format string prints verbatim (cosmetic).
#
# Known limitations (by design, to stay false-positive free):
#   - Only literal format strings are checked; formats built at runtime are skipped.
#   - %s given a non-string argument is fine for tinyformat (type-driven), so no
#     type checking is attempted — only counts.
#   - '*' width/precision consume one extra argument each and are counted as such.
#
# Usage: python3 fmtscan.py <source-root>   (e.g. python3 contrib/devtools/fmtscan.py src)
# Exit status: number of THROWS-class findings (0 when clean).

import re, sys, os

CALL_RE = re.compile(r'\b(LogPrintf|LogPrint|strprintf|error)\s*\(')
SPEC_RE = re.compile(r'%(?:[-+ #0]*)(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|L|z|j|t)?([diouxXeEfFgGaAcspn%])')
SKIP_DIRS = {'leveldb', 'secp256k1', 'univalue', 'snark', 'test', 'test-komodo',
             'gtest', 'crypto', 'cryptoconditions', 'rust', 'obj'}

def find_calls(text):
    for m in CALL_RE.finditer(text):
        name = m.group(1)
        # avoid matching declarations/definitions like `bool error(const char* format)`
        before = text[max(0, m.start() - 24):m.start()]
        if re.search(r'(::|\bbool\s+|\bint\s+|\bstatic\s+\w*\s*)$', before):
            continue
        i = m.end()
        depth, j = 1, i
        in_str = in_chr = esc = in_lc = in_bc = False
        while j < len(text) and depth > 0 and j - i < 4000:
            c = text[j]
            if in_lc:
                if c == '\n': in_lc = False
            elif in_bc:
                if c == '/' and text[j-1] == '*': in_bc = False
            elif in_str:
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == '"': in_str = False
            elif in_chr:
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == "'": in_chr = False
            else:
                if c == '"': in_str = True
                elif c == "'": in_chr = True
                elif c == '/' and j + 1 < len(text) and text[j+1] == '/': in_lc = True
                elif c == '/' and j + 1 < len(text) and text[j+1] == '*': in_bc = True
                elif c == '(': depth += 1
                elif c == ')': depth -= 1
            j += 1
        if depth == 0:
            yield name, m.start(), text[i:j-1]

def split_args(body):
    args, depth, cur = [], 0, ''
    in_str = in_chr = esc = False
    for c in body:
        if in_str:
            cur += c
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == '"': in_str = False
        elif in_chr:
            cur += c
            if esc: esc = False
            elif c == '\\': esc = True
            elif c == "'": in_chr = False
        else:
            if c == '"': in_str = True; cur += c
            elif c == "'": in_chr = True; cur += c
            elif c in '([{': depth += 1; cur += c
            elif c in ')]}': depth -= 1; cur += c
            elif c == ',' and depth == 0:
                args.append(cur.strip()); cur = ''
            else: cur += c
    if cur.strip(): args.append(cur.strip())
    return args

def literal_text(arg):
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', arg)
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '', arg).strip()
    if not parts or stripped:
        return None
    return ''.join(parts)

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'src'
    throws, literal = [], []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if not (f.endswith('.cpp') or f.endswith('.h')):
                continue
            p = os.path.join(dirpath, f)
            try:
                text = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for name, pos, body in find_calls(text):
                args = split_args(body)
                if not args:
                    continue
                fi = 1 if name == 'LogPrint' else 0   # LogPrint(category, fmt, ...)
                if len(args) <= fi:
                    continue
                fmt = literal_text(args[fi])
                if fmt is None:
                    continue
                specs = [s for s in SPEC_RE.findall(fmt) if s != '%']
                stars = fmt.count('%*') + fmt.count('.*')
                need = len(specs) + stars
                have = len(args) - fi - 1
                if need == have:
                    continue
                line = text.count('\n', 0, pos) + 1
                entry = (p, line, name, need, have, fmt[:60].replace('\n', ' '))
                # zero-arg LogPrint/LogPrintf/error take a passthrough overload (no
                # tfm::format call); strprintf always formats and always throws
                if have == 0 and name != 'strprintf':
                    literal.append(entry)
                else:
                    throws.append(entry)

    for p, line, name, need, have, fmt in sorted(throws):
        print(f"THROWS  {p}:{line}: {name} specifiers={need} args={have} :: {fmt}")
    for p, line, name, need, have, fmt in sorted(literal):
        print(f"LITERAL {p}:{line}: {name} specifiers={need} args={have} :: {fmt}")
    print(f"\n{len(throws)} throwing, {len(literal)} literal-only")
    return len(throws)

if __name__ == '__main__':
    sys.exit(main())
