import { describe, expect, it } from 'vitest';
import { analyze } from './analyze';
import { DEFAULT_OPTIONS } from './config';
import { decodePunycode, editDistance, registrableDomain, skeleton } from './domain';
import { computeFlips } from './flip';
import { runMatrix } from './mutations';
import { formatReport } from './report';
import { SAMPLES } from './samples';
import type { Analysis, RuleId, Verdict } from './types';

function ok(input: string, options = DEFAULT_OPTIONS): Analysis {
  const r = analyze(input, options);
  if (!r.ok) throw new Error(`Expected ${input} to parse: ${r.error}`);
  return r;
}
const rules = (a: Analysis): RuleId[] => a.findings.map((f) => f.ruleId);

describe('helpers', () => {
  it('decodes punycode', () => {
    expect(decodePunycode('mnchen-3ya')).toBe('münchen');
    const host = new URL('https://c\u0430mpus.example').hostname;
    expect(host.startsWith('xn--')).toBe(true);
  });
  it('computes registrable domains', () => {
    expect(registrableDomain('a.b.campus.example')).toBe('campus.example');
    expect(registrableDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
  });
  it('builds confusable skeletons', () => {
    expect(skeleton('carnpus.example')).toBe(skeleton('campus.example'));
    expect(skeleton('paypa1.com')).toBe(skeleton('paypal.com'));
    expect(skeleton('c\u0430mpus.example')).toBe(skeleton('campus.example'));
    expect(editDistance('gogle.com', 'google.com')).toBe(1);
  });
});

describe('samples', () => {
  const expected: Record<string, Verdict> = {
    'https://campus.example/library/hours': 'Safe',
    'https://campus.example@login-verify.example/sso': 'Suspicious',
    'https://bit.ly/3xCampus': 'Review',
    'https://carnpus.example/reset-password': 'Suspicious',
    'http://3232235777/admin': 'Suspicious',
    'https://campus.example.account-verify.example/login': 'Suspicious',
    'http://campus.example/events': 'Review',
  };
  for (const s of SAMPLES) {
    it(`${s.label}: ${s.url}`, () => {
      expect(ok(s.url).verdict).toBe(expected[s.url]);
    });
  }
});

describe('PR-01 userinfo', () => {
  it('flags a domain-looking username as critical and explains the real host', () => {
    const a = ok('https://campus.example@other.example/login');
    expect(a.verdict).toBe('Suspicious');
    expect(a.findings[0]).toMatchObject({ ruleId: 'PR-01', severity: 'critical' });
    expect(a.parts.hostname).toBe('other.example');
    expect(a.readsLike).toMatchObject({ appears: 'campus.example', actual: 'other.example' });
    const deceptive = a.readsLike!.segments.find((s) => s.tone === 'deceptive');
    expect(deceptive?.text).toBe('campus.example@');
  });
  it('flags credentials and hides the password', () => {
    const a = ok('https://admin:hunter2@campus.example/');
    expect(rules(a)).toContain('PR-01');
    expect(a.verdict).toBe('Suspicious');
    expect(JSON.stringify({ p: a.parts, f: a.findings, s: a.summary })).not.toContain('hunter2');
    expect(a.readsLike).toBeNull();
  });
  it('handles multiple @ signs using the last one', () => {
    const a = ok('https://campus.example@x@evil.example/');
    expect(a.parts.hostname).toBe('evil.example');
    expect(a.verdict).toBe('Suspicious');
  });
});

describe('PR-02 non-web schemes', () => {
  it.each(['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'file:///C:/Windows/system32', 'vbscript:msgbox(1)'])(
    '%s is Suspicious',
    (u) => {
      const a = ok(u);
      expect(a.verdict).toBe('Suspicious');
      expect(a.findings[0].ruleId).toBe('PR-02');
    },
  );
  it.each(['mailto:help@campus.example', 'tel:+15551234567', 'ftp://files.campus.example/a'])('%s is Review', (u) => {
    const a = ok(u);
    expect(a.verdict).toBe('Review');
    expect(rules(a)).toContain('PR-02');
  });
});

describe('PR-03 IP hosts', () => {
  it('decodes decimal IPs and flags them as high', () => {
    const a = ok('http://3232235777/');
    expect(a.parts.hostname).toBe('192.168.1.1');
    expect(a.findings.find((f) => f.ruleId === 'PR-03')?.severity).toBe('high');
    expect(a.readsLike).toMatchObject({ appears: '3232235777', actual: '192.168.1.1' });
  });
  it('flags hex and octal forms', () => {
    expect(ok('http://0xC0A80101/').verdict).toBe('Suspicious');
    expect(ok('http://0300.0250.1.1/').verdict).toBe('Suspicious');
  });
  it('flags dotted IPs as Review', () => {
    const a = ok('https://203.0.113.10/login');
    expect(a.verdict).toBe('Review');
    expect(a.findings[0]).toMatchObject({ ruleId: 'PR-03', severity: 'medium' });
  });
  it('flags IPv6 literals', () => {
    expect(rules(ok('https://[2001:db8::1]/'))).toContain('PR-03');
  });
});

describe('PR-04 shorteners', () => {
  it.each(['https://bit.ly/abc', 'https://tinyurl.com/x', 'https://t.co/abc'])('%s → Review', (u) => {
    const a = ok(u);
    expect(a.verdict).toBe('Review');
    expect(rules(a)).toEqual(['PR-04']);
  });
  it('does not flag lookalike-of-shortener hosts as shorteners', () => {
    expect(rules(ok('https://notbit.ly.example/'))).not.toContain('PR-04');
  });
});

describe('PR-05 lookalikes', () => {
  it('flags carnpus.example as imitating campus.example', () => {
    const a = ok('https://carnpus.example/');
    expect(a.findings[0]).toMatchObject({ ruleId: 'PR-05', severity: 'high' });
    expect(a.findings[0].explanation).toContain('“rn” in place of “m”');
    expect(a.matchedReference).toBe('campus.example');
  });
  it('flags subdomains of a lookalike', () => {
    expect(rules(ok('https://login.carnpus.example/'))).toContain('PR-05');
  });
  it('flags Cyrillic homographs', () => {
    const a = ok('https://c\u0430mpus.example/');
    expect(a.verdict).toBe('Suspicious');
    expect(rules(a)).toEqual(expect.arrayContaining(['PR-05', 'PR-07']));
  });
  it('treats single-edit typos as medium (Review)', () => {
    const a = ok('https://gogle.com/');
    expect(a.verdict).toBe('Review');
    expect(a.findings[0]).toMatchObject({ ruleId: 'PR-05', severity: 'medium' });
  });
  it('does not flag unrelated unusual spellings', () => {
    for (const u of ['https://kampala.example/', 'https://xkcd.com/', 'https://campfire.example/']) {
      expect(rules(ok(u))).not.toContain('PR-05');
    }
  });
  it('only compares against configured references', () => {
    const a = ok('https://carnpus.example/', { referenceDomains: ['bank.example'] });
    expect(rules(a)).not.toContain('PR-05');
  });
});

describe('PR-06 / PR-09 reference misuse', () => {
  it('flags reference as subdomain of another domain', () => {
    const a = ok('https://campus.example.evil.example/');
    expect(a.findings[0]).toMatchObject({ ruleId: 'PR-06', severity: 'high' });
    expect(a.readsLike?.actual).toBe('evil.example');
  });
  it('flags reference name as a hyphenated token (medium)', () => {
    const a = ok('https://paypal-secure.example/');
    expect(a.verdict).toBe('Review');
    expect(rules(a)).toEqual(['PR-06']);
  });
  it('flags reference domain in the path', () => {
    const a = ok('https://files.example/campus.example/login');
    expect(a.verdict).toBe('Review');
    expect(rules(a)).toEqual(['PR-09']);
  });
});

describe('benign unusual URLs', () => {
  it.each([
    'https://CAMPUS.EXAMPLE/Library',
    'https://campus.example:8443/library',
    'https://portal.campus.example/a/b/c',
    'https://campus.example/r%C3%A9sum%C3%A9%20files',
    'https://campus.example/?q=a%40b&next=%2Fhome#top',
    'https://campus.example./login',
    'https://en.wikipedia.org/wiki/URL',
    'https://www.bbc.co.uk/news',
    'https://xn--mnchen-3ya.example/', // ok: but punycode is flagged medium
  ])('%s', (u) => {
    const a = ok(u);
    if (u.includes('xn--')) {
      expect(a.verdict).toBe('Review');
      expect(rules(a)).toEqual(['PR-07']);
    } else {
      expect(a.verdict).toBe('Safe');
      expect(a.findings).toEqual([]);
    }
  });
  it('normalizes uppercase hosts', () => {
    expect(ok('https://CAMPUS.EXAMPLE/').parts.hostname).toBe('campus.example');
  });
});

describe('PR-10 ambiguity and malformed input', () => {
  it('assumes https for scheme-less input conservatively', () => {
    const a = ok('campus.example/login');
    expect(a.assumedScheme).toBe(true);
    expect(a.parts.scheme).toBe('https');
    expect(a.verdict).toBe('Review');
  });
  it('treats host:port without scheme as a host', () => {
    const a = ok('campus.example:8443/x');
    expect(a.parts.hostname).toBe('campus.example');
    expect(a.parts.port).toBe('8443');
  });
  it('flags backslashes and follows browser parsing', () => {
    const a = ok('https://campus.example\\@evil.example/');
    expect(a.parts.hostname).toBe('campus.example');
    expect(rules(a)).toContain('PR-10');
  });
  it('flags invisible characters', () => {
    const a = ok('https://campus.example/lo\u200Bgin');
    expect(rules(a)).toContain('PR-10');
    expect(a.verdict).toBe('Review');
  });
  it.each(['', '   ', 'not a url', 'https://', 'http://exa mple.com', 'https://campus.example:99999/', 'hello', 'https://[::1', 'https://a..b/'])(
    'rejects %j gracefully',
    (u) => {
      const r = analyze(u);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error.length).toBeGreaterThan(0);
        expect(r.hint.length).toBeGreaterThan(0);
      }
    },
  );
  it('rejects percent-escapes in hosts that lenient browser parsers accept', () => {
    expect(analyze('https://exa%20mple.com/').ok).toBe(false);
  });
  it('rejects absurdly long input', () => {
    expect(analyze('https://a.example/' + 'a'.repeat(5000)).ok).toBe(false);
  });
  it('never throws on random junk', () => {
    const junk = ['%%%', '::::', 'http://@', '@@@', 'javascript:', '//', 'xn--', 'http://xn--a/', '\u0000', 'https://a..b/'];
    for (const j of junk) expect(() => analyze(j)).not.toThrow();
  });
});

describe('verdict policy', () => {
  it('Safe requires https and a named host, not just zero findings', () => {
    const a = ok('https://campus.example/');
    expect(a.checks.every((c) => c.passed)).toBe(true);
    expect(ok('http://campus.example/').verdict).toBe('Review');
  });
  it('two medium signals escalate to Suspicious', () => {
    const a = ok('https://bit.ly/campus.example');
    expect(rules(a)).toEqual(expect.arrayContaining(['PR-04', 'PR-09']));
    expect(a.verdict).toBe('Suspicious');
  });
  it('report text includes every finding', () => {
    const a = ok('https://campus.example@login-verify.example/');
    const text = formatReport(a);
    expect(text).toContain('SUSPICIOUS');
    expect(text).toContain('[PR-01]');
  });
});

describe('mutation matrix', () => {
  it('meets every expectation for a reference baseline', () => {
    const m = runMatrix(ok('https://campus.example/login'), DEFAULT_OPTIONS);
    const mismatches = m.results.filter((r) => r.status === 'mismatch').map((r) => `${r.id}: ${r.actual} ${r.url}`);
    expect(mismatches).toEqual([]);
    expect(m.caught).toBeGreaterThanOrEqual(8);
    expect(m.clean).toBe(6);
  });
  it('includes the required variants', () => {
    const urls = runMatrix(ok('https://campus.example/'), DEFAULT_OPTIONS).results.map((r) => r.url);
    expect(urls).toEqual(
      expect.arrayContaining([
        'https://carnpus.example/login',
        'https://campus.example@login-verify.example/login',
        'http://3232235777/login',
        'https://CAMPUS.EXAMPLE/login',
        'https://campus.example:8443/login',
        'https://portal.campus.example/login',
      ]),
    );
  });
  it('derives the baseline from a deceptive input', () => {
    const m = runMatrix(ok('https://carnpus.example/x'), DEFAULT_OPTIONS);
    expect(m.baseline.domain).toBe('campus.example');
  });
  it('flags reference-dependent attacks as mismatches for non-reference baselines', () => {
    const m = runMatrix(ok('https://github.com/'), DEFAULT_OPTIONS);
    const look = m.results.find((r) => r.id === 'lookalike')!;
    expect(look.status).toBe('mismatch');
    expect(look.note).toMatch(/reference/);
  });
});

describe('flip suggestions', () => {
  const flip = (u: string) => computeFlips(ok(u), DEFAULT_OPTIONS);
  it('userinfo: removing the prefix flips Suspicious → Safe', () => {
    const f = flip('https://campus.example@other.example/login');
    expect(f.primary).toMatchObject({ direction: 'improve', from: 'Suspicious', to: 'Safe', url: 'https://other.example/login' });
  });
  it('http: adding s flips Review → Safe', () => {
    expect(flip('http://campus.example/').primary).toMatchObject({ to: 'Safe', url: 'https://campus.example/' });
  });
  it('lookalike: genuine reference flips to Safe', () => {
    expect(flip('https://carnpus.example/x').primary).toMatchObject({ to: 'Safe', url: 'https://campus.example/x' });
  });
  it('encoded IP: plain form drops to Review and explains the blocker', () => {
    const f = flip('http://3232235777/');
    expect(f.primary?.to).toBe('Review');
    expect(f.blockers.map((b) => b.ruleId)).toContain('PR-03');
  });
  it('shortener: no edit, only a blocker', () => {
    const f = flip('https://bit.ly/abc');
    expect(f.primary).toBeNull();
    expect(f.blockers[0].ruleId).toBe('PR-04');
  });
  it('safe: shows the smallest edit that would raise the verdict', () => {
    const f = flip('https://campus.example/login');
    expect(f.primary).toMatchObject({ direction: 'worsen', to: 'Review', url: 'http://campus.example/login' });
    expect(f.secondary?.to).toBe('Suspicious');
  });
  it('every suggested URL re-analyzes to the stated verdict', () => {
    for (const s of SAMPLES) {
      const f = flip(s.url);
      for (const c of [f.primary, f.secondary]) {
        if (c) expect(ok(c.url).verdict).toBe(c.to);
      }
    }
  });
});
