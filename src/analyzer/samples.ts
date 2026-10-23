export interface Sample {
  label: string;
  kind: 'ordinary' | 'deceptive' | 'ambiguous';
  url: string;
}

/** Illustrative inputs. *.example domains are reserved and are not real sites. */
export const SAMPLES: Sample[] = [
  { label: 'Campus portal', kind: 'ordinary', url: 'https://campus.example/library/hours' },
  { label: '@ disguise', kind: 'deceptive', url: 'https://campus.example@login-verify.example/sso' },
  { label: 'Short link', kind: 'ambiguous', url: 'https://bit.ly/3xCampus' },
  { label: 'Lookalike', kind: 'deceptive', url: 'https://carnpus.example/reset-password' },
  { label: 'Encoded IP', kind: 'deceptive', url: 'http://3232235777/admin' },
  { label: 'Subdomain trick', kind: 'deceptive', url: 'https://campus.example.account-verify.example/login' },
  { label: 'Plain HTTP', kind: 'ambiguous', url: 'http://campus.example/events' },
];
