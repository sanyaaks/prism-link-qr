/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        pulse: { DEFAULT: '#00D1B2', soft: '#5BE6D0', deep: '#00A88F' },
        midnight: { DEFAULT: '#001F3F', 950: '#00142A', 900: '#001A35', 800: '#062A4F', 700: '#0D3760' },
        carbon: { DEFAULT: '#2E2E2E', 900: '#1C1C1C' },
        signal: '#FFFFFF',
        verdict: { safe: '#3DD68C', review: '#F5A524', suspicious: '#FF5D5D' },
      },
      fontFamily: {
        serif: ['"Playfair Display"', 'Canela', 'Georgia', 'serif'],
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      keyframes: {
        rise: { '0%': { opacity: '0', transform: 'translateY(12px)' }, '100%': { opacity: '1', transform: 'none' } },
        fade: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        beam: { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        rise: 'rise 0.6s cubic-bezier(0.2, 0.7, 0.2, 1) both',
        fade: 'fade 0.4s ease-out both',
        beam: 'beam 1.1s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
