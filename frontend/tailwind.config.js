/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#050810',
        bg2: '#0a0f1e',
        bg3: '#0f1628',
        panel: '#0d1425',
        accent: '#3b82f6',
        accent2: '#06b6d4',
        accent3: '#8b5cf6',
      },
      fontFamily: {
        sans: ['Sora', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
