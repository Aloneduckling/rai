/** @type {import('tailwindcss').Config} */
const defaultTheme = require('tailwindcss/defaultTheme');
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      backgroundImage: {
        "background-landscape": "url(./src/assets/background_landscape.png)",
        "background-potrait": "./src/assets/background_potrait.png"
      },
      fontFamily: {
        'sans': ['Kanit', ...defaultTheme.fontFamily.sans]
      },
      colors: {
        'primary': '#FFD00B',
        'primary-content': '#18171C',
        'base': '#fff',
        'base-content': '#30313D',
        'base-200': '#F8F9FD',
        'base-300': '#DFE5EB',
        'base-400': '#D9D9D9'
      }
    },
  },
  plugins: [],
}

