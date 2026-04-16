/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/bgpeek/templates/**/*.html"],
  darkMode: "class",
  safelist: [
    // Community label colors — generated in Python, not in templates.
    "text-amber-400",
    "text-emerald-400",
    "text-rose-400",
    "text-sky-400",
    "text-violet-400",
    "text-slate-400",
    "text-red-400",
    "text-orange-400",
    "text-cyan-400",
    "text-pink-400",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
