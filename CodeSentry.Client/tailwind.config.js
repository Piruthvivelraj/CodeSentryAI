/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./**/*.razor",
    "./wwwroot/**/*.html",
    "./wwwroot/**/*.css",
    "./wwwroot/**/*.js"
  ],
  theme: {
    extend: {
      colors: {
        "surface-container-highest": "#32353c",
        "outline": "#8c909f",
        "inverse-surface": "#e1e2ec",
        "on-secondary-fixed": "#23005c",
        "secondary-fixed": "#e9ddff",
        "on-primary-fixed": "#001a42",
        "on-background": "#e1e2ec",
        "error-container": "#93000a",
        "surface-bright": "#363941",
        "tertiary-fixed": "#6ffbbe",
        "accent": "#3b82f6",
        "primary": "#adc6ff",
        "outline-variant": "#424754",
        "on-secondary-container": "#c4abff",
        "primary-fixed": "#d8e2ff",
        "surface-container": "#1d2027",
        "primary-container": "#4d8eff",
        "background": "#10131a",
        "on-error": "#690005",
        "on-surface-variant": "#c2c6d6",
        "on-tertiary-container": "#00311f",
        "on-primary": "#002e6a",
        "inverse-primary": "#005ac2",
        "on-tertiary-fixed": "#002113",
        "primary-fixed-dim": "#adc6ff",
        "error": "#ffb4ab",
        "surface-container-high": "#272a31",
        "on-surface": "#e1e2ec",
        "tertiary-container": "#00a572",
        "inverse-on-surface": "#2e3038",
        "surface-dim": "#10131a",
        "on-primary-fixed-variant": "#004395",
        "tertiary-fixed-dim": "#4edea3",
        "surface-tint": "#adc6ff",
        "on-tertiary-fixed-variant": "#005236",
        "on-primary-container": "#00285d",
        "surface-variant": "#32353c",
        "secondary-container": "#571bc1",
        "secondary": "#d0bcff",
        "surface": "#10131a",
        "tertiary": "#4edea3",
        "surface-container-lowest": "#0b0e15",
        "on-tertiary": "#003824",
        "secondary-fixed-dim": "#d0bcff",
        "surface-container-low": "#191b23",
        "on-secondary-fixed-variant": "#5516be",
        "on-error-container": "#ffdad6",
        "on-secondary": "#3c0091"
      },
      borderRadius: {
        "DEFAULT": "0.25rem",
        "lg": "0.5rem",
        "xl": "0.75rem",
        "full": "9999px"
      },
      spacing: {
        "gutter": "16px",
        "unit": "4px",
        "container-max": "1440px",
        "margin": "24px"
      },
      fontFamily: {
        "data-md": ["JetBrains Mono"],
        "label-sm": ["Inter"],
        "data-sm": ["JetBrains Mono"],
        "data-lg": ["JetBrains Mono"],
        "body-md": ["Inter"],
        "section-header": ["Inter"],
        "label-md": ["Inter"]
      },
      fontSize: {
        "data-md": ["18px", {"lineHeight": "24px", "fontWeight": "500"}],
        "label-sm": ["11px", {"lineHeight": "14px", "fontWeight": "500"}],
        "data-sm": ["13px", {"lineHeight": "18px", "fontWeight": "400"}],
        "data-lg": ["32px", {"lineHeight": "40px", "letterSpacing": "-0.02em", "fontWeight": "700"}],
        "body-md": ["14px", {"lineHeight": "22px", "fontWeight": "400"}],
        "section-header": ["12px", {"lineHeight": "16px", "letterSpacing": "0.15em", "fontWeight": "800"}],
        "label-md": ["14px", {"lineHeight": "20px", "fontWeight": "600"}]
      }
    }
  },
  plugins: []
}
