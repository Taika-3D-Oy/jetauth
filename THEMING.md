# Theming & White-Labeling Guide

JetAuth features a fully customisable dynamic theming and white-labeling engine. You can change everything from the brand name (e.g. from "JetAuth" to your company's brand) to colors, logos, web fonts, card styles, and footers — either globally across the entire deployment or individually per OAuth client application.

---

## 📑 Table of Contents

1. [Theming Architecture & Resolution Hierarchy](#theming-architecture--resolution-hierarchy)
2. [Built-in Theme Presets](#built-in-theme-presets)
3. [White-Labeling Configuration](#white-labeling-configuration)
4. [CSS Variables & Styling Properties](#css-variables--styling-properties)
5. [Configuring via Admin UI](#configuring-via-admin-ui)
6. [Configuring via Management REST API](#configuring-via-management-rest-api)
7. [Ready-to-Use Theme Recipes](#ready-to-use-theme-recipes)
8. [Security & Sanitization](#security--sanitization)

---

## Theming Architecture & Resolution Hierarchy

Every authentication surface in JetAuth (Login, Passkey/MFA verification, Registration, OAuth Consent, Device Authorization, and Account Management) dynamically resolves its theme using a three-tier hierarchy:

```
┌───────────────────────────────────────────────────────────┐
│ 1. Built-in Preset (e.g. jetauth-dark, glassmorphic, etc.)│
└───────────────────────────┬───────────────────────────────┘
                            │ (overridden by)
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 2. System Global Default Theme (Admin Settings)         │
└───────────────────────────┬─────────────────────────────┘
                            │ (overridden by)
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Client-Specific Theme Override (Per OAuth Client)    │
└─────────────────────────────────────────────────────────┘
```

If a client does not specify a custom color or logo, it inherits the system global default theme. If no system global theme is configured, the built-in preset default (`jetauth-dark`) is used.

---

## Built-in Theme Presets

You can select any of the 6 modern presets by setting `theme_preset` to its identifier:

| Preset Name | Identifier | Style Description | Best For |
| :--- | :--- | :--- | :--- |
| **JetAuth Dark** | `jetauth-dark` | Emerald green (`#10b981`) & deep slate background (`#0b0f19`) with subtle elevation. | Production dark mode, developer tools, fintech |
| **JetAuth Light** | `jetauth-light` | Crisp clean white background, indigo accents (`#2563eb`), refined light gray borders. | Enterprise SaaS, clean productivity apps |
| **Glassmorphic** | `glassmorphic` | Translucent frosted glass (`backdrop-filter: blur(16px)`), violet/indigo glow, blurred shadows. | Modern AI apps, Web3, trendy consumer portals |
| **Cyberpunk** | `cyberpunk` | High-contrast neon cyan (`#00f0ff`) and hot pink (`#ff003c`), futuristic dark grid. | Gaming, crypto, developer tools |
| **Minimal Noir** | `minimal-noir` | Jet black (`#09090b`), pure white buttons (`#ffffff`), monochrome typography, hairline borders. | Luxury brands, design studios, minimalist products |
| **Neo-Brutalist** | `neo-brutalist` | Bold 3px solid black borders, hard offset box-shadows (`6px 6px 0px #000`), yellow accents (`#facc15`), 0px radius. | Creative agencies, trendy Gen-Z tools, high-impact brands |

---

## White-Labeling Configuration

Full white-labeling can be achieved purely via theme configuration without changing code:

- **Custom Application / Brand Name (`app_name`)**:
  Replaces all occurrences of `"JetAuth"` or `"Lattice-ID"` in page headers, login banners, and browser titles with your brand (e.g., `"Acme Cloud ID"`).
- **Custom Logo URL (`logo_url`)**:
  Renders your logo image at the top of login and authorization screens (supports SVG, PNG, WebP, JPEG).
- **Logo Height (`logo_height`)**:
  Adjusts the displayed logo height (e.g., `"48px"`, `"60px"`, `"3rem"`).
- **Custom Favicon (`favicon_url`)**:
  Custom browser tab icon URL.
- **Custom Footer Text (`footer_text`)**:
  Custom copyright or legal notice displayed in the footer (e.g., `"© 2026 Acme Corp. All rights reserved."`).
- **"Powered by" Text (`powered_by_text`)**:
  Customises the attribution text (e.g., `"Secured by JetAuth"` or `"Powered by Acme Auth"`).
- **Hide "Powered by" Link (`hide_powered_by`)**:
  Set to `true` to completely eliminate any vendor / powered-by footer notice.
- **Legal Links (`terms_url`, `privacy_url`, `help_url`)**:
  Automatically adds safe, outbound clickable links to your legal terms, privacy statement, or help desk in the footer.

---

## CSS Variables & Styling Properties

The theme engine generates standard CSS variables on the `:root` pseudo-class. You can customize them individually or override them with `custom_css`:

| CSS Variable | Theme Field | Description | Default (`jetauth-dark`) |
| :--- | :--- | :--- | :--- |
| `--primary` | `primary_color` | Main brand color for primary buttons & active states | `#10b981` |
| `--primary-hover` | `primary_hover_color` | Button hover & focus highlight color | `#059669` |
| `--bg` | `background_color` | Page background color | `#0b0f19` |
| `--card-bg` | `card_background` | Authentication card surface background | `#111827` |
| `--card-border` | `card_border` | Border definition for card containers | `1px solid #1f2937` |
| `--card-shadow` | `card_shadow` | Box-shadow applied to authentication card | `0 20px 25px -5px rgba(...)` |
| `--card-backdrop-blur` | `card_backdrop_blur` | Backdrop filter blur for glass effects | `0px` (`16px` for glass) |
| `--text` | `text_color` | Primary body text color | `#f9fafb` |
| `--text-muted` | `text_muted_color` | Secondary subtitles and label color | `#9ca3af` |
| `--input-bg` | `input_background` | Form input element background color | `#1f2937` |
| `--input-border` | `input_border_color` | Form input border style | `1px solid #374151` |
| `--input-text` | `input_text_color` | Text color inside form inputs | `#f9fafb` |
| `--button-text` | `button_text_color` | Text color inside primary buttons | `#ffffff` |
| `--radius` | `border_radius` | Corner rounding for cards, inputs, and buttons | `12px` |
| `--font-family` | `font_family` | Font family declaration for the whole page | `'Inter', sans-serif` |

### Custom Web Fonts

To load a custom web font (such as Google Fonts), supply the stylesheet URL in `font_url` and specify the font in `font_family`:

```json
{
  "font_url": "https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap",
  "font_family": "'Plus Jakarta Sans', system-ui, sans-serif"
}
```

---

## Configuring via Admin UI

### 1. Global System-Wide Theming
1. Log in to the Admin Panel at `/admin`.
2. Navigate to **System Settings** in the left sidebar (`/admin/settings`).
3. Scroll down to the **Global White-Labeling & Theme Defaults** section.
4. Choose a default **Theme Preset** or configure custom brand colors, logo, and web font.
5. Check **"Hide 'Powered by' branding link completely"** if you want full white-labeling.
6. Click **"Save White-Labeling Settings"**.

### 2. Per-Client Application Theming
1. In the Admin Panel, navigate to **Clients** (`/admin/clients`).
2. Select your client application to open its detail page (`/admin/clients/<client_id>`).
3. Under the **Theme & White-Labeling Override** card:
   - Choose a **Theme Preset** (or select *(Inherit System Default)*).
   - Enter your client application's **Custom Brand Name** and **Logo URL**.
   - Customize colors, background image, font URL, and custom CSS.
   - Configure custom footer text or toggle **"Hide 'Powered by' footer branding"**.
4. Click **"Save Client Theme"**.

---

## Configuring via Management REST API

You can programmatically manage themes via the standard Management API.

### Create a Client with Custom Theming
```http
POST /api/clients
Authorization: Bearer <ADMIN_OR_TENANT_ADMIN_TOKEN>
Content-Type: application/json

{
  "name": "Customer Portal",
  "client_type": "confidential",
  "redirect_uris": ["https://portal.example.com/callback"],
  "theme": {
    "app_name": "Acme Portal",
    "theme_preset": "glassmorphic",
    "logo_url": "https://portal.example.com/assets/logo.svg",
    "logo_height": "52px",
    "primary_color": "#6366f1",
    "primary_hover_color": "#4f46e5",
    "footer_text": "© 2026 Acme Technologies",
    "powered_by_text": "Secured by Acme ID",
    "hide_powered_by": false,
    "terms_url": "https://portal.example.com/terms",
    "privacy_url": "https://portal.example.com/privacy"
  }
}
```

### Update an Existing Client's Theme
```http
PUT /api/clients/client_abc123
Authorization: Bearer <ADMIN_OR_TENANT_ADMIN_TOKEN>
Content-Type: application/json

{
  "theme": {
    "app_name": "Cyber Hub",
    "theme_preset": "cyberpunk",
    "custom_css": ".card { transform: rotate(-0.5deg); }"
  }
}
```

---

## Ready-to-Use Theme Recipes

### 1. Modern Glassmorphism (Frosted Glass)
```json
{
  "app_name": "Aether Studio",
  "theme_preset": "glassmorphic",
  "logo_url": "https://aether.example.com/logo-white.svg",
  "primary_color": "#818cf8",
  "primary_hover_color": "#6366f1",
  "background_image_url": "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=1920&q=80",
  "card_backdrop_blur": "20px",
  "border_radius": "16px",
  "font_url": "https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700&display=swap",
  "font_family": "'Plus Jakarta Sans', sans-serif"
}
```

### 2. Luxury Noir (Monochrome)
```json
{
  "app_name": "Maison Noir",
  "theme_preset": "minimal-noir",
  "logo_url": "https://maison.example.com/brand.svg",
  "primary_color": "#ffffff",
  "primary_hover_color": "#e2e8f0",
  "background_color": "#050505",
  "card_background": "#0d0d0e",
  "card_border": "1px solid #1f1f23",
  "border_radius": "6px",
  "font_url": "https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&display=swap",
  "font_family": "'Space Grotesk', monospace",
  "hide_powered_by": true,
  "footer_text": "Maison Noir Authentication"
}
```

### 3. Neo-Brutalist (High Impact)
```json
{
  "app_name": "KRAFT ID",
  "theme_preset": "neo-brutalist",
  "primary_color": "#ffdf00",
  "primary_hover_color": "#facc15",
  "background_color": "#fef08a",
  "card_background": "#ffffff",
  "card_border": "3px solid #000000",
  "card_shadow": "8px 8px 0px #000000",
  "border_radius": "0px",
  "button_text_color": "#000000",
  "font_url": "https://fonts.googleapis.com/css2?family=Public+Sans:wght@600;800&display=swap",
  "font_family": "'Public Sans', sans-serif"
}
```

---

## Security & Sanitization

Lattice-ID strictly sanitizes theme inputs to ensure that custom theming cannot introduce cross-site scripting (XSS) or break rendering integrity:

- **Safe URL Enforcers**: All `logo_url`, `favicon_url`, `background_image_url`, `font_url`, `terms_url`, and `privacy_url` values must use `http://`, `https://`, or valid protocol-relative URLs (`//`). `javascript:`, `data:`, and `vbscript:` schemes are blocked.
- **CSS Sanitization**: Any `custom_css` entered is stripped of closing `</style>` tags, `<script>` tags, and expressions to prevent escaping into the HTML DOM.
- **HTML Escaping**: Application titles, footers, and copyright strings are HTML-escaped before injection into templates.
