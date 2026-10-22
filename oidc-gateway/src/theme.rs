use crate::store::{self, ClientTheme, RuntimeSettings};
use crate::util;

/// Strip a single pass of `<style`, `</style`, `<script`, `</script`, and `<!--...-->` tags.
fn strip_dangerous_css_tags_once(css: &str) -> String {
    let lower = css.to_ascii_lowercase();
    let mut out = String::with_capacity(css.len());
    let mut chars = css.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        let rem_lower = &lower[idx..];
        if rem_lower.starts_with("</style")
            || rem_lower.starts_with("<style")
            || rem_lower.starts_with("<script")
            || rem_lower.starts_with("</script")
        {
            for (_, c) in chars.by_ref() {
                if c == '>' {
                    break;
                }
            }
        } else if rem_lower.starts_with("<!--") {
            let mut dash_count = 0;
            for (_, c) in chars.by_ref() {
                if c == '-' {
                    dash_count += 1;
                } else if c == '>' && dash_count >= 2 {
                    break;
                } else {
                    dash_count = 0;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Sanitize custom CSS by iteratively stripping closing style/script tags, HTML comments,
/// and any remaining `<` characters so content can never break out of a `<style>` element.
pub fn sanitize_custom_css(css: &str) -> String {
    let mut current = css.to_string();
    for _ in 0..8 {
        let next = strip_dangerous_css_tags_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    // In HTML5 RAWTEXT state (<style>), '<' is the only character that can initiate
    // a closing </style> tag and has no valid meaning in CSS selectors or declarations.
    current.retain(|c| c != '<');
    current
}

/// Returns true if a CSS property value is safe to interpolate into `:root { --var: <val>; }`.
/// Rejects characters that could break out of the CSS declaration, block, or `<style>` tag,
/// as well as external resource loaders (`url(`, `@import`).
pub fn is_safe_css_value(val: &str) -> bool {
    if val.len() > 512 {
        return false;
    }
    if val
        .chars()
        .any(|c| matches!(c, '<' | '>' | '{' | '}' | ';' | '\\' | '\n' | '\r' | '\0'))
    {
        return false;
    }
    let lower = val.to_ascii_lowercase();
    if lower.contains("url(") || lower.contains("@import") || lower.contains("expression(") {
        return false;
    }
    true
}

/// Sanitize a single CSS custom property value, falling back to `fallback` if unsafe.
pub fn sanitize_css_value<'a>(val: Option<&'a str>, fallback: &'a str) -> &'a str {
    match val {
        Some(v) if !v.trim().is_empty() && is_safe_css_value(v) => v,
        _ => fallback,
    }
}

/// Validate all fields of a [`ClientTheme`] before persisting.
pub fn validate_theme(theme: &ClientTheme) -> Result<(), String> {
    if let Some(preset) = theme.theme_preset.as_deref()
        && !preset.is_empty()
        && !is_known_preset(preset)
    {
        return Err(format!(
            "unknown theme preset (valid: {})",
            KNOWN_THEME_PRESETS.join(", ")
        ));
    }
    let css_fields: &[(&str, Option<&str>)] = &[
        ("logo_height", theme.logo_height.as_deref()),
        ("primary_color", theme.primary_color.as_deref()),
        ("primary_hover_color", theme.primary_hover_color.as_deref()),
        ("background_color", theme.background_color.as_deref()),
        ("card_background", theme.card_background.as_deref()),
        ("card_border", theme.card_border.as_deref()),
        ("card_shadow", theme.card_shadow.as_deref()),
        ("card_backdrop_blur", theme.card_backdrop_blur.as_deref()),
        ("text_color", theme.text_color.as_deref()),
        ("text_muted_color", theme.text_muted_color.as_deref()),
        ("input_background", theme.input_background.as_deref()),
        ("input_border_color", theme.input_border_color.as_deref()),
        ("input_text_color", theme.input_text_color.as_deref()),
        ("button_text_color", theme.button_text_color.as_deref()),
        ("border_radius", theme.border_radius.as_deref()),
        ("font_family", theme.font_family.as_deref()),
    ];
    for (name, val) in css_fields {
        if let Some(v) = val
            && !is_safe_css_value(v)
        {
            return Err(format!("invalid or unsafe CSS value in theme.{name}"));
        }
    }
    let url_fields: &[(&str, Option<&str>)] = &[
        ("logo_url", theme.logo_url.as_deref()),
        ("favicon_url", theme.favicon_url.as_deref()),
        (
            "background_image_url",
            theme.background_image_url.as_deref(),
        ),
        ("font_url", theme.font_url.as_deref()),
        ("terms_url", theme.terms_url.as_deref()),
        ("privacy_url", theme.privacy_url.as_deref()),
        ("help_url", theme.help_url.as_deref()),
    ];
    for (name, val) in url_fields {
        if let Some(u) = val
            && !u.is_empty()
            && (!util::is_safe_url(u)
                || u.chars().any(|c| {
                    matches!(
                        c,
                        '"' | '\'' | '(' | ')' | ';' | '{' | '}' | '<' | '>' | '\\' | '\n' | '\r'
                    )
                }))
        {
            return Err(format!("invalid or unsafe URL in theme.{name}"));
        }
    }
    Ok(())
}

/// Fallback base theme if none configured.
pub fn fallback_theme() -> ClientTheme {
    ClientTheme {
        app_name: "JetAuth".to_string(),
        logo_url: None,
        logo_height: Some("48px".to_string()),
        favicon_url: None,
        theme_preset: Some("taika-dark".to_string()),
        primary_color: Some("#10b981".to_string()),
        primary_hover_color: Some("#059669".to_string()),
        background_color: Some("linear-gradient(135deg, #090d16 0%, #0d1b2a 50%, #061e24 100%)".to_string()),
        background_image_url: None,
        card_background: Some("rgba(15, 23, 42, 0.75)".to_string()),
        card_border: Some("1px solid rgba(255, 255, 255, 0.12)".to_string()),
        card_shadow: Some("0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 30px rgba(16, 185, 129, 0.12)".to_string()),
        card_backdrop_blur: Some("20px".to_string()),
        text_color: Some("#f8fafc".to_string()),
        text_muted_color: Some("#94a3b8".to_string()),
        input_background: Some("rgba(30, 41, 59, 0.6)".to_string()),
        input_border_color: Some("rgba(255, 255, 255, 0.16)".to_string()),
        input_text_color: Some("#f8fafc".to_string()),
        button_text_color: Some("#ffffff".to_string()),
        border_radius: Some("14px".to_string()),
        font_family: Some("'Plus Jakarta Sans', system-ui, -apple-system, sans-serif".to_string()),
        font_url: Some("https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap".to_string()),
        footer_text: None,
        powered_by_text: Some("Powered by JetAuth".to_string()),
        hide_powered_by: false,
        terms_url: None,
        privacy_url: None,
        help_url: None,
        custom_css: None,
    }
}

/// Theme preset names recognized by [`apply_preset`], including aliases.
/// Anything else resolves to the default theme.
pub const KNOWN_THEME_PRESETS: &[&str] = &[
    "taika-dark",
    "taika-light",
    "glassmorphism",
    "glassmorphic",
    "glassmorphic-frost",
    "cyberpunk",
    "midnight-neon",
    "minimal-noir",
    "dark-luxury",
    "neo-brutalist",
    "default",
];

/// Whether `name` is a recognized theme preset.
pub fn is_known_preset(name: &str) -> bool {
    KNOWN_THEME_PRESETS.contains(&name)
}

/// Apply a preset template to a theme, populating any fields that are not explicitly overridden.
pub fn apply_preset(preset_name: &str) -> ClientTheme {
    match preset_name {
        "taika-dark" => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("taika-dark".to_string()),
            primary_color: Some("#10b981".to_string()),
            primary_hover_color: Some("#059669".to_string()),
            background_color: Some("linear-gradient(135deg, #090d16 0%, #0d1b2a 50%, #061e24 100%)".to_string()),
            background_image_url: None,
            card_background: Some("rgba(15, 23, 42, 0.75)".to_string()),
            card_border: Some("1px solid rgba(255, 255, 255, 0.12)".to_string()),
            card_shadow: Some("0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 30px rgba(16, 185, 129, 0.12)".to_string()),
            card_backdrop_blur: Some("20px".to_string()),
            text_color: Some("#f8fafc".to_string()),
            text_muted_color: Some("#94a3b8".to_string()),
            input_background: Some("rgba(30, 41, 59, 0.6)".to_string()),
            input_border_color: Some("rgba(255, 255, 255, 0.16)".to_string()),
            input_text_color: Some("#f8fafc".to_string()),
            button_text_color: Some("#ffffff".to_string()),
            border_radius: Some("14px".to_string()),
            font_family: Some("'Plus Jakarta Sans', system-ui, -apple-system, sans-serif".to_string()),
            font_url: Some("https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap".to_string()),
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
        "taika-light" => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("taika-light".to_string()),
            primary_color: Some("#059669".to_string()),
            primary_hover_color: Some("#047857".to_string()),
            background_color: Some("linear-gradient(135deg, #f0fdf4 0%, #f8fafc 50%, #ecfdf5 100%)".to_string()),
            background_image_url: None,
            card_background: Some("#ffffff".to_string()),
            card_border: Some("1px solid #e2e8f0".to_string()),
            card_shadow: Some("0 20px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.03)".to_string()),
            card_backdrop_blur: Some("0px".to_string()),
            text_color: Some("#0f172a".to_string()),
            text_muted_color: Some("#64748b".to_string()),
            input_background: Some("#f8fafc".to_string()),
            input_border_color: Some("#cbd5e1".to_string()),
            input_text_color: Some("#0f172a".to_string()),
            button_text_color: Some("#ffffff".to_string()),
            border_radius: Some("12px".to_string()),
            font_family: Some("'Plus Jakarta Sans', system-ui, -apple-system, sans-serif".to_string()),
            font_url: Some("https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap".to_string()),
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
        "glassmorphism" | "glassmorphic" | "glassmorphic-frost" => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("glassmorphism".to_string()),
            primary_color: Some("#6366f1".to_string()),
            primary_hover_color: Some("#4f46e5".to_string()),
            background_color: Some("radial-gradient(at 0% 0%, #c084fc 0px, transparent 50%), radial-gradient(at 100% 0%, #38bdf8 0px, transparent 50%), radial-gradient(at 100% 100%, #818cf8 0px, transparent 50%), radial-gradient(at 0% 100%, #f472b6 0px, transparent 50%), #0f172a".to_string()),
            background_image_url: None,
            card_background: Some("rgba(255, 255, 255, 0.12)".to_string()),
            card_border: Some("1px solid rgba(255, 255, 255, 0.25)".to_string()),
            card_shadow: Some("0 8px 32px 0 rgba(0, 0, 0, 0.37)".to_string()),
            card_backdrop_blur: Some("24px".to_string()),
            text_color: Some("#ffffff".to_string()),
            text_muted_color: Some("rgba(255, 255, 255, 0.75)".to_string()),
            input_background: Some("rgba(255, 255, 255, 0.08)".to_string()),
            input_border_color: Some("rgba(255, 255, 255, 0.2)".to_string()),
            input_text_color: Some("#ffffff".to_string()),
            button_text_color: Some("#ffffff".to_string()),
            border_radius: Some("20px".to_string()),
            font_family: Some("'Inter', system-ui, -apple-system, sans-serif".to_string()),
            font_url: Some("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap".to_string()),
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
        "cyberpunk" | "midnight-neon" => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("cyberpunk".to_string()),
            primary_color: Some("#06b6d4".to_string()),
            primary_hover_color: Some("#0891b2".to_string()),
            background_color: Some("#05050a".to_string()),
            background_image_url: None,
            card_background: Some("rgba(13, 14, 25, 0.92)".to_string()),
            card_border: Some("1px solid #06b6d4".to_string()),
            card_shadow: Some("0 0 25px rgba(6, 182, 212, 0.35), inset 0 0 15px rgba(6, 182, 212, 0.05)".to_string()),
            card_backdrop_blur: Some("10px".to_string()),
            text_color: Some("#f0fdf4".to_string()),
            text_muted_color: Some("#94a3b8".to_string()),
            input_background: Some("#0d1117".to_string()),
            input_border_color: Some("#1e293b".to_string()),
            input_text_color: Some("#38bdf8".to_string()),
            button_text_color: Some("#05050a".to_string()),
            border_radius: Some("4px".to_string()),
            font_family: Some("'Space Grotesk', system-ui, -apple-system, sans-serif".to_string()),
            font_url: Some("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&display=swap".to_string()),
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
        "minimal-noir" | "dark-luxury" => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("minimal-noir".to_string()),
            primary_color: Some("#ffffff".to_string()),
            primary_hover_color: Some("#e2e8f0".to_string()),
            background_color: Some("#09090b".to_string()),
            background_image_url: None,
            card_background: Some("#121215".to_string()),
            card_border: Some("1px solid #27272a".to_string()),
            card_shadow: Some("0 20px 25px -5px rgba(0, 0, 0, 0.5)".to_string()),
            card_backdrop_blur: Some("0px".to_string()),
            text_color: Some("#fafafa".to_string()),
            text_muted_color: Some("#a1a1aa".to_string()),
            input_background: Some("#18181b".to_string()),
            input_border_color: Some("#27272a".to_string()),
            input_text_color: Some("#fafafa".to_string()),
            button_text_color: Some("#09090b".to_string()),
            border_radius: Some("8px".to_string()),
            font_family: Some("'Inter', system-ui, -apple-system, sans-serif".to_string()),
            font_url: Some("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap".to_string()),
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
        "neo-brutalist" => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("neo-brutalist".to_string()),
            primary_color: Some("#facc15".to_string()),
            primary_hover_color: Some("#eab308".to_string()),
            background_color: Some("#fffbeb".to_string()),
            background_image_url: None,
            card_background: Some("#ffffff".to_string()),
            card_border: Some("3px solid #000000".to_string()),
            card_shadow: Some("6px 6px 0px #000000".to_string()),
            card_backdrop_blur: Some("0px".to_string()),
            text_color: Some("#000000".to_string()),
            text_muted_color: Some("#4b5563".to_string()),
            input_background: Some("#ffffff".to_string()),
            input_border_color: Some("2px solid #000000".to_string()),
            input_text_color: Some("#000000".to_string()),
            button_text_color: Some("#000000".to_string()),
            border_radius: Some("0px".to_string()),
            font_family: Some("system-ui, -apple-system, sans-serif".to_string()),
            font_url: None,
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
        _ => ClientTheme {
            app_name: "JetAuth".to_string(),
            logo_url: None,
            logo_height: Some("48px".to_string()),
            favicon_url: None,
            theme_preset: Some("default".to_string()),
            primary_color: Some("#2563eb".to_string()),
            primary_hover_color: Some("#1d4ed8".to_string()),
            background_color: Some("#f8fafc".to_string()),
            background_image_url: None,
            card_background: Some("#ffffff".to_string()),
            card_border: Some("1px solid #e2e8f0".to_string()),
            card_shadow: Some("0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)".to_string()),
            card_backdrop_blur: Some("0px".to_string()),
            text_color: Some("#0f172a".to_string()),
            text_muted_color: Some("#64748b".to_string()),
            input_background: Some("#ffffff".to_string()),
            input_border_color: Some("#cbd5e1".to_string()),
            input_text_color: Some("#0f172a".to_string()),
            button_text_color: Some("#ffffff".to_string()),
            border_radius: Some("12px".to_string()),
            font_family: Some("system-ui, -apple-system, sans-serif".to_string()),
            font_url: None,
            footer_text: None,
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            terms_url: None,
            privacy_url: None,
            help_url: None,
            custom_css: None,
        },
    }
}

/// Merge a base theme with overrides from another theme (only non-None, non-empty fields override).
pub fn merge_themes(base: ClientTheme, override_theme: Option<ClientTheme>) -> ClientTheme {
    let Some(o) = override_theme else {
        return base;
    };

    let mut result = base;

    if !o.app_name.is_empty() {
        result.app_name = o.app_name;
    }
    if o.logo_url.is_some() {
        result.logo_url = o.logo_url;
    }
    if o.logo_height.is_some() {
        result.logo_height = o.logo_height;
    }
    if o.favicon_url.is_some() {
        result.favicon_url = o.favicon_url;
    }
    if o.theme_preset.is_some() {
        result.theme_preset = o.theme_preset;
    }
    if o.primary_color.is_some() {
        result.primary_color = o.primary_color;
    }
    if o.primary_hover_color.is_some() {
        result.primary_hover_color = o.primary_hover_color;
    }
    if o.background_color.is_some() {
        result.background_color = o.background_color;
    }
    if o.background_image_url.is_some() {
        result.background_image_url = o.background_image_url;
    }
    if o.card_background.is_some() {
        result.card_background = o.card_background;
    }
    if o.card_border.is_some() {
        result.card_border = o.card_border;
    }
    if o.card_shadow.is_some() {
        result.card_shadow = o.card_shadow;
    }
    if o.card_backdrop_blur.is_some() {
        result.card_backdrop_blur = o.card_backdrop_blur;
    }
    if o.text_color.is_some() {
        result.text_color = o.text_color;
    }
    if o.text_muted_color.is_some() {
        result.text_muted_color = o.text_muted_color;
    }
    if o.input_background.is_some() {
        result.input_background = o.input_background;
    }
    if o.input_border_color.is_some() {
        result.input_border_color = o.input_border_color;
    }
    if o.input_text_color.is_some() {
        result.input_text_color = o.input_text_color;
    }
    if o.button_text_color.is_some() {
        result.button_text_color = o.button_text_color;
    }
    if o.border_radius.is_some() {
        result.border_radius = o.border_radius;
    }
    if o.font_family.is_some() {
        result.font_family = o.font_family;
    }
    if o.font_url.is_some() {
        result.font_url = o.font_url;
    }
    if o.footer_text.is_some() {
        result.footer_text = o.footer_text;
    }
    if o.powered_by_text.is_some() {
        result.powered_by_text = o.powered_by_text;
    }
    if o.hide_powered_by {
        result.hide_powered_by = true;
    }
    if o.terms_url.is_some() {
        result.terms_url = o.terms_url;
    }
    if o.privacy_url.is_some() {
        result.privacy_url = o.privacy_url;
    }
    if o.help_url.is_some() {
        result.help_url = o.help_url;
    }
    if o.custom_css.is_some() {
        result.custom_css = o.custom_css;
    }

    result
}

/// Resolve the full effective theme for a client theme or fallback.
pub fn resolve_effective_theme(
    theme_opt: Option<ClientTheme>,
    global_settings: &RuntimeSettings,
) -> ClientTheme {
    // 1. Determine base preset: client's preset -> global's preset -> fallback
    let preset_name = theme_opt
        .as_ref()
        .and_then(|t| t.theme_preset.as_deref())
        .or_else(|| {
            global_settings
                .default_theme
                .as_ref()
                .and_then(|t| t.theme_preset.as_deref())
        })
        .unwrap_or("taika-dark");

    let base = apply_preset(preset_name);

    // 2. Layer global default theme over base
    let with_global = merge_themes(base, global_settings.default_theme.clone());

    // 3. Layer specific client theme over that
    merge_themes(with_global, theme_opt)
}

/// Resolve theme for a session ID.
pub async fn resolve_theme_for_session(session_id: &str) -> ClientTheme {
    let settings = store::get_runtime_settings().await;
    let session = match store::get_auth_session(session_id).await {
        Ok(Some(s)) => s,
        _ => return resolve_effective_theme(None, &settings),
    };
    match store::get_client(&session.client_id).await {
        Ok(Some(c)) => resolve_effective_theme(c.theme, &settings),
        _ => resolve_effective_theme(None, &settings),
    }
}

/// Resolve theme for a client ID.
pub async fn resolve_theme_for_client(client_id: &str) -> ClientTheme {
    let settings = store::get_runtime_settings().await;
    match store::get_client(client_id).await {
        Ok(Some(c)) => resolve_effective_theme(c.theme, &settings),
        _ => resolve_effective_theme(None, &settings),
    }
}

/// Resolve global default theme.
pub async fn resolve_global_theme() -> ClientTheme {
    let settings = store::get_runtime_settings().await;
    resolve_effective_theme(None, &settings)
}

/// Render the `<head>` branding assets (favicon, webfonts, and custom CSS variables).
pub fn render_head_tags(theme: &ClientTheme) -> String {
    let mut head = String::new();

    // Favicon
    if let Some(fav) = &theme.favicon_url
        && util::is_safe_url(fav)
    {
        head.push_str(&format!(
            r#"<link rel="icon" href="{}">"#,
            util::html_escape(fav)
        ));
        head.push('\n');
    }

    // Custom Webfont
    if let Some(font_url) = &theme.font_url
        && util::is_safe_url(font_url)
    {
        head.push_str(&format!(
                r#"<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="{}">"#,
                util::html_escape(font_url)
            ));
        head.push('\n');
    }

    head
}

/// Generate CSS variable values and styles.
pub fn render_css_variables(theme: &ClientTheme) -> String {
    let primary = sanitize_css_value(theme.primary_color.as_deref(), "#10b981");
    let primary_hover = sanitize_css_value(theme.primary_hover_color.as_deref(), "#059669");
    let bg = sanitize_css_value(
        theme.background_color.as_deref(),
        "linear-gradient(135deg, #090d16 0%, #0d1b2a 50%, #061e24 100%)",
    );
    let card_bg = sanitize_css_value(theme.card_background.as_deref(), "rgba(15, 23, 42, 0.75)");
    let card_border = sanitize_css_value(
        theme.card_border.as_deref(),
        "1px solid rgba(255, 255, 255, 0.12)",
    );
    let card_shadow = sanitize_css_value(
        theme.card_shadow.as_deref(),
        "0 25px 50px -12px rgba(0, 0, 0, 0.5)",
    );
    let card_blur = sanitize_css_value(theme.card_backdrop_blur.as_deref(), "20px");
    let text = sanitize_css_value(theme.text_color.as_deref(), "#f8fafc");
    let text_muted = sanitize_css_value(theme.text_muted_color.as_deref(), "#94a3b8");
    let input_bg = sanitize_css_value(theme.input_background.as_deref(), "rgba(30, 41, 59, 0.6)");
    let input_border = sanitize_css_value(
        theme.input_border_color.as_deref(),
        "rgba(255, 255, 255, 0.16)",
    );
    let input_text = sanitize_css_value(theme.input_text_color.as_deref(), "#f8fafc");
    let button_text = sanitize_css_value(theme.button_text_color.as_deref(), "#ffffff");
    let radius = sanitize_css_value(theme.border_radius.as_deref(), "14px");
    let font_family = sanitize_css_value(
        theme.font_family.as_deref(),
        "'Plus Jakarta Sans', system-ui, -apple-system, sans-serif",
    );

    let mut css = format!(
        r#":root {{
  --primary: {primary};
  --primary-hover: {primary_hover};
  --bg: {bg};
  --card-bg: {card_bg};
  --card-border: {card_border};
  --card-shadow: {card_shadow};
  --card-backdrop-blur: {card_blur};
  --text: {text};
  --text-muted: {text_muted};
  --input-bg: {input_bg};
  --input-border: {input_border};
  --input-text: {input_text};
  --button-text: {button_text};
  --radius: {radius};
  --font-family: {font_family};
}}
"#
    );

    if let Some(bg_img) = &theme.background_image_url
        && util::is_safe_url(bg_img)
        && !bg_img.chars().any(|c| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | ';' | '{' | '}' | '<' | '>' | '\\' | '\n' | '\r'
            )
        })
    {
        css.push_str(&format!(
                r#"body {{ background-image: url("{}"); background-size: cover; background-position: center; }}"#,
                util::html_escape(bg_img)
            ));
        css.push('\n');
    }

    if let Some(custom) = &theme.custom_css {
        let clean = sanitize_custom_css(custom);
        if !clean.trim().is_empty() {
            css.push_str("/* Custom CSS */\n");
            css.push_str(&clean);
            css.push('\n');
        }
    }

    css
}

/// Render the header logo HTML.
pub fn render_logo(theme: &ClientTheme) -> String {
    let app_name = util::html_escape(&theme.app_name);
    let logo_height = sanitize_css_value(theme.logo_height.as_deref(), "48px");
    match &theme.logo_url {
        Some(url) if util::is_safe_url(url) => format!(
            r#"<div style="text-align:center;margin-bottom:20px"><img src="{}" alt="{}" style="max-height:{};max-width:100%;object-fit:contain"></div>"#,
            util::html_escape(url),
            app_name,
            util::html_escape(logo_height),
        ),
        _ => String::new(),
    }
}

/// Render the white-labeled footer HTML.
pub fn render_footer(theme: &ClientTheme, extra_links: Option<&str>) -> String {
    let mut parts = Vec::new();

    if let Some(extra) = extra_links {
        parts.push(extra.to_string());
    }

    if let Some(terms) = &theme.terms_url
        && util::is_safe_url(terms)
    {
        parts.push(format!(
                r#"<a href="{}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none">Terms</a>"#,
                util::html_escape(terms)
            ));
    }

    if let Some(privacy) = &theme.privacy_url
        && util::is_safe_url(privacy)
    {
        parts.push(format!(
                r#"<a href="{}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none">Privacy</a>"#,
                util::html_escape(privacy)
            ));
    }

    if let Some(help) = &theme.help_url
        && util::is_safe_url(help)
    {
        parts.push(format!(
                r#"<a href="{}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none">Help</a>"#,
                util::html_escape(help)
            ));
    }

    if let Some(custom_foot) = &theme.footer_text
        && !custom_foot.trim().is_empty()
    {
        parts.push(util::html_escape(custom_foot));
    }

    if !theme.hide_powered_by {
        let powered_by = theme
            .powered_by_text
            .as_deref()
            .unwrap_or("Powered by JetAuth");
        if !powered_by.trim().is_empty() {
            parts.push(util::html_escape(powered_by));
        }
    }

    if parts.is_empty() {
        return String::new();
    }

    format!(r#"<p class="footer">{}</p>"#, parts.join(" · "))
}

/// Darken a hex color by ~15% for hover states.
pub fn darken_hex(hex: &str) -> String {
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return "#1d4ed8".to_string(); // fallback
    }
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(37);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(99);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(235);
    let darken = |c: u8| (c as f32 * 0.85) as u8;
    format!("#{:02x}{:02x}{:02x}", darken(r), darken(g), darken(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_custom_css() {
        let input = "body { color: red; } </style><script>alert(1)</script>";
        let sanitized = sanitize_custom_css(input);
        assert!(!sanitized.contains("</style>"));
    }

    #[test]
    fn test_apply_preset_taika_dark() {
        let preset = apply_preset("taika-dark");
        assert_eq!(preset.app_name, "JetAuth");
        assert_eq!(preset.primary_color, Some("#10b981".to_string()));
        assert_eq!(preset.border_radius, Some("14px".to_string()));
        assert_eq!(
            preset.powered_by_text,
            Some("Powered by JetAuth".to_string())
        );
    }

    #[test]
    fn test_apply_preset_glassmorphic() {
        let preset = apply_preset("glassmorphic");
        assert_eq!(preset.card_backdrop_blur, Some("24px".to_string()));
    }

    #[test]
    fn test_merge_themes_override() {
        let base = apply_preset("taika-dark");
        let custom = ClientTheme {
            app_name: "My Custom App".to_string(),
            primary_color: Some("#ff0000".to_string()),
            hide_powered_by: true,
            ..Default::default()
        };
        let merged = merge_themes(base, Some(custom));
        assert_eq!(merged.app_name, "My Custom App");
        assert_eq!(merged.primary_color, Some("#ff0000".to_string()));
        assert_eq!(merged.border_radius, Some("14px".to_string())); // preserved from base
        assert!(merged.hide_powered_by);
    }

    #[test]
    fn test_render_footer_white_labeled() {
        let theme = ClientTheme {
            app_name: "JetAuth".to_string(),
            powered_by_text: Some("Powered by JetAuth".to_string()),
            hide_powered_by: false,
            footer_text: Some("© 2026 Taika 3D".to_string()),
            ..Default::default()
        };
        let footer = render_footer(&theme, Some(r#"<a href="/account">Account</a>"#));
        assert!(footer.contains("Powered by JetAuth"));
        assert!(footer.contains("© 2026 Taika 3D"));
        assert!(footer.contains("Account"));
        assert!(!footer.contains("Lattice-ID"));
    }

    #[test]
    fn test_render_footer_hidden_powered_by() {
        let theme = ClientTheme {
            app_name: "JetAuth".to_string(),
            hide_powered_by: true,
            footer_text: Some("© 2026 Taika 3D".to_string()),
            ..Default::default()
        };
        let footer = render_footer(&theme, None);
        assert!(!footer.contains("Powered by"));
        assert!(footer.contains("© 2026 Taika 3D"));
    }

    #[test]
    fn test_sanitize_custom_css_bypass() {
        let input = "body { color: red; } </style ><script>alert('xss')</script> /* test */";
        let sanitized = sanitize_custom_css(input);
        assert!(!sanitized.to_ascii_lowercase().contains("</style"));
        assert!(!sanitized.to_ascii_lowercase().contains("<script"));
        assert!(sanitized.contains("body { color: red; }"));

        let mixed = "/* ok */ </sTyLe   id=\"evil\"> <SCRIPT src=\"evil.js\"></script>";
        let sanitized_mixed = sanitize_custom_css(mixed);
        assert!(!sanitized_mixed.to_ascii_lowercase().contains("</style"));
        assert!(!sanitized_mixed.to_ascii_lowercase().contains("<script"));
    }
}
