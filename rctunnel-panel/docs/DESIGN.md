# rcpanel — Design Specification (for designers)

> **Goal:** a fresh, friendly, trustworthy control panel in **green tones**, built on
> **Bootstrap 5.3**, with clear, purposeful micro-animations. Light by default,
> optional dark mode. This spec maps the visual language onto rcpanel's *real*
> screens (dashboard, agent, admin, profile, error pages).

---

## 0. Personality
- **Fresh & calm:** airy spacing, soft shadows, rounded corners, lots of white space.
- **Friendly:** human copy, friendly empty states, emoji/illustration accents, gentle motion.
- **Trustworthy:** consistent status colors, never hide failures, clear confirmations.
- Keep it **English-only** (the product is English-only).

---

## 1. Foundation: Bootstrap 5.3
Use stock Bootstrap 5.3 + a thin theme layer. Override tokens via CSS variables
(no fork needed). Drop this into `theme.css` loaded after Bootstrap:

```css
:root,[data-bs-theme="light"]{
  /* brand = emerald (fresh green) */
  --bs-primary:#10b981; --bs-primary-rgb:16,185,129;
  --rc-green-50:#ecfdf5;  --rc-green-100:#d1fae5; --rc-green-200:#a7f3d0;
  --rc-green-300:#6ee7b7; --rc-green-400:#34d399; --rc-green-500:#10b981;
  --rc-green-600:#059669; --rc-green-700:#047857; --rc-green-800:#065f46;
  --rc-green-900:#064e3b;
  --bs-body-bg:#f6faf8;            /* faint green-tinted off-white */
  --bs-body-color:#0f2e22;         /* deep green-charcoal text */
  --bs-border-color:#e3ece8;
  --bs-link-color:#047857;
  --bs-border-radius:.75rem; --bs-border-radius-lg:1rem; --bs-border-radius-sm:.5rem;
  /* semantic (coexist with green) */
  --bs-success:#10b981; --bs-info:#0ea5a4; --bs-warning:#f59e0b; --bs-danger:#ef4444;
}
[data-bs-theme="dark"]{
  --bs-body-bg:#0c1512; --bs-body-color:#dcefe7; --bs-border-color:#1d2c26;
  --bs-primary:#34d399; --bs-primary-rgb:52,211,153; --bs-link-color:#6ee7b7;
}
```

- **Primary button** = emerald `#10b981`; hover `#059669`; text on it = white.
- ⚠️ **Contrast:** emerald-500 on white fails AA for *small text* — use `--rc-green-700`
  (`#047857`) for green text/links on light, reserve emerald-500 for fills/buttons.

---

## 1A. Light / night theme switching
The product ships **both themes** with a toggle. Mechanism is Bootstrap 5.3 native:
the theme is the `data-bs-theme` attribute on `<html>` (`"light"` | `"dark"`); all
tokens in §1 already switch off it.

**Toggle control** — in the navbar, far right, before "Logout":
- An **icon button** that morphs sun ⇄ moon (Tabler `ti-sun` / `ti-moon`); 36×36, pill,
  ghost style; `aria-label="Toggle dark theme"`, reflects state with `aria-pressed`.
- Optionally a 3-way segmented control **Light · Auto · Dark** (Auto = follow OS). Default
  shipping: a simple sun/moon toggle with **Auto as the initial state**.

**Behavior**
- **First visit → Auto:** follow the OS (`prefers-color-scheme`). No stored choice yet.
- **On toggle → remember:** store the explicit choice in `localStorage["rc-theme"]`
  (`light`/`dark`); once set, it overrides the OS until the user picks Auto again.
- **No flash (FOUC):** apply the theme **before first paint** via a tiny inline script in
  `<head>`, *before* the stylesheet — never wait for `DOMContentLoaded`.

```html
<script>
  (function () {
    var s = localStorage.getItem('rc-theme');
    var dark = s ? s === 'dark'
                 : matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-bs-theme', dark ? 'dark' : 'light');
  })();
</script>
```
```js
function toggleTheme() {
  var el = document.documentElement;
  var next = el.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
  el.setAttribute('data-bs-theme', next);
  localStorage.setItem('rc-theme', next);     // explicit choice wins over OS
}
```

**Dark palette (surfaces & elevation)** — extend §1 `[data-bs-theme="dark"]`:
```css
[data-bs-theme="dark"]{
  --bs-body-bg:#0c1512;                 /* page */
  --rc-surface:#111f1a;                 /* cards */
  --rc-surface-2:#16261f;               /* elevated / inputs */
  --bs-body-color:#dcefe7; --bs-border-color:#1d2c26;
  --bs-primary:#34d399; --bs-primary-rgb:52,211,153;   /* brighter green for dark */
  --bs-link-color:#6ee7b7;
}
```
- In dark, status soft-badges use `rgba(green,.18)` fills with green-**300** text.
- Quota bar, online pulse, type pills keep the same hues (they read on both).

**Animation & a11y**
- Animate the swap: `transition: background-color var(--t), color var(--t), border-color var(--t)`
  on body/cards; rotate-fade the sun/moon icon (`--t`). Skip under `prefers-reduced-motion`.
- Both themes must pass **AA** contrast (re-check green text: dark uses green-300/400 on dark surfaces).
- Logo/illustrations need a dark variant (or use currentColor) so they don't glow on dark bg.

---

## 2. Typography
- **Font:** `Inter` (Google Fonts), fallback `system-ui, -apple-system, Segoe UI, Roboto, sans-serif`.
  Monospace for tokens/commands: `ui-monospace, "JetBrains Mono", monospace`.
- **Scale** (rem): h1 1.75 / h2 1.375 / h3 1.125 / body 0.95 / small 0.8125. Line-height 1.55.
- Weights: 400 body, 500 labels, 600 headings/buttons. Letter-spacing −0.01em on headings.
- Numbers in tables (ping, traffic, ports): `font-variant-numeric: tabular-nums`.

---

## 3. Core components (Bootstrap classes + theme)
| Element | Base | Notes |
|---|---|---|
| **Button (primary)** | `.btn .btn-success` | pill optional (`.rounded-pill`); hover lifts 1px + soft shadow |
| **Button (ghost)** | `.btn .btn-outline-secondary` | for secondary actions (Edit, Cancel) |
| **Button (danger)** | `.btn .btn-outline-danger` | Delete; turns solid red on the confirm step |
| **Card** | `.card` radius `lg`, `box-shadow:0 1px 2px rgba(6,95,70,.06),0 8px 24px rgba(6,95,70,.05)` | hover: shadow grows + `translateY(-2px)` |
| **Table** | `.table .align-middle` borderless, `--bs-table-hover-bg:var(--rc-green-50)` | row hover tint green |
| **Badge (status)** | `.badge rounded-pill` soft style: bg `rgba(green,.12)`, text green-700 | online/active = green, offline = gray, suspended = red |
| **Form control** | `.form-control` / `.form-floating` | focus ring = emerald `box-shadow:0 0 0 .25rem rgba(16,185,129,.25)` |
| **Toast** | `.toast` top-right stack | replaces alert()/inline — see §5 feedback |
| **Navbar** | `.navbar` sticky, surface/blur, green wordmark | links: Dashboard · Admin · Profile · Logout · **theme toggle** (sun/moon, far right) — see §1A |
| **Progress** | `.progress` | quota usage bar, color shifts (see §6 quota) |

Logo/wordmark: **rcpanel** lowercase, weight 600, with a small tunnel/arrow mark in
emerald gradient (`#34d399 → #059669`). Provide SVG.

---

## 4. Motion (clear, friendly — never flashy)
Tokens: durations `--t-fast:120ms`, `--t:220ms`, `--t-slow:360ms`; easing
`cubic-bezier(.4,0,.2,1)` (standard), `cubic-bezier(.34,1.56,.64,1)` (gentle overshoot for "pop").

| Interaction | Animation |
|---|---|
| Page/section enter | fade-in + 8px slide-up, `--t`, stagger cards 40ms |
| Button hover | `translateY(-1px)` + shadow, `--t-fast` |
| Card hover | lift 2px + shadow grow, `--t` |
| **Online status dot** | soft pulsing halo (2s ease-in-out infinite) — "alive" |
| **Ping chip** | number counts-up on load (300ms) |
| **Quota bar** | width animates from 0 to value on load, `--t-slow` |
| Toast | slide-in from right + fade, auto-dismiss 4s, progress underline |
| **Tunnel "Edit" row** | expand: height+opacity, `--t` (use Bootstrap `.collapse`) |
| **Delete confirm** | button morphs to red "Confirm?" with a 3s shrinking underline timer |
| Loading | skeleton shimmer (1.2s linear infinite) for tables/cards |
| Empty state | gentle float on the illustration (4s) |
| **Always** honor `@media (prefers-reduced-motion: reduce)` → disable transforms, keep opacity only |

---

## 5. Feedback pattern (important — replaces alert/confirm)
The app currently uses blocking `alert()/confirm()` which some browsers suppress.
**Designers: standardize on non-blocking UI:**
- **Success/error → Toasts** (top-right): green check toast "Password changed", red toast for errors. Never a browser dialog.
- **Destructive confirm → inline two-step** OR a small **popover/modal**: first click arms ("Confirm?" red, 3s), second confirms. Show what's being deleted.
- **Inline form validation:** field-level helper text under inputs, green check when valid.

---

## 6. Domain UI patterns (rcpanel-specific)
- **Agent status:** `online` = green pulse dot + label; `offline` = hollow gray dot. Stale = muted.
- **Ping chip:** `<100ms` green, `100–300ms` amber, `>300ms` red; `—` when offline.
- **Traffic:** show `↘ in 1.2 MB · ↗ out 4.5 MB` with subtle in/out icons (server-side perspective; tooltip explains). Human-readable units.
- **Quota:** progress bar `used / quota`; **green < 70%**, **amber 70–90%**, **red ≥ 90%**; at 100% the team row shows a red **"suspended"** badge.
- **Tunnel type:** colored pill per type — tcp/udp (slate), http/https (emerald), stcp/sudp/xtcp (violet, "private"), tcpmux (teal).
- **Install command:** monospace block with a **Copy** button (toast "Copied"), inside the agent page.
- **Agent version + OTA:** show version chip; if an update is rolling out, a subtle "updating…" shimmer.

---

## 7. Screen-by-screen
**7.1 Login** — centered card (max 380px) on a soft green gradient bg; logo on top;
floating-label email/password; full-width green button; friendly subtitle. Error → inline red helper, gentle shake (respect reduced-motion).

**7.2 Dashboard** — sticky navbar; page title + brief; two sections in cards:
- **Nodes** table (name, address, subdomain host, ports) + "Add node" inline form.
- **Agents** table: Name → link, Node, **Status** (pulse), **Ping** (chip), **Version**, **LAN IP**, **OS/Arch**, actions (two-step Delete). "Add agent" form (name + node select). Friendly empty state with illustration + "Add your first agent".

**7.3 Agent detail** — header with name + status + ping + os/version chips; **Install command** card (copy); **Tunnels** card: table (name + option chips: enc/cmp/bw/hc, type pill, local, exposes URL, **traffic in/out**, enabled switch, **Edit** expand row, two-step Delete) + "Add tunnel" form (type-aware fields, subdomain hint "up to 4 levels"); **Visitors** card similarly.

**7.4 Admin** (admin only) — **Teams** table: editable name (✎ inline), subdomain (`*.team.domain`), members, **quota progress bar** (used/quota), state badge, quota input + save, Delete. "Add team" form. **Users** table: email, role badge, team select (reassign), "Add user" form (email, password, role, team).

**7.5 Profile** — two cards: **Email** (input + save → toast), **Password** (current + new + save → toast). Clear success/error toasts (no dialogs).

**7.6 Error / status pages** (served when a tunnel is unavailable) — full-screen, centered, friendly illustration + headline, on soft green bg:
- 🚦 **Traffic limit reached** — "This tunnel is paused — the team's traffic quota is used up."
- 🔌 **Tunnel offline** — "The agent is offline right now."
- 🔍 **Tunnel not found.**
Keep calm tone, show the host, optional link/contact.

---

## 8. Layout & responsive
- Container max-width 1040px, 24px gutters; cards 16–24px padding.
- Spacing scale: 4/8/12/16/24/32/48.
- **Mobile (<768px):** navbar collapses to a toggler; data tables become stacked cards
  (label/value rows); forms go full-width single column; sticky primary action.
- Touch targets ≥ 44px.

---

## 9. Accessibility
- Contrast AA: green **text** uses `--rc-green-700+`; never emerald-500 for small text on white.
- Visible focus ring (emerald) on every interactive element; full keyboard nav.
- Status not by color alone — pair dot/badge with text ("online"/"suspended").
- `prefers-reduced-motion` respected. Form fields have real `<label>`s. Toasts use `aria-live="polite"`.

---

## 10. Deliverables expected from design
1. Figma file with: color/type tokens, component library (buttons, cards, table rows, badges, chips, forms, toasts, switches, progress, empty states), and the 6 screens (light + dark, desktop + mobile).
2. Logo/wordmark SVG + favicon.
3. 3 friendly illustrations for the error/empty states (traffic limit, offline, not found / empty).
4. Motion notes per interaction (or a short Lottie/anim spec) following §4 tokens.
5. `theme.css` token values confirmed against AA contrast.

> Implementation note for devs: the current panel is server-rendered (Jinja templates
> in `rcpanel/templates/`). The redesign = swap to Bootstrap 5.3 + `theme.css` and
> map existing blocks to the components above; no backend/API changes required.
