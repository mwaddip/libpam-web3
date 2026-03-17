# Page Templates

The signing page and signup page are split into replaceable **templates** (HTML/CSS) and engine-owned **JS bundles**. You can customize the look and feel without touching any wallet or chain logic.

## How It Works

```
template (HTML/CSS)     — layout, branding, copy, styles        (you own this)
engine bundle (JS)      — wallet connection, signing, chain ops  (engine owns this)
generator (Python/Bash) — injects config, combines them → output
```

## File Structure

```
auth-svc/signing-page/
  template.html        ← edit this for custom signing page styling
  engine.js            ← don't touch (wallet + signing logic)

scripts/
  signup-template.html ← edit this for custom signup page styling
  signup-engine.js     ← don't touch (wallet + purchase + decrypt logic)
  generate-signup-page.py  ← combines template + engine → signup.html
```

## Creating a Custom Template

1. Copy the default template (`template.html` or `signup-template.html`)
2. Modify HTML structure, CSS, copy, images — anything visual
3. Keep all **required DOM element IDs** intact (see below)
4. Keep the `CONFIG` script block and engine script include
5. Rebuild:
   - Signing page: run `packaging/build.sh` (inlines engine.js at package build time)
   - Signup page: run `python3 scripts/generate-signup-page.py`

## Template Variables

Placeholders in `{{VARIABLE}}` format, injected by the generator:

| Variable | Type | Description |
|----------|------|-------------|
| `PAGE_TITLE` | string | Page heading text |
| `PRIMARY_COLOR` | CSS color | Accent color (buttons, links, active states) |
| `PUBLIC_SECRET` | string | Message text the user signs |
| `SERVER_PUBLIC_KEY` | hex string | secp256k1 public key for ECIES encryption |
| `RPC_URL` | URL | Chain RPC endpoint |
| `NFT_CONTRACT` | hex string | NFT contract address |
| `SUBSCRIPTION_CONTRACT` | hex string | Subscription contract address |
| `CHAIN_ID` | integer | EVM chain ID |
| `USDC_ADDRESS` | hex string | Payment token (USDC) contract address |

`PRIMARY_COLOR` defaults to the `accent_color` field in `engine.json` (`#627EEA`). Override it in `blockhost.yaml` with `primary_color: "#yourcolor"`.

## Accent Color

The template uses a CSS variable for theming:

```css
:root {
    --primary: {{PRIMARY_COLOR}};
}
```

All buttons, links, active states, and highlights reference `var(--primary)`. Change the color in one place and the entire page follows.

## Required DOM Element IDs

The engine JS finds elements by `id`. Your template **must** include all of these.

### Signing Page

| Element ID | Type | Purpose |
|------------|------|---------|
| `btn-connect` | button | Triggers wallet connection |
| `btn-sign` | button | Triggers message signing |
| `wallet-address` | span/div | Displays connected wallet address |
| `status-message` | div | Shows status/error messages |
| `step-connect` | div | Connect wallet step container |
| `step-sign` | div | Sign message step container |

### Signup Page

| Element ID | Type | Purpose |
|------------|------|---------|
| `btn-connect` | button | Triggers wallet connection |
| `btn-sign` | button | Triggers message signing |
| `btn-purchase` | button | Triggers subscription purchase |
| `wallet-address` | span/div | Displays connected wallet address |
| `plan-select` | select | Plan selection dropdown |
| `days-input` | input | Subscription duration (days) |
| `total-cost` | span/div | Computed cost display |
| `status-message` | div | Shows status/error messages |
| `step-connect` | div | Connect wallet step container |
| `step-sign` | div | Sign message step container |
| `step-purchase` | div | Purchase step container |
| `step-servers` | div | View servers step container |
| `server-list` | div | Container for decrypted server details |

Your template can add any extra elements, sections, or IDs. It must not remove or rename the required ones.

## CSS Classes

The engine JS toggles these classes on elements. Your template's CSS defines what they look like.

| Class | Applied to | Meaning |
|-------|-----------|---------|
| `hidden` | any element | Not visible |
| `active` | step container | Currently active step |
| `completed` | step container | Step finished |
| `disabled` | button | Button not yet clickable |
| `loading` | button | Operation in progress |
| `error` | `#status-message` | Error state |
| `success` | `#status-message` | Success state |

Example CSS for these classes (from the default template):

```css
.hidden { display: none !important; }
.completed { border-color: var(--success); }
button.disabled, button:disabled { opacity: 0.5; cursor: not-allowed; }
button.loading { opacity: 0.7; cursor: wait; }
#status-message.error { background: ...; border: 1px solid var(--error); }
#status-message.success { background: ...; border: 1px solid var(--success); }
```

## CONFIG Object

The engine reads configuration from a global `CONFIG` object defined in a `<script>` block before the engine include:

```html
<script>
var CONFIG = {
    publicSecret: '{{PUBLIC_SECRET}}',
    serverPublicKey: '{{SERVER_PUBLIC_KEY}}',
    rpcUrl: '{{RPC_URL}}',
    nftContract: '{{NFT_CONTRACT}}',
    subscriptionContract: '{{SUBSCRIPTION_CONTRACT}}',
    chainId: {{CHAIN_ID}},
    usdcAddress: '{{USDC_ADDRESS}}',
};
</script>
<script type="module" src="signup-engine.js"></script>
```

The generator replaces the `{{...}}` placeholders with real values from `blockhost.yaml` and `web3-defaults.yaml`.
