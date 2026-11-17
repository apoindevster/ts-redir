# ts-redir web interface

The browser interface shares TailBridge and TailShare's dark retro console
identity. Its purpose is to create, inspect, and delete host firewall redirects
into a Tailscale tailnet. Keep the form and rules table direct and readable;
color and type carry the 1980s/1990s neon character.

## Shared palette

Use TailShare's web palette, with TailBridge's stronger control outlines:

| Token | Value | Role |
| --- | --- | --- |
| Ink | `#0b101b` | Page and inset inputs |
| Panel | `#121b2b` | Form and rules surfaces |
| Raised panel | `#182339` | Section headers and row hover |
| Line | `#2c3950` | Structural dividers |
| Control line | `#647496` | Resting control boundaries |
| Text | `#edf4ff` | Values and primary text |
| Muted | `#a7b8d0` | Labels, instructions, placeholders |
| Cyan | `#67f5df` | Primary actions, TCP labels, success feedback |
| Magenta | `#ff70c9` | Brand return path, UDP labels, text selection |
| Orange | `#ffad70` | Keyboard focus and errors |

Protocol labels always include TCP or UDP text. Color never carries their
meaning alone. A static cyan/magenta/orange footer edge echoes TailBridge.
Use flat surfaces and thin dividers; no gradients, glow, blur, or shadows.

## Typography and controls

Use bundled Chakra Petch 600 for the brand and headings, and IBM Plex Sans
400/500/600 for controls and content. Font subsets and licenses live in
`internal/web/assets/fonts/`. Assets are embedded and served by Go, without
CDN or build-tool dependencies. System sans-serif remains the fallback.

Inputs use 16px type and a minimum 46px height. Buttons are at least 44px tall.
Controls have 4px corners, protocol labels 3px, and outer surfaces 7px. Orange
focus outlines are 2px with a 4px offset. Keep browser-native selects and number
inputs. Brief color transitions answer interaction; reduced motion disables them.

## Layout and behavior

The centered shell is at most 1220px wide, with a compact brand header, page
title, creation form, and existing rules. The desktop form uses three columns.
Below 700px it becomes a single column and each rule reflows into two columns
of labelled values with its Delete action below. Long addresses and peer names
wrap without hiding actions. Source descriptions sit below source addresses.

Preserve platform protocol restrictions: Linux offers TCP, UDP, and Both;
Windows offers TCP only. Both creates independently managed TCP and UDP rows.
Show loading, empty, error, disabled, and success states from real requests.
Keep form values on failure, prevent duplicate in-flight submissions, and
confirm deletion. Refresh updates existing rules without clearing form input.

TailBridge's reference is its native touchscreen, not a browser layout to copy.
TailShare supplies the web typography and control vocabulary. Neither project's
source files are modified by this shared styling work.
