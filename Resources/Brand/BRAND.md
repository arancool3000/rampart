# RamPart brand

The name is **RamPart**: capital R, capital P, one word. It reads "ram part", never "ramp art".

## The mark: the "Two-Part Shield"
A minimal shield drawn with three curves: a shallow crown and two flanks that meet at the point. It is split down the centre into a white half and a teal half.

**Look again:** the seam where the two halves meet is a keyhole. Two parts, one lock: *Ram* + *Part*, locked together.

At a glance it is just a clean, modern, two-tone shield. On a second look, the round bow and the flaring slot of a keyhole show up in the negative space between the halves, running out through the shield's point.

The outline and the keyhole are written by hand as SVG path data in `generate.swift` (`MarkGeometry.shieldD` / `keyholeD`). The halves are that outline split at x = 512 with the keyhole removed. Everything else is generated from it.

## Colour
| Token | Hex | Use |
|---|---|---|
| Navy | `#070D1C` | Tile base, dark backgrounds (Palette.navy) |
| Midnight | `#0A2840` | Tile mid-tone |
| Deep teal | `#0F5466` | Tile highlight (top left) |
| Teal | `#17B8CC` | Tile glow (Palette.teal) |
| Mint | `#54E6C2` | Teal half, gradient top (Palette.mint) |
| Accent, light | `#0A84A0` | Teal half, gradient bottom; R and P in the wordmark on light backgrounds; teal half of the light glyph |
| Accent, dark | `#40C8E0` | R and P in the wordmark on dark backgrounds; teal half of the dark glyph; glint glow |
| Ink | `#0B1B2E` | Wordmark and glyph on light backgrounds |
| Frost | `#C4EEF4` | White half, gradient bottom |

## Wordmark
SF Pro Rounded Bold, tracking −0.025 em, outlined to paths. **R** and **P** take the accent colour and the rest takes ink (light) or white (dark), so the two halves of the name read at a glance. Never retype the wordmark: use the SVGs.

## Clear space and minimum sizes
- Let **k** be the diameter of the keyhole bow (116 on the 1024 grid, about 1/5 of the shield's height).
  - Keep at least **1 k** clear around the bare shield.
  - In a lockup with the wordmark, leave 1 k to 1.5 k between the shield and the wordmark.
- Keep clear space of at least half the cap height of the R around the wordmark.
- App icon: the shipped sizes run from 16 px up.
  - At 16 px the keyhole shrinks to a hint, and the mark reads as a two-tone shield. That is intended.
  - From 32 px up the keyhole is clear.
- Bare shield: 12 pt tall at minimum. The menu bar uses the 18 pt template.
- Wordmark: at least 80 px (or 14 pt cap height) wide. Below that, use the shield alone.

## Files
| File | What |
|---|---|
| `logo-mark.svg` | Full icon (squircle tile and shield). `part-0` is the tile, `part-1` the white half (Ram) and `part-2` the teal half (Part). `part-3` is the keyhole plug: invisible at rest, and used only to animate the reveal. |
| `logo-glyph-light.svg` / `logo-glyph-dark.svg` | Bare shield for light and dark backgrounds. |
| `logo-wordmark-light.svg` / `logo-wordmark-dark.svg` | Outlined wordmark with one path per letter (`letter-R`, `letter-a`, `letter-m`, `letter-P`, `letter-a-2`, `letter-r`, `letter-t`). |
| `logo-mark-1024.png` | Icon master. |
| `AppIcon.iconset/`, `AppIcon.icns` | macOS app icon on the 824/1024 grid with 100-unit margins. Built with `iconutil`. |
| `MenuBarIconTemplate.png`, `@2x`, `MenuBarIcon.pdf` | 18 pt monochrome template (black and alpha). Set `isTemplate = true`. |
| `animation.json` | Path data, order, delays, durations, start values and easing for the mark and the letters. |
| `storyboard/frame-t000..t100.png` | Assembly animation at t = 0, 0.25, 0.5, 0.75 and 1 (1.6 s total). |
| `previews/` | Icon at 16 to 256 px, wordmark PNGs, and `concepts.png`, the labelled sheet of every concept explored. |
| `generate.swift` | Regenerates everything: `swift Resources/Brand/generate.swift`. Offscreen only. |

## Motion
The animation runs 1.6 s and reveals the hidden meaning last:
1. The tile springs in.
2. The white and teal halves glide in from the left and right and meet as a solid shield.
3. The letters of "RamPart" rise and fade in, 60 ms apart.
4. At 0.95 s the keyhole opens: the plug shrinks into the bow and fades.
5. A four-point glint flashes once on the shield's right shoulder (1.10 to 1.55 s).

Under Reduce Motion, cross-fade to the final state in 0.2 s and skip the glint. Nothing flashes red, shakes or loops.

## Do
- Use the supplied files on navy, white or the app's mesh backgrounds.
- Keep the white half on the left and the teal half on the right, so the keyhole reads.
- Use the dark glyph or wordmark on dark surfaces and the light versions on light surfaces.

## Don't
- Don't close or fill the keyhole. Don't add a check mark, a letter or any icon inside the shield.
- Don't recolour the mark red, orange, yellow or green. Those are status colours, and the McAfee, Norton, Avast and Bitdefender brands use them.
- Don't outline the shield, add bevels, or use glows beyond the supplied depth.
- Don't write "Rampart", "RAMPART" or "Ram Part" in brand contexts.
- Don't stretch, rotate or skew the mark, or set the wordmark in another font.

## Distinctiveness check (2026-11)
Checked against how the major vendors' logos are publicly described. This is not a legal trademark search. Get one before launch.

| Vendor | Their mark | How ours differs |
|---|---|---|
| Norton | Yellow circle with a black check mark | Not a circle, no check, no yellow |
| McAfee | Red shield carrying a white "M" | Ours carries no letter, uses no red, and is split in two with the keyhole as negative space |
| Avast | Orange orb or "amoeba" | No orb, no orange |
| Bitdefender | Red and black, with a "B" | No letterform, no red |
| Malwarebytes | Blue "M" emblem | No letterform |
| Kaspersky | Green and teal wordmark | Shares a teal family, but no wordmark-only mark |
| ESET | Teal wordmark | Shares a teal family, but no wordmark-only mark |
| Sophos | Blue wordmark | No wordmark-only mark |
| Intego | No logo descriptions found | Could not check |

Shield-and-keyhole is a common general idea in security clip-art. Ours is made distinctive by three things together:
- the keyhole exists only as the seam between two halves;
- the halves are split white and teal;
- the slot runs out through the point.

## Final mark (chosen 2026-11-06): the Two-Part Shield
A white shield with a peaked top, sloped shoulders and a soft point, drawn from scratch (not an SF Symbol), on a near-black squircle tile. The right half is about 11% darker, so it reads as lit from the left: two parts, Ram + Part, one shield. No keyholes, no glow.
Source: `generate-shield.swift` (variant 0). Earlier concepts are in `previous-concepts/`; the wordmark files above still apply.
