# RamPart brand

The name is **RamPart**: capital R, capital P, one word. It reads "ram part", never "ramp art".

## The mark: the "Keep R"
An R built from three dressed stones:
1. **Stem (tower).** It rises above the bowl and is crowned by one crenel with two merlons.
2. **Bowl (rampart block).** A solid block with a rounded front.
3. **Leg (stride).** A teal parallelogram, the forward motion of protection.

The pieces sit 22 units apart on the 1024 grid. Those gaps give the mark its masonry character, and they are also the parts the assembly animation uses (`part-1..3`).

Geometry lives in `generate.swift` (`MarkGeometry`) as SVG path data. Everything else is generated from it.

## Colour
| Token | Hex | Use |
|---|---|---|
| Navy | `#070D1C` | Tile base, dark backgrounds (Palette.navy) |
| Midnight | `#0A2840` | Tile mid-tone |
| Deep teal | `#0F5466` | Tile highlight (top left) |
| Teal | `#17B8CC` | Stride gradient end, glow (Palette.teal) |
| Mint | `#54E6C2` | Stride gradient start (Palette.mint) |
| Accent, light | `#0A84A0` | R and P in the wordmark on light backgrounds; stride on the light glyph |
| Accent, dark | `#40C8E0` | R and P in the wordmark on dark backgrounds; stride on the dark glyph |
| Ink | `#0B1B2E` | Wordmark and glyph on light backgrounds |
| Frost | `#C4EEF4` | Bottom of the white stone gradient |

## Wordmark
SF Pro Rounded Bold, tracking −0.025 em, outlined to paths. **R** and **P** take the accent colour and the rest takes ink (light) or white (dark), so the two halves of the name read at a glance. Never retype the wordmark: use the SVGs.

## Clear space and minimum sizes
- Let **s** be the stem width (128 on the 1024 grid, about 22% of the glyph height). Keep at least **1 s** clear around the bare glyph. For a mark plus wordmark lockup, keep the gap between them at 1 s to 1.5 s.
- Keep clear space of at least half the cap height of the R around the wordmark.
- App icon: the shipped sizes run from 16 px up. At 16 px the crenel drops out and the mark reads as a plain R, which is intended.
- Bare glyph: 12 pt tall at minimum. The menu bar uses the 18 pt template.
- Wordmark: 80 px (or 14 pt cap height) wide at minimum. Below that, use the glyph.

## Files
| File | What |
|---|---|
| `logo-mark.svg` | Full icon (squircle tile and mark). `part-0` is the tile and `part-1..3` are the stones in assembly order. |
| `logo-glyph-light.svg` / `logo-glyph-dark.svg` | Bare R for light and dark backgrounds. |
| `logo-wordmark-light.svg` / `logo-wordmark-dark.svg` | Outlined wordmark with one path per letter (`letter-R`, `letter-a`, `letter-m`, `letter-P`, `letter-a-2`, `letter-r`, `letter-t`). |
| `logo-mark-1024.png` | Icon master. |
| `AppIcon.iconset/`, `AppIcon.icns` | macOS app icon on the 824/1024 grid with 100-unit margins. Built with `iconutil`. |
| `MenuBarIconTemplate.png`, `@2x`, `MenuBarIcon.pdf` | 18 pt monochrome template (black and alpha). Set `isTemplate = true`. |
| `animation.json` | Path data, order, delays, durations, start values and easing for the mark and the letters. |
| `storyboard/frame-t000..t100.png` | Assembly animation at t = 0, 0.25, 0.5, 0.75 and 1 (1.2 s total). |
| `previews/` | Icon at 16 to 256 px, plus wordmark PNGs for review. |
| `generate.swift` | Regenerates everything: `swift Resources/Brand/generate.swift`. Offscreen only. |

## Motion
The animation runs 1.2 s in this order:
1. The tile springs in.
2. The tower grows up from the baseline.
3. The bowl slides in from the right.
4. The stride drops into place.
5. The letters rise and fade in, 60 ms apart.

Under Reduce Motion, cross-fade everything in 0.2 s. Nothing flashes, shakes or uses red.

## Do
- Use the supplied files on navy, white or the app's mesh backgrounds.
- Use the dark glyph or wordmark on dark surfaces and the light versions on light surfaces.
- Keep the stride teal. It is the one accent in the mark.

## Don't
- Don't put the mark inside a shield. The tower already says "protection", and shields put us in the same visual space as McAfee and Norton.
- Don't close the gaps between the stones, round off the crenel, or add outlines, bevels or glows beyond the supplied depth.
- Don't recolour the mark red, orange, yellow or green. Those are status colours, and the Norton, Avast and Bitdefender brands use them.
- Don't write "Rampart", "RAMPART" or "Ram Part" in brand contexts.
- Don't stretch, rotate or skew the mark, or set the wordmark in another font.

## Distinctiveness check (2026-11)
Checked against how the major vendors' logos are publicly described:
- **Norton:** yellow circle with a checkmark.
- **McAfee:** red shield with an M.
- **Bitdefender:** red and black, with a "B".
- **Malwarebytes:** blue "M" emblem.
- **Avast:** orange "amoeba".
- **Kaspersky:** green and teal geometric wordmark.
- **ESET:** teal wordmark.
- **Sophos:** blue wordmark.
- **Intego:** no logo descriptions were found; I could not check this one.

None of them uses a tower-stem R or a battlement. The nearest overlaps are colour (Kaspersky's and ESET's teal) and the general "monogram on a tile" format (Bitdefender, Malwarebytes). The letterform, the palette pairing of navy, white and teal, and the masonry construction all differ. This is not a legal trademark search. Get one before launch.
