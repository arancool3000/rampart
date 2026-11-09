# RamPart brand

The name is **RamPart**: capital R, capital P, one word. It reads "ram part", never "ramp art".

## The mark: the Pixel Guard (chosen 2026-11-09)
RamPart's mascot is a friendly robot security guard built from **pixel boxes**. The logo is the guard's **head**:
- a teal peaked cap with a gold shield badge, and a dark brim;
- a white shell with a dark face screen, two lit mint eyes and a little blush;
- grey ear guards and an antenna with a beacon light on top.

Every box is a slightly rounded square with a small gap, so it reads as "made of boxes". At 16 px the boxes become whole pixels with no gaps, so the silhouette stays crisp. It is two-tone: the right half of the shell, cap and uniform is a shade darker, as if lit from the left. Only the visor (the eyes) is lit, and it is crisp, with no glow.

The floating desktop bot is the same guard with a small boxy body: a teal uniform with a gold shield badge on the chest, white arms, a belt with a gold buckle, and grey legs.

### Single source of truth
`Sources/RampartApp/Features/Bot/PixelGuard.swift` holds:
- the pixel matrices (three head variants and the body);
- the face layout and expressions;
- the palette;
- the renderer (`PixelRenderer`), which is shared by SwiftUI (`PixelGuardView(size:expression:)`, `PixelBotView`) and CoreGraphics (icon generation).

`BotLogic.swift` holds the animator, the state machine and the speech bubble text.

### Regenerate
```sh
Resources/Brand/generate-guard.sh                  # AppIcon.iconset + .icns, logo-mark-1024.png, MenuBarIconTemplate(@2x).png, previews/icon-*.png
Resources/Brand/generate-guard.sh --previews DIR   # variant sheets + bot pose sheet into DIR only
```
The script compiles `generate-guard.swift` together with `PixelGuard.swift` and `BotLogic.swift`, and renders offscreen with CoreGraphics only.

## Variants explored
| # | Name | Notes |
|---|---|---|
| 1 | **Cap Guard** (shipped) | Peaked cap and badge read as "security guard" instantly. Friendly screen face. Strongest 16 px silhouette (antenna, cap, ears). |
| 2 | Visor Sentinel | Helmet with a forehead badge and a single slit visor. Cooler, but colder and less friendly. |
| 3 | Beacon Bot | A light bar on top and a big screen face. Reads as "robot" but not as "guard". |

## Colour
| Token | Hex | Use |
|---|---|---|
| Tile top / bottom | `#172131` / `#080D17` | App tile gradient |
| Cap / uniform | `#1FB4C8` (shade `#1696A8`) | Brand teal |
| Brim / belt | `#0E6876` (shade `#0B5866`) | |
| Shell | `#F5F8FB` (shade `#D3DCE6`) | Head and arms |
| Steel | `#95A3B6` (shade `#7A889C`) | Ear guards, antenna, legs |
| Badge gold | `#FFC53D` (shade `#E5A626`) | Cap and chest shield, buckle |
| Screen | `#0A1522` | Face |
| Visor / eyes | `#63F2CF` | Lit eyes, beacon at rest |
| Alert | `#FF5A5F` / beacon `#FF4D57` | Alert state only, never in the logo |
| Blush | `#F27C9C` | Cheeks |

## Files
| File | What |
|---|---|
| `logo-mark-1024.png` | Icon master (824/1024 tile grid). |
| `AppIcon.iconset/`, `AppIcon.icns` | All sizes from 16 to 1024. The 16 and 32 px sizes are full-bleed, so each box lands on a whole pixel. |
| `MenuBarIconTemplate.png`, `@2x` | 18 pt monochrome template (black and alpha). The screen and badge are cut-outs and the eyes stay solid. Set `isTemplate = true`. |
| `logo-wordmark-light.svg` / `-dark.svg` | Outlined wordmark, unchanged. |
| `previews/icon-*.png` | Icon at 16 to 256 px. |
| `previous-concepts/` | The retired Two-Part Shield, its generators and its concept sheet. |

## Motion (floating bot)
All motion is made of pixel boxes, runs at 30 fps at most (12 fps when idle) and pauses when the bot is hidden. Under Reduce Motion each state shows a static pose.

| State | Motion |
|---|---|
| Assembling (launch) | Scattered boxes fly in, top row first, then the dark plate fades in. |
| Idle | Blinks every few seconds; a dim visor scan line runs down the screen every 7 s. |
| Scanning | The beacon turns amber, a ripple runs through the boxes and the eyes sweep left and right. |
| Alert | The visor and beacon turn red, the beacon blinks, and the bot gives a short shake every 2.5 s. |
| Celebrating (Cat & Mouse catch) | Happy eyes, a wave, a bounce, and a finite burst of gold, mint and pink boxes. |
| Sleeping (protection paused) | Eyes closed, beacon off, small pixel "z"s drift up. |
| Happy (all clear) | Happy eyes and a wave. |
| Thinking, talking, listening | Typing dots, a moving mouth, or a pulsing beacon while you chat or speak. |

## Don't
- Don't add glow, blur or gradients to the boxes. Keep them flat, crisp and pixel-snapped.
- Don't recolour the guard red or orange outside the alert state.
- Don't write "Rampart", "RAMPART" or "Ram Part" in brand contexts.
- Don't stretch, rotate or skew the mark.
