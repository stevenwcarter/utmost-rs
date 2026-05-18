# Utmost GUI — Lightbox Click-and-Drag Pan

**Date:** 2026-05-18
**Status:** Approved
**Author:** Steven Carter (with brainstorming assistance)

## 1. Overview

The lightbox supports zoom (slider, Fit button, `+`/`-`/`0` keys) but when the
zoomed image is larger than the viewport the user can only see the centered
portion — there's no way to look at the rest. This work adds click-and-drag
pan to the zoomed image so the user can move the visible region around.

Pan is disabled in fit mode (the image already fits the viewport, so there's
nothing to pan to). When zoomed, the body's center area becomes a draggable
surface; the existing 60px hover-only nav arrow strips on the left and right
stay on top so they're still reachable. The cursor shows `grab` while
hovering the drag surface and `grabbing` during an active drag.

All pan state lives in Slint on the `Lightbox` component — `pan-x` and
`pan-y` length properties. The Rust `ViewModel` and `LightboxView` struct
are not touched.

Spec follow-up to `2026-05-18-gui-preview-lightbox-design.md`. Implementation
plan will be a single small set of edits to `ui/lightbox.slint`.

## 2. Goals / Non-goals

**Goals**

- Click-and-drag pan when the lightbox is zoomed (`!fit`).
- Drag area covers the body Rectangle (excluding the 36px top bar and 40px
  bottom bar); `prev_touch` and `next_touch` sit on top of the drag area
  inside their 60px strips so nav arrows still work.
- Cursor reflects state: `grab` over the drag surface when zoomed,
  `grabbing` while pressed, default when in fit mode.
- Pan offset clamped so the image edges never go INSIDE the viewport. When
  the zoomed image is smaller than the viewport (zoom < native fit), the
  clamp pins the image centered.
- Pan resets to `(0, 0)` on three events:
  - Navigating to the next/prev image (`lightbox-index1` changes)
  - Switching to fit mode (Fit button or `0` key sets `fit = true`)
  - Lightbox first opens (covered by the existing `init => { self.focus(); }`)
- Pan persists across zoom changes (slider, `+`/`-`). The offset stays the
  same; the clamp absorbs the new bounds so the image edges still snap to
  the viewport edges.

**Non-goals**

- No keyboard pan (arrow keys are reserved for next/prev navigation).
- No two-finger touchpad pan (Slint TouchArea is mouse/single-pointer; touch
  is out of scope for this work).
- No momentum / inertia after release. Drag stops the instant the button is
  released.
- No Rust-side state for pan. The `ViewModel` and `LightboxView` are
  unchanged. Pan does not survive lightbox close/reopen — that's fine; we
  always re-open at center.
- No tests beyond the existing 33-test suite. Pure-Rust tests are
  untouched; manual smoke covers the drag behaviour.

## 3. Slint changes

Single file: `crates/utmost-gui/ui/lightbox.slint`.

### 3.1 New properties on `Lightbox`

```slint
property <length> pan-x: 0px;
property <length> pan-y: 0px;
```

### 3.2 New `drag_touch` TouchArea (inside the body Rectangle)

Placed **before** `prev_touch` and `next_touch` so the nav strips have
higher Z within their 60px regions:

```slint
drag_touch := TouchArea {
    x: 0;
    y: 0;
    width: parent.width;
    height: parent.height;
    enabled: root.has-image && !root.fit;
    mouse-cursor: drag_touch.pressed ? grabbing : grab;

    property <length> start-pan-x;
    property <length> start-pan-y;

    changed pressed => {
        if (self.pressed) {
            self.start-pan-x = root.pan-x;
            self.start-pan-y = root.pan-y;
        }
    }
    moved => {
        root.pan-x = drag_touch.start-pan-x + (self.mouse-x - self.pressed-x);
        root.pan-y = drag_touch.start-pan-y + (self.mouse-y - self.pressed-y);
    }
}
```

`enabled: root.has-image && !root.fit` means clicks fall through to whatever
is underneath (nothing meaningful) when in fit mode — the existing nav
strips on top of `drag_touch` still receive their clicks.

### 3.3 Update zoom-image positioning to apply pan + clamp

Replace the existing `x:` / `y:` lines on the `if root.has-image && !root.fit: Image` element with:

```slint
x: self.width > parent.width
   ? clamp((parent.width - self.width) / 2 + root.pan-x,
           parent.width - self.width,
           0px)
   : (parent.width - self.width) / 2;
y: self.height > parent.height
   ? clamp((parent.height - self.height) / 2 + root.pan-y,
           parent.height - self.height,
           0px)
   : (parent.height - self.height) / 2;
```

When the zoomed image is wider than the viewport (`self.width > parent.width`),
the clamp range is `[parent.width - self.width, 0]` — the image can pan
left (negative x) until its right edge reaches the viewport's right edge,
or pan right (toward x=0) until its left edge reaches x=0. Same for y.

When the image fits horizontally (`self.width <= parent.width`), the
formula falls back to the centered position `(parent.width - self.width) / 2`
regardless of `pan-x`. This guarantees that if the user pans at a high zoom
and then dollies back to a smaller zoom that makes the image fit, the
image snaps back to centered. The stored `pan-x` is preserved; it just
has no visible effect until the image is larger than the viewport again.

### 3.4 Reset triggers (component-scope `changed` callbacks)

```slint
changed index1 => {
    self.pan-x = 0px;
    self.pan-y = 0px;
}
changed fit => {
    if (self.fit) {
        self.pan-x = 0px;
        self.pan-y = 0px;
    }
}
```

## 4. Why state lives in Slint, not the ViewModel

The clamping math needs the rendered image dimensions (`self.width` =
`source.width * 1px * zoom`) and the body Rectangle dimensions
(`parent.width`, `parent.height`). Slint knows both natively; Rust does
not. Pushing pan into the `ViewModel` would force one of:

- A clamping round-trip (Slint → Rust → Slint each frame), or
- Publishing viewport + image dimensions to Rust just for clamping.

Both are worse than keeping pan Slint-local. Pan is also fundamentally a
transient UI concern (like hover state) and doesn't need to survive
lightbox close/reopen.

## 5. Testing

No new unit tests.

- `cargo build -p utmost-gui` — Slint syntax check.
- `cargo test -p utmost-gui` — confirms the existing 33-test suite still passes.
- Manual smoke (folded into Task 16 of the prior plan):
  - Open the lightbox, zoom in past fit, hold the mouse button down inside
    the image area, and drag — the image moves with the cursor.
  - Cursor changes to `grab` on hover and `grabbing` during drag.
  - Drag past the image edge — image stops at the viewport edge; user
    can't drag it off-screen.
  - Press right arrow to navigate — pan resets to centered on the new image.
  - Drag to a corner, then press `0` (fit) — image returns to centered fit
    view, pan resets.
  - Drag to a corner, then change zoom via the slider — pan stays at the
    same offset, image edges still pinned to viewport edges (clamped).
  - In fit mode, cursor over the image is default (not `grab`), and
    clicking does nothing (drag is disabled).

## 6. Open questions

None.

## 7. Out-of-scope follow-ups

- Keyboard pan (arrow keys with a modifier? Shift+arrow?).
- Two-finger touchpad pan.
- Momentum/inertia after release.
- Persisting pan across lightbox close/reopen.
