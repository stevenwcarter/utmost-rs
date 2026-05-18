# Lightbox Click-and-Drag Pan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This feature is Slint-only — no Rust changes, no new tests. Verify via `cargo build -p utmost-gui` (Slint syntax) and `cargo test -p utmost-gui` (no regressions). The pre-commit hook runs `cargo fmt` + `cargo clippy --all-targets` and rejects on any warning.

**Goal:** Add click-and-drag pan to the lightbox's zoomed-image view so the user can navigate the visible region when the zoomed image is larger than the viewport.

**Architecture:** Single-file change to `crates/utmost-gui/ui/lightbox.slint`. Pan state (`pan-x`, `pan-y`) lives on the `Lightbox` component as `length` properties. A new `drag_touch` TouchArea inside the body Rectangle captures mouse-down + drag and updates the pan offsets. The zoom-image `x` / `y` formulas are rewritten to apply the pan with clamping that keeps image edges flush with viewport edges when the image is larger than the viewport, and snaps back to centered when the image fits. Pan resets on image-change and on switch-to-fit via Slint `changed` callbacks. No `ViewModel` or `LightboxView` changes.

**Tech Stack:** Slint 1.16 (`TouchArea` with `pressed` state and `moved` callback; `clamp()` built-in; `mouse-cursor: grab | grabbing` property).

**Spec:** `docs/superpowers/specs/2026-05-18-gui-lightbox-pan-design.md`

---

## File Structure

**Modified:**

- `crates/utmost-gui/ui/lightbox.slint` — adds `pan-x` / `pan-y` properties, `drag_touch` TouchArea inside the body, updated `x` / `y` formulas on the zoom-image, and two `changed` callbacks for resets

**Not touched:**

- No Rust file changes (`ViewModel`, `LightboxView`, `slint_adapter.rs` all unaffected)
- No new tests; the existing 33-test suite must continue to pass

---

## Task 1: Add pan state and drag mechanism

This task adds the active drag machinery: pan-x/pan-y properties, the drag TouchArea that captures mouse events, and the updated image positioning formula. After this task, drag works while the lightbox is open at a given image. The reset-on-navigation behavior is added in Task 2.

**Files:**
- Modify: `crates/utmost-gui/ui/lightbox.slint`

- [ ] **Step 1: Add `pan-x` and `pan-y` properties on the `Lightbox` component**

Open `crates/utmost-gui/ui/lightbox.slint`. Inside `export component Lightbox inherits FocusScope`, locate the `in property <bool> fit: true;` line (around line 10) and immediately after the existing `in property` and `callback` declarations (before the first child Rectangle), insert:

```slint
    property <length> pan-x: 0px;
    property <length> pan-y: 0px;
```

These are component-private (`property`, not `in property` or `in-out property`) since pan state lives entirely inside Slint and is never read or written from Rust.

- [ ] **Step 2: Add the `drag_touch` TouchArea inside the body Rectangle**

Locate the body Rectangle (the one with `y: 36px;`, `clip: true;`, currently around lines 22–103). Inside it, BEFORE the existing `prev_touch := TouchArea` block (which is currently the first child after the three conditional `if` blocks), insert the drag TouchArea. The order matters: `drag_touch` must come BEFORE `prev_touch` and `next_touch` so the nav strips are declared later and therefore render on top (intercepting clicks in their 60px regions first).

The new block:

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

Notes:
- `enabled: root.has-image && !root.fit` — drag is only active when zoomed and an image is loaded; in fit mode the TouchArea is inactive and clicks fall through.
- `mouse-cursor` is a TouchArea property in Slint 1.16. `grab` and `grabbing` are members of the `MouseCursor` enum.
- The two private properties (`start-pan-x`, `start-pan-y`) snapshot the pan offset when the mouse goes down. The `moved` callback then computes the new pan as `snapshot + (current_mouse - mouse_at_press)`.

- [ ] **Step 3: Update the zoom-image `x` and `y` formulas**

Find the zoom-image element (the one inside `if root.has-image && !root.fit:`, currently around lines 43–49). It currently has:

```slint
        if root.has-image && !root.fit: Image {
            source: root.source-image;
            width: self.source.width * 1px * root.zoom;
            height: self.source.height * 1px * root.zoom;
            x: (parent.width - self.width) / 2;
            y: (parent.height - self.height) / 2;
            image-fit: preserve;
        }
```

Replace the `x:` and `y:` lines with the panned + clamped versions:

```slint
        if root.has-image && !root.fit: Image {
            source: root.source-image;
            width: self.source.width * 1px * root.zoom;
            height: self.source.height * 1px * root.zoom;
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
            image-fit: preserve;
        }
```

Explanation of the formula:
- When the rendered image is wider than the viewport (`self.width > parent.width`): the clamp range is `[parent.width - self.width, 0px]` (a negative-to-zero range). The image can pan negatively (left) until its right edge reaches the viewport's right edge, or pan up to `0px` (where the image's left edge sits at the viewport's left).
- When the image fits (`self.width <= parent.width`): the expression returns `(parent.width - self.width) / 2`, a fixed centered position regardless of `pan-x`. If the user pans at high zoom then dollies back to a zoom level where the image fits, it snaps to centered.

- [ ] **Step 4: Build and run tests**

Run: `cargo build -p utmost-gui`
Expected: clean build, no Slint syntax errors.

Run: `cargo test -p utmost-gui`
Expected: 33/33 tests pass (the existing suite — no new tests in this work).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/lightbox.slint
git commit -m "feat(gui): click-and-drag pan in lightbox zoomed view"
```

---

## Task 2: Reset pan on image-change and on switch-to-fit

Adds two `changed` reactions on the `Lightbox` component so pan returns to `(0, 0)` when the user navigates to a different image or switches to fit mode. Without these, the pan offset survives navigation, which is wrong.

**Files:**
- Modify: `crates/utmost-gui/ui/lightbox.slint`

- [ ] **Step 1: Add `changed index1` and `changed fit` callbacks at component scope**

In `crates/utmost-gui/ui/lightbox.slint`, locate the existing `key-pressed(event) => { ... }` handler at the end of the `Lightbox` component (currently around lines 200–225). Immediately BEFORE that handler (still inside the component body), insert:

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

These fire when their respective properties change:
- `changed index1` — `lightbox-index1` is updated by Rust during sync whenever the user navigates next/prev. Each change resets pan.
- `changed fit` — `fit` becomes `true` when the user clicks the "Fit" button or presses the `0` key. Resets pan only when becoming `true` (no need to reset when leaving fit mode — pan-x and pan-y are still 0 from the prior fit reset).

- [ ] **Step 2: Build and run tests**

Run: `cargo build -p utmost-gui`
Expected: clean build.

Run: `cargo test -p utmost-gui`
Expected: 33/33 tests pass.

- [ ] **Step 3: Commit**

```bash
cargo fmt && cargo clippy --all-targets
git add crates/utmost-gui/ui/lightbox.slint
git commit -m "feat(gui): reset lightbox pan on image-change and switch-to-fit"
```

---

## Notes for the executing agent

- This is a Slint-only feature. The Rust `ViewModel` and `LightboxView` are intentionally untouched. Do NOT add `pan_x` / `pan_y` to Rust — the spec is explicit about pan living in Slint for the clamping math.
- If Slint compilation rejects `changed pressed` or `changed index1` or `changed fit` syntax, the codebase already uses `changed lightbox-index1` style in similar callbacks; try variants and document any deviation in the report. Slint 1.16 supports the `changed <property> => { ... }` syntax at component scope and inside TouchAreas.
- If `mouse-cursor: drag_touch.pressed ? grabbing : grab;` is rejected (the `grab` / `grabbing` enum members are part of the standard Slint `MouseCursor` enum in 1.16; both should work), fall back to just `grab` and report.
- Manual verification (not in scope as a task here, but useful when running locally): build with `cargo build --release`, open the GUI, navigate to a tile with a real image, open the lightbox, zoom past fit, then drag — image should move with the cursor and stop at edges. Pressing right arrow should reset pan on the new image. Pressing `0` should snap back to centered fit. The cursor should be `grab` over the image when zoomed and `grabbing` while dragging.
