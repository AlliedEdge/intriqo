import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";

type NeuformMode = "dark" | "light";
type NeuformModePreference = NeuformMode | "auto";

type FocusTarget = {
  selector: string;
  role: "background" | "ui";
  width?: string;
};

type BakeKnobs = {
  size: number;
  gap: number;
  length: number;
  density: number;
  strokeWidth: number;
  mode: NeuformMode;
};

type EffectDefinition = {
  title: string;
  source: string;
  background: string | ((mode: NeuformMode) => string);
  defaultMode?: NeuformModePreference;
  supportsMode?: boolean;
  targets: readonly FocusTarget[];
  focusCss?: string;
  patch?: (source: string, knobs: BakeKnobs) => string;
};

export type ParticleDriftProps = {
  mode?: NeuformModePreference;
  speed?: number;
  size?: number;
  gap?: number;
  length?: number;
  density?: number;
  strokeWidth?: number;
  opacity?: number;
  hue?: number;
  saturation?: number;
  brightness?: number;
  className?: string;
  style?: CSSProperties;
  /**
   * When provided, mouse interaction inside the iframe is driven by pointer
   * events on this element instead of the iframe's own pointer events.
   * Particles only react when the cursor is over (or touching) the target.
   * Pass a ref to e.g. an auth card so the animation responds to the card area only.
   */
  mouseTarget?: React.RefObject<HTMLElement>;
};

const PARTICLE_DRIFT_DEFAULTS = {
  mode: "dark" as NeuformMode,
  speed: 1,
  size: 1,
  gap: 2,
  length: 1,
  density: 1,
  strokeWidth: 1,
  opacity: 1,
  hue: 0,
  saturation: 1,
  brightness: 1,
} as const;

const LIGHT_PAPER = "#eef1f6";

function clamp(value: number, minimum: number, maximum: number) {
  return Math.min(maximum, Math.max(minimum, value));
}

function scaleCount(base: number, density: number, minimum = 1) {
  return Math.max(minimum, Math.round(base * density));
}

function resolveMode(
  mode: NeuformMode | number | string | undefined,
  fallback: NeuformMode = "dark",
): NeuformMode {
  if (mode === undefined || mode === null) return fallback;
  if (mode === "light" || mode === 1 || mode === "1") return "light";
  return "dark";
}

function readAutomaticMode(): NeuformMode {
  if (typeof document === "undefined" || typeof window === "undefined")
    return "dark";
  const root = document.documentElement;
  const declared = root.dataset.scheme ?? root.dataset.theme;
  if (declared === "light" || declared === "dark") return declared;
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function useAutomaticMode(enabled: boolean) {
  const [mode, setMode] = useState<NeuformMode>(readAutomaticMode);

  useEffect(() => {
    if (
      !enabled ||
      typeof document === "undefined" ||
      typeof window === "undefined"
    )
      return undefined;
    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => setMode(readAutomaticMode());
    const observer = new MutationObserver(update);
    observer.observe(root, {
      attributes: true,
      attributeFilter: ["data-scheme", "data-theme"],
    });
    media.addEventListener("change", update);
    update();
    return () => {
      observer.disconnect();
      media.removeEventListener("change", update);
    };
  }, [enabled]);

  return mode;
}

function resolveBackground(
  background: EffectDefinition["background"],
  mode: NeuformMode,
) {
  return typeof background === "function" ? background(mode) : background;
}

// Minimal self-contained particle canvas document — no hero layout, no external CDN scripts.
// The focusScript (injected by buildFocusedDocument) moves #particle-canvas to
// position:fixed; inset:0; width:100%; height:100% so the surrounding markup is
// irrelevant for display, but stripping it avoids any layout jank on mobile where
// the iframe's internal viewport may not match the outer viewport before isolation.
const PARTICLE_DRIFT_SOURCE = `<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Particle Drift</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html, body {
            width: 100%; height: 100%;
            overflow: hidden;
            background: #030509;
        }
        #particle-canvas {
            display: block;
            width: 100%; height: 100%;
            /* The focusScript will promote this to position:fixed;inset:0 but
               sizing it 100% here ensures clientWidth/Height are non-zero on
               the very first resize() call, even before isolation runs. */
        }
    </style>
</head>
<body>
    <canvas id="particle-canvas"></canvas>

    <script>
        (function () {
            var canvas = document.getElementById('particle-canvas');
            var ctx = canvas.getContext('2d');

            var width = 0, height = 0;
            var nodes = [];
            var beams = [];
            var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&*()'.split('');
            var mouse = { x: -1e4, y: -1e4 };

            function resize() {
                width = canvas.clientWidth || window.innerWidth;
                height = canvas.clientHeight || window.innerHeight;
                var dpr = window.devicePixelRatio || 1;
                canvas.width = width * dpr;
                canvas.height = height * dpr;
                ctx.scale(dpr, dpr);
            }

            function initParticles() {
                nodes = Array.from({ length: 90 }).map(function () {
                    return {
                        x: Math.random() * width,
                        y: Math.random() * height,
                        vy: Math.random() * 0.4 + 0.1,
                        char: chars[Math.floor(Math.random() * chars.length)]
                    };
                });
                beams = Array.from({ length: 25 }).map(function () {
                    return {
                        x: Math.random() * width,
                        y: Math.random() * height,
                        length: Math.random() * 100 + 50,
                        speed: Math.random() * 6 + 3,
                        opacity: Math.random() * 0.5 + 0.3
                    };
                });
            }

            window.addEventListener('resize', function () {
                resize();
                initParticles();
            });

            // Native pointer events — active by default so the component
            // works standalone. The parent page can override by sending
            // { type: 'threeui-mouse', x, y } messages; once the first
            // such message arrives, native tracking is disabled and the
            // parent drives the cursor position entirely.
            var externalMouse = false;

            window.addEventListener('mousemove', function (e) {
                if (!externalMouse) {
                    mouse.x = e.clientX;
                    mouse.y = e.clientY;
                }
            });

            window.addEventListener('touchmove', function (e) {
                if (!externalMouse && e.touches.length > 0) {
                    mouse.x = e.touches[0].clientX;
                    mouse.y = e.touches[0].clientY;
                }
            }, { passive: true });

            window.addEventListener('touchend', function () {
                if (!externalMouse) {
                    mouse.x = -1e4;
                    mouse.y = -1e4;
                }
            });

            // Parent-injected mouse coordinates (used when the particle
            // canvas is a full-viewport background and only a specific
            // element on the parent page should drive the interaction).
            window.addEventListener('message', function (e) {
                if (!e.data || e.data.type !== 'threeui-mouse') return;
                externalMouse = true;
                mouse.x = typeof e.data.x === 'number' ? e.data.x : -1e4;
                mouse.y = typeof e.data.y === 'number' ? e.data.y : -1e4;
            });

            resize();
            initParticles();

            function draw() {
                var speed = (window.__SF_CONTROLS && window.__SF_CONTROLS.speed) || 1;
                ctx.clearRect(0, 0, width, height);

                // 1. Upward Beams
                beams.forEach(function (b) {
                    b.y -= b.speed * speed;
                    if (b.y + b.length < 0) {
                        b.y = height + 100;
                        b.x = Math.random() * width;
                    }
                    var g = ctx.createLinearGradient(b.x, b.y, b.x, b.y + b.length);
                    g.addColorStop(0, \`rgba(96, 165, 250, \${b.opacity})\`);
                    g.addColorStop(1, 'transparent');
                    ctx.strokeStyle = g;
                    ctx.lineWidth = 1.5;
                    ctx.beginPath();
                    ctx.moveTo(b.x, b.y);
                    ctx.lineTo(b.x, b.y + b.length);
                    ctx.stroke();
                });

                // 2. Interactive ASCII nodes
                ctx.font = '12px monospace';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';

                // Proximity lines
                ctx.lineWidth = 0.5;
                for (var i = 0; i < nodes.length; i++) {
                    var n1 = nodes[i];
                    for (var j = i + 1; j < nodes.length; j++) {
                        var n2 = nodes[j];
                        var d = Math.hypot(n1.x - n2.x, n1.y - n2.y);
                        if (d < 120) {
                            ctx.strokeStyle = \`rgba(156, 163, 175, \${0.15 * (1 - d / 120)})\`;
                            ctx.beginPath();
                            ctx.moveTo(n1.x, n1.y);
                            ctx.lineTo(n2.x, n2.y);
                            ctx.stroke();
                        }
                    }
                }

                nodes.forEach(function (n) {
                    n.y += n.vy * speed; // Slow drift
                    if (n.y > height + 20) {
                        n.y = -20;
                        n.x = Math.random() * width;
                    }
                    var dist = Math.hypot(mouse.x - n.x, mouse.y - n.y);
                    if (dist < 180 || Math.random() > 0.98) {
                        n.char = chars[Math.floor(Math.random() * chars.length)];
                    }
                    if (dist < 180) {
                        ctx.strokeStyle = \`rgba(96, 165, 250, \${0.5 * (1 - dist / 180)})\`;
                        ctx.beginPath();
                        ctx.moveTo(n.x, n.y);
                        ctx.lineTo(mouse.x, mouse.y);
                        ctx.stroke();
                    }
                    ctx.fillStyle = dist < 180 ? '#60A5FA' : 'rgba(156, 163, 175, 0.4)';
                    ctx.fillText(n.char, n.x, n.y);
                });

                requestAnimationFrame(draw);
            }

            draw();
        })();
    </script>
</body>
</html>`;

const PARTICLE_DRIFT_DEFINITION: EffectDefinition = {
  title: "Particle Drift",
  source: PARTICLE_DRIFT_SOURCE,
  supportsMode: true,
  background: (mode) => (mode === "light" ? LIGHT_PAPER : "#030509"),
  targets: [{ selector: "#particle-canvas", role: "background" }],
  patch(source, { size, length, density, mode }) {
    const link = Math.round(120 * length);
    const proximityAlpha = mode === "light" ? 0.22 : 0.15;
    let next = source
      // Scale node count by density
      .replace(
        "Array.from({ length: 90 })",
        `Array.from({ length: ${scaleCount(90, density, 12)} })`,
      )
      // Scale beam count by density
      .replace(
        "Array.from({ length: 25 })",
        `Array.from({ length: ${scaleCount(25, density, 4)} })`,
      )
      // Scale beam length
      .replace(
        "length: Math.random() * 100 + 50,",
        `length: (Math.random() * 100 + 50) * ${length},`,
      )
      // Scale proximity link distance
      .replace("if (d < 120) {", `if (d < ${link}) {`)
      .replace(
        `0.15 * (1 - d / 120)`,
        `${proximityAlpha} * (1 - d / ${link})`,
      )
      // Scale beam stroke width
      .replace(
        "ctx.lineWidth = 1.5;",
        `ctx.lineWidth = ${Number((1.5 * size).toFixed(2))};`,
      );

    if (mode === "light") {
      next = next
        .split("rgba(96, 165, 250,")
        .join("rgba(37, 99, 235,")
        .split("rgba(156, 163, 175,")
        .join("rgba(36, 48, 68,")
        .replace(
          "ctx.fillStyle = dist < 180 ? '#60A5FA' : 'rgba(156, 163, 175, 0.4)';",
          "ctx.fillStyle = dist < 180 ? '#2563EB' : 'rgba(36, 48, 68, 0.55)';",
        );
    }
    return next;
  },
};

function buildFocusedDocument(
  definition: EffectDefinition,
  knobs: BakeKnobs & {
    speed: number;
    opacity: number;
  },
) {
  const mode = knobs.mode;
  const background = resolveBackground(definition.background, mode);
  const targetJson = JSON.stringify(definition.targets).replace(
    /</g,
    "\\u003c",
  );
  const controlsJson = JSON.stringify({
    mode,
    speed: knobs.speed,
    size: knobs.size,
    gap: knobs.gap,
    length: knobs.length,
    density: knobs.density,
    strokeWidth: knobs.strokeWidth,
    opacity: knobs.opacity,
  }).replace(/</g, "\\u003c");
  const patchedSource = definition.patch
    ? definition.patch(definition.source, {
        size: knobs.size,
        gap: knobs.gap,
        length: knobs.length,
        density: knobs.density,
        strokeWidth: knobs.strokeWidth,
        mode,
      })
    : definition.source;
  const focusStyle = `<style data-threeui-focus>
html, body { width: 100% !important; height: 100% !important; min-height: 0 !important; margin: 0 !important; padding: 0 !important; overflow: hidden !important; background: ${background} !important; }
body { position: relative !important; display: flex !important; align-items: center !important; justify-content: center !important; }
body > * { visibility: hidden !important; }
body[data-threeui-ready] > [data-threeui-role] { visibility: visible !important; }
[data-threeui-residual] { display: none !important; }
[data-threeui-role="background"] { position: fixed !important; inset: 0 !important; width: 100% !important; height: 100% !important; max-width: none !important; max-height: none !important; z-index: 0 !important; opacity: 1 !important; pointer-events: none !important; }
[data-threeui-role="ui"] { position: relative !important; z-index: 1 !important; width: min(calc(100% - 32px), var(--threeui-target-width, 1040px)) !important; max-width: none !important; max-height: calc(100% - 32px) !important; margin: auto !important; overflow: auto !important; opacity: 1 !important; transform: none !important; filter: none !important; flex: none !important; box-sizing: border-box !important; }
${definition.focusCss ?? ""}
</style>`;
  const controlScript = `<script data-threeui-controls>
(function () {
  var controls = ${controlsJson};
  window.__SF_CONTROLS = controls;
  var origin = performance.now();
  var virtual = 0;
  var last = origin;
  var performanceNow = performance.now.bind(performance);
  var dateNow = Date.now.bind(Date);
  var dateOrigin = dateNow();
  performance.now = function () {
    var real = performanceNow();
    virtual += (real - last) * (controls.speed || 1);
    last = real;
    return origin + virtual;
  };
  Date.now = function () {
    return dateOrigin + (performance.now() - origin);
  };
  var raf = window.requestAnimationFrame.bind(window);
  window.requestAnimationFrame = function (callback) {
    return raf(function () {
      callback(performance.now());
    });
  };
  function applyVisual() {
    var opacity = controls.opacity == null ? 1 : controls.opacity;
    var size = controls.size == null ? 1 : controls.size;
    Array.prototype.forEach.call(document.querySelectorAll('[data-threeui-role]'), function (element) {
      element.style.opacity = String(opacity);
      if (element.getAttribute('data-threeui-role') === 'ui') {
        element.style.transform = 'scale(' + size + ')';
        element.style.transformOrigin = 'center center';
      }
    });
  }
  window.addEventListener('message', function (event) {
    if (!event.data || event.data.type !== 'threeui-controls') return;
    var next = event.data.controls || {};
    Object.keys(next).forEach(function (key) { controls[key] = next[key]; });
    applyVisual();
  });
  window.__SF_APPLY_CONTROLS = applyVisual;
})();
</script>`;
  const focusScript = `<script data-threeui-focus>
(function () {
  var isolated = false;
  function isolate() {
    if (isolated) return;
    var specs = ${targetJson};
    var roots = [];
    specs.forEach(function (spec) {
      var element = document.querySelector(spec.selector);
      if (!element) return;
      element.setAttribute('data-threeui-role', spec.role);
      if (spec.width) element.style.setProperty('--threeui-target-width', spec.width);
      if (!roots.some(function (root) { return root.contains(element); })) roots.push(element);
    });
    if (!roots.length) return;
    isolated = true;
    roots.forEach(function (root) { document.body.appendChild(root); });
    Array.from(document.body.children).forEach(function (element) {
      if (roots.indexOf(element) !== -1) return;
      element.setAttribute('data-threeui-residual', '');
      element.setAttribute('aria-hidden', 'true');
      if ('inert' in element) element.inert = true;
    });
    document.body.setAttribute('data-threeui-ready', '');
    if (window.__SF_APPLY_CONTROLS) window.__SF_APPLY_CONTROLS();
    requestAnimationFrame(function () { window.dispatchEvent(new Event('resize')); });
  }
  function scheduleIsolation() { setTimeout(isolate, 100); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scheduleIsolation, { once: true });
  else scheduleIsolation();
  window.addEventListener("load", isolate, { once: true });
})();
</script>`;
  return patchedSource
    .replace(/<head([^>]*)>/i, `<head$1>${controlScript}${focusStyle}`)
    .replace(/<\/body>/i, `${focusScript}</body>`);
}

export default function ParticleDrift({
  mode,
  speed = PARTICLE_DRIFT_DEFAULTS.speed,
  size = PARTICLE_DRIFT_DEFAULTS.size,
  gap = PARTICLE_DRIFT_DEFAULTS.gap,
  length = PARTICLE_DRIFT_DEFAULTS.length,
  density = PARTICLE_DRIFT_DEFAULTS.density,
  strokeWidth = PARTICLE_DRIFT_DEFAULTS.strokeWidth,
  opacity = PARTICLE_DRIFT_DEFAULTS.opacity,
  hue = PARTICLE_DRIFT_DEFAULTS.hue,
  saturation = PARTICLE_DRIFT_DEFAULTS.saturation,
  brightness = PARTICLE_DRIFT_DEFAULTS.brightness,
  className,
  style,
  mouseTarget,
}: ParticleDriftProps) {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const requestedMode =
    mode ??
    PARTICLE_DRIFT_DEFINITION.defaultMode ??
    PARTICLE_DRIFT_DEFAULTS.mode;
  const automaticMode = useAutomaticMode(requestedMode === "auto");
  const resolvedMode =
    requestedMode === "auto"
      ? automaticMode
      : resolveMode(requestedMode, PARTICLE_DRIFT_DEFAULTS.mode);
  const background = resolveBackground(
    PARTICLE_DRIFT_DEFINITION.background,
    resolvedMode,
  );
  const safeSpeed = clamp(speed, 0, 3);
  const safeSize = clamp(size, 0.05, 200);
  const safeGap = clamp(gap, 0, 64);
  const safeLength = clamp(length, 0.35, 2.5);
  const safeDensity = clamp(density, 0.25, 2.5);
  const safeStrokeWidth = clamp(strokeWidth, 0.25, 8);
  const safeOpacity = clamp(opacity, 0.05, 1);
  const safeHue = clamp(hue, -180, 180);
  const safeSaturation = clamp(saturation, 0, 2);
  const safeBrightness = clamp(brightness, 0.35, 1.65);

  // Rebuild when baked geometry/mode knobs change. Speed/opacity stay live via postMessage + time wrap.
  const source = useMemo(
    () =>
      buildFocusedDocument(PARTICLE_DRIFT_DEFINITION, {
        mode: resolvedMode,
        speed: PARTICLE_DRIFT_DEFAULTS.speed,
        size: safeSize,
        gap: safeGap,
        length: safeLength,
        density: safeDensity,
        strokeWidth: safeStrokeWidth,
        opacity: PARTICLE_DRIFT_DEFAULTS.opacity,
      }),
    [resolvedMode, safeDensity, safeGap, safeLength, safeSize, safeStrokeWidth],
  );

  const liveControls = useMemo(
    () => ({
      mode: resolvedMode,
      speed: safeSpeed,
      size: safeSize,
      gap: safeGap,
      length: safeLength,
      density: safeDensity,
      strokeWidth: safeStrokeWidth,
      opacity: safeOpacity,
    }),
    [
      resolvedMode,
      safeDensity,
      safeGap,
      safeLength,
      safeOpacity,
      safeSize,
      safeSpeed,
      safeStrokeWidth,
    ],
  );

  const pushControls = useCallback(() => {
    iframeRef.current?.contentWindow?.postMessage(
      { type: "threeui-controls", controls: liveControls },
      "*",
    );
  }, [liveControls]);

  // Push on every knob change, and again once the frame has actually loaded:
  // a message posted before the frame installed its listener is dropped, which
  // would otherwise leave the baked defaults in place until the next change.
  useEffect(() => {
    pushControls();
  }, [pushControls, source]);

  // If a mouseTarget element is provided, track pointer events on it and relay
  // coordinates into the iframe via postMessage. The iframe's own native mouse
  // listeners are suppressed once it receives the first such message.
  useEffect(() => {
    const target = mouseTarget?.current;
    if (!target) return;

    const sendMouse = (x: number, y: number) => {
      iframeRef.current?.contentWindow?.postMessage(
        { type: "threeui-mouse", x, y },
        "*",
      );
    };

    const sendOff = () => sendMouse(-1e4, -1e4);

    const onMove = (e: MouseEvent) => {
      const rect = target.getBoundingClientRect();
      // Translate from page coords to iframe (full-viewport) coords —
      // they share the same pixel space since the iframe fills the viewport.
      sendMouse(e.clientX, e.clientY);
      // Clamp: if cursor drifted outside the card, send off-screen
      if (
        e.clientX < rect.left || e.clientX > rect.right ||
        e.clientY < rect.top  || e.clientY > rect.bottom
      ) sendOff();
    };

    const onTouch = (e: TouchEvent) => {
      if (e.touches.length === 0) return sendOff();
      const t = e.touches[0];
      sendMouse(t.clientX, t.clientY);
    };

    target.addEventListener("mousemove", onMove);
    target.addEventListener("mouseleave", sendOff);
    target.addEventListener("touchmove", onTouch, { passive: true });
    target.addEventListener("touchend", sendOff);

    // Immediately push off-screen so native tracking doesn't fire first
    sendOff();

    return () => {
      target.removeEventListener("mousemove", onMove);
      target.removeEventListener("mouseleave", sendOff);
      target.removeEventListener("touchmove", onTouch);
      target.removeEventListener("touchend", sendOff);
    };
  }, [mouseTarget, source]);

  const filter =
    safeHue === 0 && safeSaturation === 1 && safeBrightness === 1
      ? undefined
      : `hue-rotate(${safeHue}deg) saturate(${safeSaturation}) brightness(${safeBrightness})`;

  return (
    <iframe
      ref={iframeRef}
      className={className}
      title={PARTICLE_DRIFT_DEFINITION.title}
      srcDoc={source}
      sandbox="allow-scripts"
      loading="eager"
      onLoad={pushControls}
      style={{
        display: "block",
        width: "100%",
        height: "100%",
        border: 0,
        background,
        filter,
        ...style,
      }}
    />
  );
}