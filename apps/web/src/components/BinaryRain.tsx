import { useEffect, useRef } from "react";

// Mixed glyph set: binary weighted heavily, plus hex and katakana fragments
const GLYPHS =
  "0101010101010101ABCDEF0123456789" +
  "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモ" +
  "@#$%/|\\[]{}·×÷±";

function randomGlyph(): string {
  return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
}

type Drop = {
  y: number;
  speed: number;
};

const COL_W = 14;
const FONT_SIZE = 13;

export function BinaryRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let drops: Drop[] = [];
    let animId: number;

    function resize() {
      if (!canvas || !ctx) return;
      cancelAnimationFrame(animId);
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      const columns = Math.floor(canvas.width / COL_W);
      drops = Array.from({ length: columns }, () => ({
        y: Math.random() * -(canvas!.height / FONT_SIZE),
        speed: 0.35 + Math.random() * 0.9,
      }));
      ctx.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;
      draw();
    }

    function draw() {
      if (!canvas || !ctx) return;

      // Semi-transparent overlay for trail fade
      ctx.fillStyle = "rgba(1, 10, 15, 0.065)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      for (let i = 0; i < drops.length; i++) {
        const drop = drops[i];
        const x = i * COL_W;
        const headY = Math.floor(drop.y) * FONT_SIZE;

        // Bright white-cyan head
        if (headY >= 0 && headY <= canvas.height + FONT_SIZE) {
          ctx.fillStyle = "rgba(210, 252, 255, 0.92)";
          ctx.fillText(randomGlyph(), x, headY);
        }

        // Glow neck just behind head
        const neck1Y = headY - FONT_SIZE;
        if (neck1Y >= 0 && neck1Y <= canvas.height) {
          ctx.fillStyle = "rgba(0, 255, 255, 0.52)";
          ctx.fillText(randomGlyph(), x, neck1Y);
        }

        // Secondary neck, starting to fade
        const neck2Y = headY - FONT_SIZE * 2;
        if (neck2Y >= 0 && neck2Y <= canvas.height) {
          ctx.fillStyle = "rgba(0, 220, 230, 0.22)";
          ctx.fillText(randomGlyph(), x, neck2Y);
        }

        drop.y += drop.speed;

        if (drop.y * FONT_SIZE > canvas.height && Math.random() > 0.975) {
          drop.y = Math.random() * -25;
          drop.speed = 0.35 + Math.random() * 0.9;
        }
      }

      animId = requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener("resize", resize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      role="presentation"
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        zIndex: 0,
      }}
    />
  );
}
