import { useEffect, useState } from "react";

const GLITCH_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*!?/\\|[]{}";

function randomChar(): string {
  return GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)];
}

function randomStr(length: number): string {
  return Array.from({ length }, () => randomChar()).join("");
}

/**
 * グリッチデコードアニメーション。
 * delayMs後にtarget文字列へ向かってランダム文字から徐々にデコードされる。
 */
export function useGlitchDecode(target: string, delayMs = 900): string {
  const [display, setDisplay] = useState(() => randomStr(target.length));

  useEffect(() => {
    setDisplay(randomStr(target.length));

    let interval: ReturnType<typeof setInterval> | undefined;

    const startTimeout = setTimeout(() => {
      const totalFrames = 28;
      let frame = 0;

      interval = setInterval(() => {
        frame++;
        const progress = frame / totalFrames;
        const revealedCount = Math.floor(progress * target.length);

        setDisplay(
          target
            .split("")
            .map((char, i) => {
              if (char === " ") return " ";
              if (i < revealedCount) return char;
              return randomChar();
            })
            .join("")
        );

        if (frame >= totalFrames) {
          clearInterval(interval);
          setDisplay(target);
        }
      }, 40);
    }, delayMs);

    return () => {
      clearTimeout(startTimeout);
      clearInterval(interval);
    };
  }, [target, delayMs]);

  return display;
}
