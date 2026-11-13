import type { EntryIcon } from "@password-manager/shared/types";

/** Preset colors, muted to sit on the dark panels. The core stores only the name. */
export const ICON_COLORS: { name: string; label: string; value: string }[] = [
  { name: "slate", label: "スレート", value: "#8b96a3" },
  { name: "white", label: "ホワイト", value: "#d9dde1" },
  { name: "red", label: "レッド", value: "#e5757d" },
  { name: "orange", label: "オレンジ", value: "#e8955f" },
  { name: "amber", label: "アンバー", value: "#dcb15c" },
  { name: "lime", label: "ライム", value: "#a3c766" },
  { name: "green", label: "グリーン", value: "#7fbf8f" },
  { name: "teal", label: "ティール", value: "#6bb3ad" },
  { name: "cyan", label: "シアン", value: "#63bcd0" },
  { name: "sky", label: "スカイ", value: "#6aa7e0" },
  { name: "blue", label: "ブルー", value: "#7a8ff0" },
  { name: "indigo", label: "インディゴ", value: "#9488ee" },
  { name: "violet", label: "バイオレット", value: "#b083e8" },
  { name: "purple", label: "パープル", value: "#c77ee0" },
  { name: "pink", label: "ピンク", value: "#e07fb6" },
  { name: "brown", label: "ブラウン", value: "#b89878" }
];
export const DEFAULT_ICON_COLOR = "teal";

export function iconColor(name: string) {
  return (ICON_COLORS.find((color) => color.name === name) ?? ICON_COLORS.find((color) => color.name === DEFAULT_ICON_COLOR)!).value;
}

/** The first character of the name, as the list has always shown it. */
export function entryInitial(name: string) {
  return [...name.trim()][0]?.toUpperCase() ?? "?";
}

export function sameIcon(a: EntryIcon | null | undefined, b: EntryIcon | null | undefined) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

const IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp"];
const MAX_SOURCE_BYTES = 5 * 1024 * 1024;
const IMAGE_SIZE = 64;
/** The core refuses a larger image (crates/vault-core/src/icons.rs). */
const MAX_IMAGE_BYTES = 32 * 1024;

/**
 * Reads a local picture and redraws it as a 64 px PNG. Only the pixels are kept: the file's
 * metadata and anything embedded in it never reach the vault, and SVG is not accepted because
 * it can carry scripts and links.
 */
export async function imageToIcon(file: File): Promise<EntryIcon> {
  if (!IMAGE_TYPES.includes(file.type)) throw new Error("PNG・JPEG・WebPの画像を選んでください");
  if (file.size > MAX_SOURCE_BYTES) throw new Error("画像は5MB以内にしてください");
  let bitmap: ImageBitmap;
  try { bitmap = await createImageBitmap(file); }
  catch { throw new Error("画像を読み込めませんでした"); }
  try {
    const canvas = document.createElement("canvas");
    canvas.width = IMAGE_SIZE; canvas.height = IMAGE_SIZE;
    const context = canvas.getContext("2d");
    if (!context) throw new Error("画像を読み込めませんでした");
    // Fill the square from the middle of the picture, as an app icon would be cropped.
    const side = Math.min(bitmap.width, bitmap.height);
    context.imageSmoothingQuality = "high";
    context.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, IMAGE_SIZE, IMAGE_SIZE);
    const image = canvas.toDataURL("image/png");
    if (!image.startsWith("data:image/png;base64,") || (image.length - 22) * 0.75 > MAX_IMAGE_BYTES) throw new Error("画像を小さくできませんでした");
    return { kind: "image", image };
  } finally { bitmap.close(); }
}
