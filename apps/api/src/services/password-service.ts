import { randomInt } from "node:crypto";
import type { PasswordGenerationOptions, PasswordGenerationResult } from "@password-manager/shared/types";
import { HttpError } from "../lib/errors.js";

const UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
const NUMBERS = "23456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}?";

export function generatePassword(options: PasswordGenerationOptions = {}): PasswordGenerationResult {
  const length = options.length ?? 20;
  const groups = [
    options.includeUppercase !== false ? UPPERCASE : "",
    options.includeLowercase !== false ? LOWERCASE : "",
    options.includeNumbers !== false ? NUMBERS : "",
    options.includeSymbols !== false ? SYMBOLS : ""
  ].filter(Boolean);

  if (length < 12 || length > 64) {
    throw new HttpError(400, "パスワードの長さは12文字以上64文字以下で指定してください");
  }

  if (groups.length === 0) {
    throw new HttpError(400, "少なくとも1つの文字種を有効にしてください");
  }

  const requiredChars = groups.map((group) => group[randomInt(group.length)]);
  const combined = groups.join("");
  const generated = [...requiredChars];

  while (generated.length < length) {
    generated.push(combined[randomInt(combined.length)]);
  }

  for (let index = generated.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInt(index + 1);
    [generated[index], generated[swapIndex]] = [generated[swapIndex], generated[index]];
  }

  return {
    password: generated.join("")
  };
}
