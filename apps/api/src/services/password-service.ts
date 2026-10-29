import { randomInt } from "node:crypto";
import type { PasswordGenerationResult } from "@password-manager/shared/types";
import { parseGenerationOptions } from "../lib/input-validation.js";

const UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
const NUMBERS = "23456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{}?";

export function generatePassword(input: unknown = {}): PasswordGenerationResult {
  const options = parseGenerationOptions(input);
  const length = options.length;
  const groups = [
    options.includeUppercase !== false ? UPPERCASE : "",
    options.includeLowercase !== false ? LOWERCASE : "",
    options.includeNumbers !== false ? NUMBERS : "",
    options.includeSymbols !== false ? SYMBOLS : ""
  ].filter(Boolean);

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
