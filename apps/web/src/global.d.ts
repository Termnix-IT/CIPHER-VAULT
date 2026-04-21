import type { PasswordManagerDesktopApi } from "@password-manager/shared/types";

declare global {
  interface Window {
    passwordManager?: PasswordManagerDesktopApi;
  }
}

export {};
