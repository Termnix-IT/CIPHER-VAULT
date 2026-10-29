// JSON-compatible synthetic cases shared by HTTP and real Electron IPC tests.
export function validEntryPayload() {
  return { serviceName: "Contract fixture", loginId: "fixture-user", password: "synthetic-password" };
}

export function invalidContractCases() {
  const entry = validEntryPayload();
  const recordMessage = "入力はオブジェクトで指定してください";
  const unknownMessage = "未対応の入力項目があります";
  const cases = [
    ...[null, [], "text", 42].map((payload) => ({ operation: "createEntry", payload, status: 400, message: recordMessage })),
    { operation: "createEntry", payload: { ...entry, surprise: { secret: "must not be echoed" } }, status: 400, message: unknownMessage },
    { operation: "createEntry", payload: { ...entry, notes: 1 }, status: 400, message: "メモは文字列で指定してください" },
    { operation: "createEntry", payload: { ...entry, tags: [null] }, status: 400, message: "タグは文字列で指定してください" },
    { operation: "createEntry", payload: { ...entry, tags: Array(101).fill("tag") }, status: 413, message: "タグは100件まで指定できます" },
    { operation: "generatePassword", payload: { length: null }, status: 400, message: "パスワードの長さは12文字以上64文字以下で指定してください" },
    { operation: "generatePassword", payload: { includeSymbols: "false" }, status: 400, message: "文字種の指定は真偽値で指定してください" },
    { operation: "generatePassword", payload: { extra: true }, status: 400, message: unknownMessage },
    { operation: "exportBackup", payload: { passphrase: "synthetic-passphrase", content: "unexpected" }, status: 400, message: unknownMessage },
    { operation: "restoreBackup", payload: { passphrase: "synthetic-passphrase", content: [] }, status: 400, message: "バックアップファイルは文字列で指定してください" },
    { operation: "unlockVault", payload: { masterPassword: ["synthetic-passphrase"] }, status: 400, message: "マスターパスワードは文字列で指定してください" },
    { operation: "resetVault", payload: { confirmation: "RESET_ALL_DATA", extra: true }, status: 400, message: unknownMessage }
  ];
  for (const [field, label, bytes] of [
    ["serviceName", "サービス名", 1024], ["loginId", "ログインID", 4096], ["password", "パスワード", 65536],
    ["notes", "メモ", 262144], ["url", "URL", 8192], ["group", "グループ", 1024]
  ]) {
    // All values fit the HTTP envelope, including a multibyte overflow.
    const value = "あ".repeat(Math.floor(bytes / 3)) + "x".repeat(bytes % 3 + 1);
    cases.push({ operation: "createEntry", payload: { ...entry, [field]: value }, status: 413,
      message: `${label}の容量が上限を超えています（${bytes} byteまで）` });
  }
  cases.push({ operation: "createEntry", payload: { ...entry, tags: ["x".repeat(257)] }, status: 413,
    message: "タグの容量が上限を超えています（256 byteまで）" });
  return cases;
}

export const contractRoutes = {
  createEntry: "/entries", generatePassword: "/password/generate", exportBackup: "/vault/backup/export",
  restoreBackup: "/vault/backup/restore", unlockVault: "/vault/unlock", resetVault: "/vault/reset"
};
