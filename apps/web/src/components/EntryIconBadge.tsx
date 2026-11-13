import type { ReactNode } from "react";
import type { EntryIcon } from "@password-manager/shared/types";
import { entryInitial, iconColor } from "../lib/entry-icons";

function Glyph({ children }: { children: ReactNode }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>;
}

/** Preset symbols for list icons. Drawn for this app on the same grid as components/Icons.tsx. */
export const ENTRY_SYMBOLS: { name: string; label: string; keywords: string; glyph: ReactNode }[] = [
  { name: "key", label: "鍵", keywords: "key password パスワード", glyph: <><circle cx="8" cy="15" r="4" /><path d="m10.8 12.2 8.7-8.7M16 6l2.5 2.5M13.5 8.5 16 11" /></> },
  { name: "lock", label: "ロック", keywords: "lock 錠 セキュリティ", glyph: <><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></> },
  { name: "shield", label: "盾", keywords: "shield security セキュリティ 保護", glyph: <path d="M12 3 5 6v5c0 4.5 3 8.3 7 10 4-1.7 7-5.5 7-10V6z" /> },
  { name: "globe", label: "ウェブ", keywords: "globe web site サイト インターネット", glyph: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z" /></> },
  { name: "mail", label: "メール", keywords: "mail email メール", glyph: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3.5 6.5 8.5 6.5 8.5-6.5" /></> },
  { name: "chat", label: "チャット", keywords: "chat message sns チャット メッセージ", glyph: <path d="M4 5h16v11H9l-5 4z" /> },
  { name: "bank", label: "銀行", keywords: "bank 銀行 金融", glyph: <path d="M3 9.5 12 4l9 5.5M4 20h16M6 10v7M10 10v7M14 10v7M18 10v7" /> },
  { name: "card", label: "カード", keywords: "card credit クレジット カード", glyph: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 10h18M7 15h4" /></> },
  { name: "wallet", label: "財布", keywords: "wallet pay 財布 決済", glyph: <><path d="M19 7V5a1 1 0 0 0-1-1H5a2 2 0 0 0 0 4h14a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H5a2 2 0 0 1-2-2V6" /><path d="M16 14h.01" /></> },
  { name: "yen", label: "お金", keywords: "money yen お金 円", glyph: <><circle cx="12" cy="12" r="9" /><path d="m9 7.5 3 4.5 3-4.5M12 12v5M9 13h6M9 15.5h6" /></> },
  { name: "chart", label: "投資", keywords: "chart stock 投資 証券 株", glyph: <><path d="M4 4v16h16" /><path d="m7 14 4-4 3 3 5-6" /></> },
  { name: "cart", label: "買い物", keywords: "cart shop ショッピング 買い物 通販", glyph: <><path d="M3 4h2l2.4 11h10.2L20 8H6.2" /><circle cx="9" cy="19" r="1.3" /><circle cx="17" cy="19" r="1.3" /></> },
  { name: "cloud", label: "クラウド", keywords: "cloud クラウド", glyph: <path d="M7 18a4 4 0 0 1-.5-8 6 6 0 0 1 11.5 1.5A3.3 3.3 0 0 1 17.5 18Z" /> },
  { name: "server", label: "サーバー", keywords: "server サーバー", glyph: <><rect x="3" y="4" width="18" height="7" rx="1.5" /><rect x="3" y="13" width="18" height="7" rx="1.5" /><path d="M7 7.5h.01M7 16.5h.01" /></> },
  { name: "database", label: "データベース", keywords: "database db データベース", glyph: <><ellipse cx="12" cy="5.5" rx="7" ry="2.5" /><path d="M5 5.5v13c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-13M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5" /></> },
  { name: "code", label: "コード", keywords: "code dev 開発 コード", glyph: <path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14" /> },
  { name: "terminal", label: "ターミナル", keywords: "terminal ssh shell ターミナル", glyph: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3M12 15h5" /></> },
  { name: "wifi", label: "Wi-Fi", keywords: "wifi network ネットワーク", glyph: <><path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.5 16a5 5 0 0 1 7 0" /><path d="M12 19.5h.01" /></> },
  { name: "link", label: "リンク", keywords: "link url リンク", glyph: <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" /> },
  { name: "folder", label: "フォルダ", keywords: "folder file フォルダ", glyph: <path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /> },
  { name: "user", label: "個人", keywords: "user person account 個人 アカウント", glyph: <><circle cx="12" cy="8" r="4" /><path d="M4.5 20a7.5 7.5 0 0 1 15 0" /></> },
  { name: "users", label: "チーム", keywords: "users team group チーム 家族", glyph: <><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6" /></> },
  { name: "briefcase", label: "仕事", keywords: "work business 仕事 会社", glyph: <><rect x="3" y="7" width="18" height="13" rx="2" /><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M3 13h18" /></> },
  { name: "home", label: "家", keywords: "home house 家 自宅", glyph: <path d="M4 10.5 12 4l8 6.5V19a1 1 0 0 1-1 1h-4.5v-6h-5v6H5a1 1 0 0 1-1-1z" /> },
  { name: "phone", label: "スマホ", keywords: "phone mobile スマホ 携帯", glyph: <><rect x="6.5" y="3" width="11" height="18" rx="2" /><path d="M11 17.5h2" /></> },
  { name: "game", label: "ゲーム", keywords: "game ゲーム", glyph: <><rect x="2.5" y="7" width="19" height="11" rx="4" /><path d="M7 11v3M5.5 12.5h3M15.5 12h.01M18 14h.01" /></> },
  { name: "music", label: "音楽", keywords: "music 音楽", glyph: <><path d="M9 18V6l11-2v12" /><circle cx="6.5" cy="18" r="2.5" /><circle cx="17.5" cy="16" r="2.5" /></> },
  { name: "video", label: "動画", keywords: "video movie 動画 映画 配信", glyph: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m10 9 5 3-5 3z" /></> },
  { name: "camera", label: "写真", keywords: "camera photo 写真 カメラ", glyph: <><path d="M4 8h3l2-3h6l2 3h3a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z" /><circle cx="12" cy="13.5" r="3.5" /></> },
  { name: "book", label: "本", keywords: "book study 本 学習 学校", glyph: <path d="M5 4h13v16H7a2 2 0 0 1-2-2zM5 18a2 2 0 0 1 2-2h11" /> },
  { name: "plane", label: "旅行", keywords: "travel plane 旅行 移動", glyph: <path d="M10.5 13.5 3 11l17-7-7 17-2.5-7.5Z" /> },
  { name: "health", label: "医療", keywords: "health medical 医療 病院 健康", glyph: <path d="M9 3h6v6h6v6h-6v6H9v-6H3V9h6z" /> },
  { name: "star", label: "お気に入り", keywords: "star favorite お気に入り", glyph: <path d="m12 3.5 2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z" /> },
  { name: "heart", label: "ハート", keywords: "heart like ハート", glyph: <path d="M12 20s-7.5-4.6-7.5-10A4.3 4.3 0 0 1 12 7.4 4.3 4.3 0 0 1 19.5 10c0 5.4-7.5 10-7.5 10Z" /> },
  { name: "tag", label: "タグ", keywords: "tag label タグ", glyph: <><path d="M3.5 3.5h7.6l9.4 9.4-7.6 7.6-9.4-9.4z" /><circle cx="7.5" cy="7.5" r="1.2" /></> },
  { name: "settings", label: "設定", keywords: "settings tool 設定 ツール", glyph: <><path d="M4 7h10M18 7h2M4 17h4M12 17h8" /><circle cx="16" cy="7" r="2" /><circle cx="10" cy="17" r="2" /></> }
];

export function symbolGlyph(name: string) {
  return ENTRY_SYMBOLS.find((symbol) => symbol.name === name)?.glyph;
}

/**
 * The icon of a list entry. Without a setting it is the neutral letter badge the list has always
 * shown; a symbol that this version does not know falls back to the letter in its color.
 */
export function EntryIconBadge({ name, icon, className = "" }: { name: string; icon?: EntryIcon | null; className?: string }) {
  if (icon?.kind === "image") {
    return <span className={`entry-badge entry-badge--image ${className}`} aria-hidden="true"><img src={icon.image} alt="" draggable={false} /></span>;
  }
  const glyph = icon?.kind === "symbol" ? symbolGlyph(icon.symbol) : undefined;
  const style = icon ? { ["--icon-color" as string]: iconColor(icon.color) } : undefined;
  return <span className={`entry-badge ${icon ? "entry-badge--colored" : ""} ${className}`} style={style} aria-hidden="true">
    {glyph ? <Glyph>{glyph}</Glyph> : entryInitial(name)}
  </span>;
}
