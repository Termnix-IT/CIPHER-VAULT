import type { ReactNode } from "react";

function Icon({ children }: { children: ReactNode }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>;
}

export const LockIcon = () => <Icon><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></Icon>;
export const PlusIcon = () => <Icon><path d="M12 5v14M5 12h14" /></Icon>;
export const FolderPlusIcon = () => <Icon><path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><path d="M12 10.5v6M9 13.5h6" /></Icon>;
export const SearchIcon = () => <Icon><circle cx="11" cy="11" r="6" /><path d="m20 20-4.5-4.5" /></Icon>;
export const CloseIcon = () => <Icon><path d="M6 6l12 12M18 6 6 18" /></Icon>;
export const CopyIcon = () => <Icon><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" /></Icon>;
export const CheckIcon = () => <Icon><path d="m5 12 4 4L19 6" /></Icon>;
export const EyeIcon = ({ crossed = false }: { crossed?: boolean }) => <Icon>
  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" />{crossed && <path d="m3 3 18 18" />}
</Icon>;
export const ChevronIcon = () => <Icon><path d="m6 9 6 6 6-6" /></Icon>;
// Window buttons, drawn on a 10 px grid with 1 px lines as Windows draws its own.
function CaptionIcon({ children }: { children: ReactNode }) {
  return <svg viewBox="0 0 10 10" width="10" height="10" fill="none" stroke="currentColor" strokeWidth="1" aria-hidden="true">{children}</svg>;
}
export const MinimizeIcon = () => <CaptionIcon><path d="M0 5.5h10" /></CaptionIcon>;
export const MaximizeIcon = () => <CaptionIcon><rect x=".5" y=".5" width="9" height="9" /></CaptionIcon>;
export const RestoreIcon = () => <CaptionIcon><rect x=".5" y="2.5" width="7" height="7" /><path d="M2.5 2.5V.5h7v7h-2" /></CaptionIcon>;
export const WindowCloseIcon = () => <CaptionIcon><path d="M.5.5l9 9M9.5.5l-9 9" /></CaptionIcon>;
export const FileIcon = () => <Icon><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /></Icon>;
// Title bar. The same 24 px grid and 1.7 px line as the icons above.
export const SidebarIcon = ({ collapsed = false }: { collapsed?: boolean }) => <Icon>
  <rect x="3" y="4" width="18" height="16" rx="2" /><path d="M9 4v16" />{collapsed ? <path d="m13 10 2 2-2 2" /> : <path d="m16 10-2 2 2 2" />}
</Icon>;
export const EntriesIcon = () => <Icon><rect x="4" y="3" width="16" height="18" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></Icon>;
export const WrenchIcon = () => <Icon><path d="M12.5 9.9A5 5 0 0 1 18.8 3.5L16.4 5.9l1.7 1.7 2.4-2.4A5 5 0 0 1 14.1 11.5L5.4 20.2a1.2 1.2 0 0 1-1.6-1.6Z" /></Icon>;
export const HelpIcon = () => <Icon><circle cx="12" cy="12" r="9" /><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6" /><path d="M12 17h.01" /></Icon>;
export const GripIcon = () => <Icon><circle cx="9" cy="6" r="1" /><circle cx="15" cy="6" r="1" /><circle cx="9" cy="12" r="1" /><circle cx="15" cy="12" r="1" /><circle cx="9" cy="18" r="1" /><circle cx="15" cy="18" r="1" /></Icon>;
export const ImageIcon = () => <Icon><rect x="3" y="4" width="18" height="16" rx="2" /><circle cx="9" cy="10" r="2" /><path d="m21 16-5-5-9 9" /></Icon>;
