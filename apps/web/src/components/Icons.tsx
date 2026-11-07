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
