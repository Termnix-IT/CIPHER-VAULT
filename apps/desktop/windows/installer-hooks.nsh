; Saved with a UTF-8 BOM, as the setup's own files are, so makensis reads the Japanese messages as UTF-8.
; Included by the Tauri setup (bundle.windows.nsis.installerHooks in tauri.conf.json).
;
; Before this app is installed, the Electron app of the same product is removed with its own
; uninstaller. That uninstaller keeps %APPDATA%\<product>\data, the vault folder both apps use, so
; the vault stays where it is. The Electron app is found only by its uninstall key, which
; electron-builder names after the app's appId, so no other program is touched.
;
; Only LogicLib blocks are used, never labels, because the macro is inserted twice in one section.

Var CipherVaultCommand
Var CipherVaultArguments
Var CipherVaultAt
Var CipherVaultFolder
Var CipherVaultVault
Var CipherVaultSession
Var CipherVaultRunning

; Sets CipherVaultRunning to 1 when the Electron program in CipherVaultFolder runs.
!macro CIPHER_VAULT_CHECK_ELECTRON
  Push $0
  Push $1
  Push $2
  Push $3
  StrCpy $CipherVaultRunning 0
  !insertmacro RestartManager_StartSession $CipherVaultSession
  ${If} $CipherVaultSession != ""
    !insertmacro RestartManager_RegisterFile $CipherVaultSession "$CipherVaultFolder\${PRODUCTNAME}.exe"
    ${If} $0 = 0
      System::Call 'RSTRTMGR::RmGetList(p $CipherVaultSession, *i .r1, *i .r2, p 0, *i .r3) i .r0'
      ; ERROR_MORE_DATA: a process holds the file.
      ${If} $0 = 234
        StrCpy $CipherVaultRunning 1
      ${EndIf}
    ${EndIf}
    !insertmacro RestartManager_EndSession $CipherVaultSession
  ${EndIf}
  Pop $3
  Pop $2
  Pop $1
  Pop $0
!macroend

!macro CIPHER_VAULT_REMOVE_ELECTRON ROOT
  ; Defined here, where PRODUCTNAME exists: the setup defines it after including this file.
  ; electron-builder names the key with a UUID made from the appId. The test product of
  ; scripts/verify-tauri-migration.mjs has its own appId, so it never meets the released app. Other
  ; product names, such as the update check's, have no Electron app to remove.
  !ifndef CIPHER_VAULT_UNINSTALLER
    !if "${PRODUCTNAME}" == "CIPHER VAULT"
      ; appId com.lugep.ciphervault
      !define CIPHER_VAULT_ELECTRON_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\a50f3a62-86c2-5b2b-889c-c4080bc754f6"
    !else if "${PRODUCTNAME}" == "CIPHER VAULT Migration Test"
      ; appId io.github.termnix-it.ciphervault.migrationtest.electron
      !define CIPHER_VAULT_ELECTRON_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\8e8f7f86-9f7c-5c36-a1d0-37b3e96aae5e"
    !endif
    !define CIPHER_VAULT_UNINSTALLER "\Uninstall ${PRODUCTNAME}.exe$\""
  !endif
  !ifdef CIPHER_VAULT_ELECTRON_KEY
    ReadRegStr $CipherVaultCommand ${ROOT} "${CIPHER_VAULT_ELECTRON_KEY}" "QuietUninstallString"
    ${If} $CipherVaultCommand == ""
      ReadRegStr $CipherVaultCommand ${ROOT} "${CIPHER_VAULT_ELECTRON_KEY}" "UninstallString"
      ${If} $CipherVaultCommand != ""
        StrCpy $CipherVaultCommand "$CipherVaultCommand /S"
      ${EndIf}
    ${EndIf}
    StrCpy $CipherVaultAt ""
    ${If} $CipherVaultCommand != ""
      ${StrLoc} $CipherVaultAt $CipherVaultCommand "${CIPHER_VAULT_UNINSTALLER}" ">"
    ${EndIf}
    ${If} $CipherVaultAt != ""
      ; The command starts with the quoted uninstaller path, so the folder runs from after the quote,
      ; and the uninstaller's own arguments follow the closing quote.
      StrLen $CipherVaultArguments "${CIPHER_VAULT_UNINSTALLER}"
      IntOp $CipherVaultArguments $CipherVaultArguments + $CipherVaultAt
      StrCpy $CipherVaultArguments $CipherVaultCommand "" $CipherVaultArguments
      IntOp $CipherVaultAt $CipherVaultAt - 1
      StrCpy $CipherVaultFolder $CipherVaultCommand $CipherVaultAt 1
      ; The uninstaller deletes its whole folder. If the Electron app was installed into the vault
      ; folder or above it, the vault would go with it, so the uninstaller is not run at all.
      ; StrCmp (==) ignores case, as Windows paths do.
      StrLen $CipherVaultAt "$CipherVaultFolder\"
      StrCpy $CipherVaultVault "$APPDATA\${PRODUCTNAME}\data\" $CipherVaultAt
      ${If} $CipherVaultVault == "$CipherVaultFolder\"
        ${IfNot} ${Silent}
          MessageBox MB_ICONEXCLAMATION|MB_OK "Electron版の${PRODUCTNAME}が保管庫と同じフォルダにインストールされているため、自動ではアンインストールしません。保管庫をバックアップしてから、Windowsの設定の「アプリ」から削除してください。"
        ${EndIf}
      ${Else}
        ; Ask before the Electron app is closed; its uninstaller would close it without asking.
        ${IfNot} ${Silent}
          !insertmacro CIPHER_VAULT_CHECK_ELECTRON
          ${DoWhile} $CipherVaultRunning = 1
            MessageBox MB_ICONEXCLAMATION|MB_RETRYCANCEL "Electron版の${PRODUCTNAME}が起動しています。編集中の内容を保存して終了してから「再試行」を押してください。$\n$\n「キャンセル」を押すとインストールを中止します。" /SD IDCANCEL IDRETRY +2
            Abort
            !insertmacro CIPHER_VAULT_CHECK_ELECTRON
          ${Loop}
        ${EndIf}
        DetailPrint "Electron版の${PRODUCTNAME}をアンインストールしています。保管庫は残します。"
        ; The uninstaller treats every program running from its folder as the app and gives up while
        ; one runs, itself included, so it runs from a copy, as electron-builder's own setup does when
        ; it replaces an old version. _?= names the installed folder and makes the setup wait until
        ; the uninstaller has finished.
        InitPluginsDir
        CopyFiles /SILENT "$CipherVaultFolder\Uninstall ${PRODUCTNAME}.exe" "$PLUGINSDIR\electron-uninstaller.exe"
        ExecWait '"$PLUGINSDIR\electron-uninstaller.exe"$CipherVaultArguments _?=$CipherVaultFolder'
        Delete "$PLUGINSDIR\electron-uninstaller.exe"
        ReadRegStr $CipherVaultCommand ${ROOT} "${CIPHER_VAULT_ELECTRON_KEY}" "UninstallString"
        ${If} $CipherVaultCommand == ""
          ; Removes the folder only if the uninstaller left it empty.
          RMDir "$CipherVaultFolder"
        ${ElseIfNot} ${Silent}
          MessageBox MB_ICONEXCLAMATION|MB_OK "Electron版の${PRODUCTNAME}を自動でアンインストールできませんでした。インストールを続けたあと、Windowsの設定の「アプリ」から削除してください。保管庫は削除されません。"
        ${EndIf}
      ${EndIf}
    ${EndIf}
  !endif
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro CIPHER_VAULT_REMOVE_ELECTRON HKCU
  !insertmacro CIPHER_VAULT_REMOVE_ELECTRON HKLM
!macroend
