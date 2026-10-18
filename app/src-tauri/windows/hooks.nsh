; LowLag installer hooks (included by Tauri's NSIS template).

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Firewall rule for LowLag"
  nsExec::Exec 'netsh advfirewall firewall delete rule name="LowLag"'
  Pop $0
  nsExec::Exec 'netsh advfirewall firewall add rule name="LowLag" dir=in action=allow program="$INSTDIR\lowlag.exe" enable=yes profile=any'
  Pop $0

  ; Moonlight keeps its settings next to itself when portable.dat exists.
  FileOpen $1 "$INSTDIR\moonlight\portable.dat" w
  FileClose $1

  ; Streaming host (Sunshine): install silently unless it is already there.
  IfFileExists "$PROGRAMFILES64\Sunshine\sunshine.exe" lowlag_sunshine_done
    DetailPrint "Installing the streaming module (Sunshine)..."
    nsExec::ExecToLog 'msiexec /i "$INSTDIR\sunshine.msi" /qn /norestart'
    Pop $0
    DetailPrint "Sunshine installer finished: $0"
  lowlag_sunshine_done:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'netsh advfirewall firewall delete rule name="LowLag"'
  Pop $0
!macroend
