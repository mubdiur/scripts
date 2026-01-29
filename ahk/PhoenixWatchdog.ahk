#Requires AutoHotkey v2.0
#SingleInstance Force
Persistent

; --- CONFIGURATION AREA (CHANGE THESE) ---
; Path to your application executable
AppPath := "C:\Users\mubdiur\AppData\Local\Programs\Tabby\Tabby.exe"
; The actual process name (check Task Manager details tab)
ExeName := "Tabby.exe"
; -----------------------------------------

; Set the Tray Icon to match your target app
if FileExist(AppPath)
    TraySetIcon(AppPath)

; Setup the Tray Menu
A_TrayMenu.Delete() ; Clear standard items
A_TrayMenu.Add("Toggle " ExeName, ToggleWindow)
A_TrayMenu.Default := "Toggle " ExeName
A_TrayMenu.ClickCount := 1 ; Single click to toggle

; The Watchdog Timer (Checks every 1000ms / 1 second)
SetTimer CheckApp, 1000

CheckApp() {
    ; If the process does NOT exist...
    if !ProcessExist(ExeName) {
        try {
            ; 1. Launch the app Minimized, capture the Process ID (PID)
            Run(AppPath, , "Min", &NewPID)

            ; 2. Wait up to 5 seconds for the window to appear
            if WinWait("ahk_pid " NewPID, , 5)
            {
                ; 3. Hide it immediately so it stays in RAM but off screen
                WinHide("ahk_pid " NewPID)
            }
        }
    }
}

ToggleWindow(*) {
    ; Check if process is running
    if ProcessExist(ExeName) {
        DetectHiddenWindows true
        ; Check if the window exists
        if WinExist("ahk_exe " ExeName) {
            ; If it is currently active/visible, hide it
            if WinActive("ahk_exe " ExeName) {
                WinHide("ahk_exe " ExeName)
            }
            ; Otherwise bring it to front
            else {
                WinShow("ahk_exe " ExeName)
                WinActivate("ahk_exe " ExeName)
            }
        }
    } else {
        ; If the app isn't running, run the check immediately to spawn it
        CheckApp()
    }
}