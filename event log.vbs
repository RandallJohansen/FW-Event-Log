
Set oShell = CreateObject("Shell.Application")  

oShell.ShellExecute "powershell", "-executionpolicy bypass -NoExit -NonInteractive -file " & chr(34) & "C:\Users\admin\Desktop\ps\- Prod -\event log V4.ps1" & chr(34) & " -blocked -allowed -inbound -outbound" , "", "runas", 1  


REM   When a script is run with elevated permissions several aspects of the user environment may change: The current directory, the current TEMP folder and any mapped drives will be disconnected.  
REM  
REM  "runas" will fail if you are running in WOW64 (a 32 bit process on 64 bit windows) for example %systemroot%\syswow64\cmd.exe ... 
REM  
REM     application   The file to execute (required)
REM     parameters    Arguments for the executable
REM     dir           Working directory
REM     verb          The operation to execute (runas/open/edit/print)
REM     window        View mode application window (normal=1, hide=0, 2=Min, 3=max, 4=restore, 5=current, 7=min/inactive, 10=default)
REM  
REM  
REM   .ShellExecute "application", "parameters", "dir", "verb", window
REM  
REM   .ShellExecute 'some program.exe', '"some parameters with spaces"', , "runas", 1
REM  
REM        ' comment
REM        command ' comment
REM  
REM        REM comment


