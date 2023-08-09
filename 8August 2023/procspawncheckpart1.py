import sys
import psutil
import ctypes
import tkinter as tk
import threading

# Function to check if the script is running with admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to display a warning message
def show_warning_message():
    popup = tk.Toplevel()
    popup.title("Warning")
    popup.configure(bg="red")
    
    message = "Suspicious Activity Detected!"
    label = tk.Label(popup, text=message, fg="black", bg="red")
    label.pack(padx=80, pady=20)
    
    warning_label = tk.Label(popup, text="⚠️", font=("Arial", 40), fg="black", bg="red")
    warning_label.pack()
    
    close_button = tk.Button(popup, text="OK", command=popup.destroy)
    close_button.pack(pady=25)

# List of LOLBins
list_lolbins = ['AppInstaller.exe', 'Aspnet_Compiler.exe', 'At.exe', 'Atbroker.exe', 'Bash.exe', 'Bitsadmin.exe', 'CertOC.exe', 'CertReq.exe', 'Certutil.exe', 'Cmd.exe', 'Cmdkey.exe', 'cmdl32.exe', 'Cmstp.exe', 'Colorcpl.exe', 'ConfigSecurityPolicy.exe', 'Conhost.exe', 'Control.exe', 'Csc.exe', 'Cscript.exe', 'CustomShellHost.exe', 'DataSvcUtil.exe', 'Desktopimgdownldr.exe', 'DeviceCredentialDeployment.exe', 'Dfsvc.exe', 'Diantz.exe', 'Diskshadow.exe', 'Dnscmd.exe', 'Esentutl.exe', 'Eventvwr.exe', 'Expand.exe', 'Explorer.exe', 'Extexport.exe', 'Extrac32.exe', 'Findstr.exe', 'Finger.exe', 'fltMC.exe', 'Forfiles.exe', 'Ftp.exe', 'Gpscript.exe', 'Hh.exe', 'IMEWDBLD.exe', 'Ie4uinit.exe', 'Ieexec.exe', 'Ilasm.exe', 'Infdefaultinstall.exe', 'Installutil.exe', 'Jsc.exe', 'Ldifde.exe', 'Makecab.exe', 'Mavinject.exe', 'Microsoft.Workflow.Compiler.exe', 'Mmc.exe', 'MpCmdRun.exe', 'Msbuild.exe', 'Msconfig.exe', 'Msdt.exe', 'Msedge.exe', 'Mshta.exe', 'Msiexec.exe', 'Netsh.exe', 'Odbcconf.exe', 'OfflineScannerShell.exe', 'OneDriveStandaloneUpdater.exe', 'Pcalua.exe', 'Pcwrun.exe', 'Pktmon.exe', 'Pnputil.exe', 'Presentationhost.exe', 'Print.exe', 'PrintBrm.exe', 'Provlaunch.exe', 'Psr.exe', 'Rasautou.exe', 'rdrleakdiag.exe', 'Reg.exe', 'Regasm.exe', 'Regedit.exe', 'Regini.exe', 'Register-cimprovider.exe', 'Regsvcs.exe', 'Regsvr32.exe', 'Replace.exe', 'Rpcping.exe', 'Rundll32.exe', 'Runexehelper.exe', 'Runonce.exe', 'Runscripthelper.exe', 'Sc.exe', 'Schtasks.exe', 'Scriptrunner.exe', 'Setres.exe', 'SettingSyncHost.exe', 'ssh.exe', 'Stordiag.exe', 'SyncAppvPublishingServer.exe', 'Tar.exe', 'Teams.exe', 'Ttdinject.exe', 'Tttracer.exe', 'Unregmp2.exe', 'vbc.exe', 'Verclsid.exe', 'Wab.exe', 'winget.exe', 'Wlrmdr.exe', 'Wmic.exe', 'WorkFolders.exe', 'Wscript.exe', 'Wsreset.exe', 'wuauclt.exe', 'Xwizard.exe', 'fsutil.exe', 'msedgewebview2.exe', 'wt.exe', 'code.exe', 'GfxDownloadWrapper.exe', 'AccCheckConsole.exe', 'adplus.exe', 'AgentExecutor.exe', 'Appvlp.exe', 'Bginfo.exe', 'Cdb.exe', 'coregen.exe', 'Createdump.exe', 'csi.exe', 'DefaultPack.EXE', 'Devinit.exe', 'Devtoolslauncher.exe', 'dnx.exe', 'Dotnet.exe', 'Dump64.exe', 'DumpMinitool.exe', 'Dxcap.exe', 'Excel.exe', 'Fsi.exe', 'FsiAnyCpu.exe', 'Mftrace.exe', 'Microsoft.NodejsTools.PressAnyKey.exe', 'Msdeploy.exe', 'MsoHtmEd.exe', 'Mspub.exe', 'msxsl.exe', 'ntdsutil.exe', 'OpenConsole.exe', 'Powerpnt.exe', 'Procdump.exe', 'ProtocolHandler.exe', 'rcsi.exe', 'Remote.exe', 'Sqldumper.exe', 'Sqlps.exe', 'SQLToolsPS.exe', 'Squirrel.exe', 'te.exe', 'Tracker.exe', 'Update.exe', 'VSDiagnostics.exe', 'VSIISExeLauncher.exe', 'VisualUiaVerifyNative.exe', 'vsjitdebugger.exe', 'Wfc.exe', 'Winword.exe', 'Wsl.exe', 'vsls-agent.exe']

# Dictionary of known paths
d_path={'AppInstaller.exe':'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.20.1881.0_x64__8wekyb3d8bbwe\AppInstaller.exe', 'cmd.exe':'C:\Windows\System321\cmd.exe', 'Conhost.exe':'C:\Windows\System32\conhost.exe', 'Explorer.exe':'C:\Windows\explorer.exe', 'msedgewebview2.exe':'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.188\msedgewebview2.exe', 'Excel.exe':'C:\Program Files\Microsoft Office\Office16\EXCEL.EXE', 'makecab.exe':'C:\Windows\System32\makecab.exe', 'msconfig.exe':'C:\Windows\System32\msconfig.exe', 'pnputil.exe':'C:\Windows\system32\pnputil.exe', 'regedit.exe':'C:\Windows\regedit.exe', 'runexehelper.exe':'c:\windows\system32\runexehelper.exe', 'scriptrunner.exe':'C:\Windows\System32\scriptrunner.exe', 'wlrmdr.exe':'c:\windows\system32\wlrmdr.exe', 'wmic.exe':'C:\Windows\System32\wbem\wmic.exe', 'advpack.dll':'c:\windows\system32\advpack.dll', 'ieadvpack.dll':'c:\windows\system32\ieadvpack.dll', 'setupapi.dll':'c:\windows\system32\setupapi.dll', 'winword.exe':'C:\Program Files\Microsoft Office\root\Office16\winword.exe', 'UtilityFunctions.ps1':'C:\\Windows\\diagnostics\\system\\Networking\\UtilityFunctions.ps1'}


# Function to display new processes and check for LOLBins
def display_new_processes():
    existing_processes = set(psutil.pids())

    print("{:<8} {:<25} {:<40} {:<15}".format("PID", "Name", "Path", "User"))
    print("-" * 128)

    while True:
        current_processes = set(psutil.pids())
        new_processes = current_processes - existing_processes

        max_name_len = max_path_len = 25
        for pid in new_processes:
            process = psutil.Process(pid)
            name_len = len(process.name())
            path_len = len(process.exe())
            max_name_len = max(max_name_len, name_len)
            max_path_len = max(max_path_len, path_len)

        for pid in new_processes:
            process = psutil.Process(pid)

            pid_str = str(process.pid)
            name = process.name()
            path = process.exe()

            try:
                user = process.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                user = "N/A"

            for list_name in list_lolbins:
                if name.lower() == list_name.lower():
                    print("{:<8} {:<{name_len}} {:<{path_len}} {:<15}".format(
                        pid_str, name, path, user,
                        name_len=max_name_len, path_len=max_path_len))

                    if name in d_path:
                        expected_path = d_path[name]
                        if path == expected_path:
                            print("Path is matching:", expected_path)
                        else:
                            print("WARNING: Path Mismatch! Expected Path:", expected_path)

                            # Show the warning message in a separate thread
                            threading.Thread(target=show_warning_message).start()

                    sys.stdout.flush()

        existing_processes = current_processes

if __name__ == "__main__":
    # Start the process monitoring loop in a separate thread
    threading.Thread(target=display_new_processes).start()

    # Create the main tkinter window
    root = tk.Tk()
    root.title("Main Window")

    # Button to trigger the warning message
    warning_button = tk.Button(root, text="Show Warning", command=show_warning_message)
    warning_button.pack(pady=50)

    # Start the main event loop
    root.mainloop()
