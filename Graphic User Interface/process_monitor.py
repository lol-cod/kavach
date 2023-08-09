import sys
import psutil
import threading
import tkinter as tk
from tkinter import ttk

class ProcessMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Monitor")
        self.root.configure(bg="#FFFFE0")  # Set light yellow background color
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TButton", padding=6, background="#66BB6A")  # Green color for start button
        self.style.configure("TText", font=("Courier New", 10), background="#FFFFE0")
        
        self.start_button = ttk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(root, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)

        self.text_box = tk.Text(root, wrap=tk.WORD, height=20, width=80)
        self.text_box.pack()

        self.flag = False  # Use boolean for flag
        self.list_lolbins = [
            'AppInstaller.exe', 'Aspnet_Compiler.exe', 'At.exe',  'AppInstaller.exe', 'Aspnet_Compiler.exe', 'At.exe', 'Atbroker.exe', 'Bash.exe', 'Bitsadmin.exe', 'CertOC.exe',
    'CertReq.exe', 'Certutil.exe', 'Cmd.exe', 'Cmdkey.exe', 'cmdl32.exe', 'Cmstp.exe', 'Colorcpl.exe',
    'ConfigSecurityPolicy.exe', 'Conhost.exe', 'Control.exe', 'Csc.exe', 'Cscript.exe', 'CustomShellHost.exe',
    'DataSvcUtil.exe', 'Desktopimgdownldr.exe', 'DeviceCredentialDeployment.exe', 'Dfsvc.exe', 'Diantz.exe',
    'Diskshadow.exe', 'Dnscmd.exe', 'Esentutl.exe', 'Eventvwr.exe', 'Expand.exe', 'Explorer.exe', 'Extexport.exe',
    'Extrac32.exe', 'Findstr.exe', 'Finger.exe', 'fltMC.exe', 'Forfiles.exe', 'Ftp.exe', 'Gpscript.exe', 'Hh.exe',
    'IMEWDBLD.exe', 'Ie4uinit.exe', 'Ieexec.exe', 'Ilasm.exe', 'Infdefaultinstall.exe', 'Installutil.exe', 'Jsc.exe',
    'Ldifde.exe', 'Makecab.exe', 'Mavinject.exe', 'Microsoft.Workflow.Compiler.exe', 'Mmc.exe', 'MpCmdRun.exe',
    'Msbuild.exe', 'Msconfig.exe', 'Msdt.exe', 'Msedge.exe', 'Mshta.exe', 'Msiexec.exe', 'Netsh.exe', 'Odbcconf.exe',
    'OfflineScannerShell.exe', 'OneDriveStandaloneUpdater.exe', 'Pcalua.exe', 'Pcwrun.exe', 'Pktmon.exe',
    'Pnputil.exe', 'Presentationhost.exe', 'Print.exe', 'PrintBrm.exe', 'Provlaunch.exe', 'Psr.exe', 'Rasautou.exe',
    'rdrleakdiag.exe', 'Reg.exe', 'Regasm.exe', 'Regedit.exe', 'Regini.exe', 'Register-cimprovider.exe',
    'Regsvcs.exe', 'Regsvr32.exe', 'Replace.exe', 'Rpcping.exe', 'Rundll32.exe', 'Runexehelper.exe', 'Runonce.exe',
    'Runscripthelper.exe', 'Sc.exe', 'Schtasks.exe', 'Scriptrunner.exe', 'Setres.exe', 'SettingSyncHost.exe', 'ssh.exe',
    'Stordiag.exe', 'SyncAppvPublishingServer.exe', 'Tar.exe', 'Teams.exe', 'Ttdinject.exe', 'Tttracer.exe',
    'Unregmp2.exe', 'vbc.exe', 'Verclsid.exe', 'Wab.exe', 'winget.exe', 'Wlrmdr.exe', 'Wmic.exe', 'WorkFolders.exe',
    'Wscript.exe', 'Wsreset.exe', 'wuauclt.exe', 'Xwizard.exe', 'fsutil.exe', 'msedgewebview2.exe', 'wt.exe',
    'code.exe', 'GfxDownloadWrapper.exe', 'AccCheckConsole.exe', 'adplus.exe', 'AgentExecutor.exe', 'Appvlp.exe',
    'Bginfo.exe', 'Cdb.exe', 'coregen.exe', 'Createdump.exe', 'csi.exe', 'DefaultPack.EXE', 'Devinit.exe',
    'Devtoolslauncher.exe', 'dnx.exe', 'Dotnet.exe', 'Dump64.exe', 'DumpMinitool.exe', 'Dxcap.exe', 'Excel.exe',
    'Fsi.exe', 'FsiAnyCpu.exe', 'Mftrace.exe', 'Microsoft.NodejsTools.PressAnyKey.exe', 'Msdeploy.exe', 'MsoHtmEd.exe',
    'Mspub.exe', 'msxsl.exe', 'ntdsutil.exe', 'OpenConsole.exe', 'Powerpnt.exe', 'Procdump.exe', 'ProtocolHandler.exe',
    'rcsi.exe', 'Remote.exe', 'Sqldumper.exe', 'Sqlps.exe', 'SQLToolsPS.exe', 'Squirrel.exe', 'te.exe', 'Tracker.exe',
    'Update.exe', 'VSDiagnostics.exe', 'VSIISExeLauncher.exe', 'VisualUiaVerifyNative.exe', 'vsjitdebugger.exe',
    'Wfc.exe', 'Winword.exe', 'Wsl.exe', 'vsls-agent.exe'
        ]
        self.d_path = {
            'AppInstaller.exe': r'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.20.1881.0_x64__8wekyb3d8bbwe\AppInstaller.exe',
            'cmd.exe': r'C:\Windows\System32\cmd.exe',
            'Conhost.exe': r'C:\Windows\System32\conhost.exe',
            'AppInstaller.exe': r'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.20.1881.0_x64__8wekyb3d8bbwe\AppInstaller.exe',
    'cmd.exe': r'C:\Windows\System32\cmd.exe',
    'Conhost.exe': r'C:\Windows\System32\conhost.exe',
    'Explorer.exe': r'C:\Windows\explorer.exe',
    'msedgewebview2.exe': r'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\115.0.1901.188\msedgewebview2.exe',
    'code.exe': r'C:\Users\priya\AppData\Local\Programs\Microsoft VS Code\Code.exe',
    'Excel.exe': r'C:\Program Files\Microsoft Office\Office16\EXCEL.EXE',
    'makecab.exe': r'C:\Windows\System32\makecab.exe',
    'msconfig.exe': r'C:\Windows\System32\msconfig.exe',
    'pnputil.exe': r'C:\Windows\system32\pnputil.exe',
    'regedit.exe': r'C:\Windows\regedit.exe',
    'runexehelper.exe': r'c:\windows\system32\runexehelper.exe',
    'scriptrunner.exe': r'C:\Windows\System32\scriptrunner.exe',
    'wlrmdr.exe': r'c:\windows\system32\wlrmdr.exe',
    'wmic.exe': r'C:\Windows\System32\wbem\wmic.exe',
    'xwizard.exe': r'C:\Windows\System32\xwizard.exe',
    'advpack.dll': r'c:\windows\system32\advpack.dll',
    'ieadvpack.dll': r'c:\windows\system32\ieadvpack.dll',
    'setupapi.dll': r'c:\windows\system32\setupapi.dll',
    'winword.exe': r'C:\Program Files\Microsoft Office\root\Office16\winword.exe',
    'UtilityFunctions.ps1': r'C:\Windows\diagnostics\system\Networking\UtilityFunctions.ps1'
        }

    def start_monitoring(self):
        self.flag = True  # Set flag to True
        threading.Thread(target=self.display_new_processes).start()

    def stop_monitoring(self):
        self.flag = False  # Set flag to False

    def display_new_processes(self):
        existing_processes = set(psutil.pids())

        while self.flag:  # Check flag in the loop
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

                for list_name in self.list_lolbins:
                    if isinstance(list_name, str) and name.lower() == list_name.lower():
                        text = "{:<8} {:<{name_len}} {:<{path_len}}\n".format(
                            pid_str, name, path,
                            name_len=max_name_len, path_len=max_path_len)
                        self.text_box.insert(tk.END, text)

                        if name in self.d_path:
                            expected_path = self.d_path[name]
                            if path == expected_path:
                                path_info = "Path is matching: {}\n".format(expected_path)
                            else:
                                path_info = "WARNING: Path Mismatch! Expected Path: {}\n".format(expected_path)
                            self.text_box.insert(tk.END, path_info)

                        self.text_box.update()
                        sys.stdout.flush()

            existing_processes = current_processes

if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessMonitorGUI(root)
    root.mainloop()
