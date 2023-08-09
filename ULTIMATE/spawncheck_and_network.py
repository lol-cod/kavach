import sys
import psutil
import socket
import threading
import csv

flag=0

# List of LOLBins
list_lolbins = [
    'AppInstaller.exe', 'Aspnet_Compiler.exe', 'At.exe', 'Atbroker.exe', 'Bash.exe', 'Bitsadmin.exe', 'CertOC.exe',
    'CertReq.exe', 'Certutil.exe', 'Cmd.exe', 'Cmdkey.exe', 'cmdl32.exe', 'Cmstp.exe', 'Colorcpl.exe',
    'ConfigSecurityPolicy.exe', 'Conhost.exe', 'Control.exe', 'Csc.exe', 'Cscript.exe', 'CustomShellHost.exe',
    'DataSvcUtil.exe', 'Desktopimgdownldr.exe', 'DeviceCredentialDeployment.exe', 'Dfsvc.exe', 'Diantz.exe',
    'Diskshadow.exe', 'Dnscmd.exe', 'Esentutl.exe', 'Eventvwr.exe', 'Expand.exe', 'Explorer.exe', 'Extexport.exe',
    'Extrac32.exe', 'Findstr.exe', 'Finger.exe', 'fltMC.exe', 'Forfiles.exe', 'Ftp.exe', 'Gpscript.exe', 'Hh.exe',
    'IMEWDBLD.exe', 'Ie4uinit.exe', 'Ieexec.exe', 'Ilasm.exe', 'Infdefaultinstall.exe', 'Installutil.exe', 'Jsc.exe',
    'Ldifde.exe', 'Makecab.exe', 'Mavinject.exe', 'Microsoft.Workflow.Compiler.exe', 'Mmc.exe', 'MpCmdRun.exe',
    'Msbuild.exe', 'Msconfig.exe', 'Msdt.exe', 'Msedge.exe', 'Mshta.exe', 'Msiexec.exe', 'ncat.exe', 'Netsh.exe', 'Odbcconf.exe',
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

# Dictionary of known paths
d_path = {
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
# Function to check if there's an internet connection
def display_new_processes():
    existing_processes = set(psutil.pids())

    print("{:<8} {:<25} {:<40} {:<15} {:<15}".format("PID", "Name", "Path", "Remote Address", "Connected"))
    print("-" * 115)

    with open("connected_processes.csv", mode="a", newline="", encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)

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

                remote_address = ""
                connected = ""

                for list_name in list_lolbins:
                    if name.lower() == list_name.lower():
                        try:
                            if name=="ncat.exe":
                                with open("connected_processes.csv", mode="a", newline="", encoding="utf-8") as csv_file:
                                    csv_writer = csv.writer(csv_file)
                                    csv_writer.writerow([pid_str, name, path, remote_address])
                                    flag=1
                            connections = process.connections()
                            if connections:
                                remote_address = f"{connections[0].laddr.ip}:{connections[0].laddr.port}"
                                connected = "No"
                            else:
                                remote_address = "N/A"
                                connected = "No"
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.TimeoutExpired):
                            pass

                        print("{:<8} {:<{name_len}} {:<{path_len}} {:<15} {:<15}".format(
                            pid_str, name, path, remote_address, connected,
                            name_len=max_name_len, path_len=max_path_len))

                        if name in d_path:
                            expected_path = d_path[name]
                            if path == expected_path:
                                print("Path is matching:", expected_path)
                            else:
                                print("WARNING: Path Mismatch! Expected Path:", expected_path)

                        sys.stdout.flush()

            existing_processes = current_processes

if __name__ == "__main__":
    threading.Thread(target=display_new_processes).start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Process monitoring stopped.")
