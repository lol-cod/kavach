import sys
import psutil
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def display_new_processes():
    list_lolbins = ['AppInstaller.exe', 'Aspnet_Compiler.exe', 'At.exe', 'Atbroker.exe', 'Bash.exe', 'Bitsadmin.exe', 'CertOC.exe', 'CertReq.exe', 'Certutil.exe', 'Cmd.exe', 'Cmdkey.exe', 'cmdl32.exe', 'Cmstp.exe', 'Colorcpl.exe', 'ConfigSecurityPolicy.exe', 'Conhost.exe', 'Control.exe', 'Csc.exe', 'Cscript.exe', 'CustomShellHost.exe', 'DataSvcUtil.exe', 'Desktopimgdownldr.exe', 'DeviceCredentialDeployment.exe', 'Dfsvc.exe', 'Diantz.exe', 'Diskshadow.exe', 'Dnscmd.exe', 'Esentutl.exe', 'Eventvwr.exe', 'Expand.exe', 'Explorer.exe', 'Extexport.exe', 'Extrac32.exe', 'Findstr.exe', 'Finger.exe', 'fltMC.exe', 'Forfiles.exe', 'Ftp.exe', 'Gpscript.exe', 'Hh.exe', 'IMEWDBLD.exe', 'Ie4uinit.exe', 'Ieexec.exe', 'Ilasm.exe', 'Infdefaultinstall.exe', 'Installutil.exe', 'Jsc.exe', 'Ldifde.exe', 'Makecab.exe', 'Mavinject.exe', 'Microsoft.Workflow.Compiler.exe', 'Mmc.exe', 'MpCmdRun.exe', 'Msbuild.exe', 'Msconfig.exe', 'Msdt.exe', 'Msedge.exe', 'Mshta.exe', 'Msiexec.exe', 'Netsh.exe', 'Odbcconf.exe', 'OfflineScannerShell.exe', 'OneDriveStandaloneUpdater.exe', 'Pcalua.exe', 'Pcwrun.exe', 'Pktmon.exe', 'Pnputil.exe', 'Presentationhost.exe', 'Print.exe', 'PrintBrm.exe', 'Provlaunch.exe', 'Psr.exe', 'Rasautou.exe', 'rdrleakdiag.exe', 'Reg.exe', 'Regasm.exe', 'Regedit.exe', 'Regini.exe', 'Register-cimprovider.exe', 'Regsvcs.exe', 'Regsvr32.exe', 'Replace.exe', 'Rpcping.exe', 'Rundll32.exe', 'Runexehelper.exe', 'Runonce.exe', 'Runscripthelper.exe', 'Sc.exe', 'Schtasks.exe', 'Scriptrunner.exe', 'Setres.exe', 'SettingSyncHost.exe', 'ssh.exe', 'Stordiag.exe', 'SyncAppvPublishingServer.exe', 'Tar.exe', 'Teams.exe', 'Ttdinject.exe', 'Tttracer.exe', 'Unregmp2.exe', 'vbc.exe', 'Verclsid.exe', 'Wab.exe', 'winget.exe', 'Wlrmdr.exe', 'Wmic.exe', 'WorkFolders.exe', 'Wscript.exe', 'Wsreset.exe', 'wuauclt.exe', 'Xwizard.exe', 'fsutil.exe', 'msedgewebview2.exe', 'wt.exe', 'code.exe', 'GfxDownloadWrapper.exe', 'AccCheckConsole.exe', 'adplus.exe', 'AgentExecutor.exe', 'Appvlp.exe', 'Bginfo.exe', 'Cdb.exe', 'coregen.exe', 'Createdump.exe', 'csi.exe', 'DefaultPack.EXE', 'Devinit.exe', 'Devtoolslauncher.exe', 'dnx.exe', 'Dotnet.exe', 'Dump64.exe', 'DumpMinitool.exe', 'Dxcap.exe', 'Excel.exe', 'Fsi.exe', 'FsiAnyCpu.exe', 'Mftrace.exe', 'Microsoft.NodejsTools.PressAnyKey.exe', 'Msdeploy.exe', 'MsoHtmEd.exe', 'Mspub.exe', 'msxsl.exe', 'ntdsutil.exe', 'OpenConsole.exe', 'Powerpnt.exe', 'Procdump.exe', 'ProtocolHandler.exe', 'rcsi.exe', 'Remote.exe', 'Sqldumper.exe', 'Sqlps.exe', 'SQLToolsPS.exe', 'Squirrel.exe', 'te.exe', 'Tracker.exe', 'Update.exe', 'VSDiagnostics.exe', 'VSIISExeLauncher.exe', 'VisualUiaVerifyNative.exe', 'vsjitdebugger.exe', 'Wfc.exe', 'Winword.exe', 'Wsl.exe', 'vsls-agent.exe']
    existing_processes = set(psutil.pids())

    print("{:<8} {:<25} {:<40} {:<15}".format(
        "PID", "Name", "Path", "User"))
    print("-" * 128)
    sys.stdout.flush()

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

            memory_mb = process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB

            try:
                user = process.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                user = "N/A"
            
            admin_status = "Admin" if is_admin() else "Regular User"

            for list_name in list_lolbins:
                if name.lower() == list_name.lower():
                    print("{:<8} {:<{name_len}} {:<{path_len}} {:<15}".format(
                    pid_str, name, path, user,
                    name_len=max_name_len, path_len=max_path_len))
                
                    print("Running as:", admin_status)
                    sys.stdout.flush()

        existing_processes = current_processes

if __name__ == "__main__":
    display_new_processes()
