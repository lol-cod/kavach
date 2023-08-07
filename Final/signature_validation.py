import subprocess
import psutil

def get_signer_information(process_id):
    try:
        process = psutil.Process(process_id)
        process_exe = process.exe()

        if not process_exe:
            print("Process executable path not available.")
            return

        # Use PowerShell to retrieve signer information
        powershell_script = (
            f"Get-AuthenticodeSignature -FilePath '{process_exe}' | "
            "Select-Object -ExpandProperty SignerCertificate | "
            "Format-List"
        )
        
        cmd = ["powershell", "-Command", powershell_script]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Error while retrieving signer information:")
            print(result.stderr)

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print("Unable to retrieve signer information.")

if __name__ == "__main__":
    try:
        process_id = int(input("Enter the PID of the process you want to examine: "))
        get_signer_information(process_id)
    except ValueError:
        print("Invalid input. Please enter a valid numeric PID.")
