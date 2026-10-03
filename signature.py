import os
import subprocess


def check_signature(file_path):

    result = {
        "signed": False,
        "publisher": "Unknown",
        "trusted": False,
        "system_file": False
    }

    # Check if file is inside a Windows system directory
    normalized_path = os.path.abspath(file_path).lower()

    windows_dir = os.environ.get("WINDIR", r"C:\Windows").lower()

    if normalized_path.startswith(windows_dir):
        result["system_file"] = True

    try:

        command = [
            "powershell",
            "-Command",
            f"(Get-AuthenticodeSignature '{file_path}').Status"
        ]

        output = subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()

        if output == "Valid":

            result["signed"] = True
            result["trusted"] = True
            result["publisher"] = "Trusted Publisher"

    except Exception:

        pass

    return result