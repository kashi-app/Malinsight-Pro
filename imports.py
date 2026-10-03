import pefile
import re


# Suspicious API detection database
SUSPICIOUS_PATTERNS = {

    "Process Injection": [
        r"VirtualAlloc",
        r"VirtualProtect",
        r"WriteProcessMemory",
        r"ReadProcessMemory",
        r"CreateRemoteThread",
        r"OpenProcess",
        r"NtQueryInformationProcess",
        r"MapViewOfFile",
        r"QueueUserAPC"
    ],

    "Execution": [
        r"CreateProcess",
        r"WinExec",
        r"ShellExecute",
        r"LoadLibrary",
        r"LoadLibraryEx",
        r"GetProcAddress"
    ],

    "Networking": [
        r"InternetOpen",
        r"InternetConnect",
        r"URLDownloadToFile",
        r"HttpSendRequest",
        r"socket",
        r"connect",
        r"recv",
        r"send",
        r"WSAStartup"
    ],

    "Registry": [
        r"RegOpenKey",
        r"RegCreateKey",
        r"RegSetValue",
        r"RegDeleteKey"
    ],

    "Cryptography": [
        r"CryptEncrypt",
        r"CryptDecrypt",
        r"CryptAcquireContext"
    ],

    "Services": [
        r"CreateService",
        r"OpenSCManager",
        r"StartService"
    ]
}


def match_suspicious_api(api_name):
    """
    Checks API against suspicious patterns.
    Supports API variants like:
    VirtualAllocEx
    CreateProcessAsUserW
    RegOpenKeyExW
    """

    detected = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, api_name, re.IGNORECASE):
                detected.append(category)
                break

    return detected



def analyze_imports(file_path):

    result = {

        "dlls": [],
        "imports": [],
        "suspicious": [],
        "categories": {}

    }


    try:

        pe = pefile.PE(file_path)


        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return result


        for entry in pe.DIRECTORY_ENTRY_IMPORT:

            try:
                dll_name = entry.dll.decode(errors="ignore")

            except:
                dll_name = str(entry.dll)


            result["dlls"].append(dll_name)


            for imp in entry.imports:

                if imp.name:

                    api = imp.name.decode(errors="ignore")

                else:

                    api = f"Ordinal_{imp.ordinal}"


                result["imports"].append(api)


                categories = match_suspicious_api(api)


                if categories:

                    result["suspicious"].append(api)


                    for category in categories:

                        if category not in result["categories"]:

                            result["categories"][category] = []


                        if api not in result["categories"][category]:

                            result["categories"][category].append(api)


        pe.close()


    except Exception as e:

        result["error"] = str(e)


    return result