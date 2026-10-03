import pefile
import datetime


def analyze_pe(file_path):

    pe = pefile.PE(file_path)

    machine = pe.FILE_HEADER.Machine

    if machine == 0x14c:
        architecture = "32-bit"

    elif machine == 0x8664:
        architecture = "64-bit"

    else:
        architecture = "Unknown"

    compile_time = datetime.datetime.utcfromtimestamp(
        pe.FILE_HEADER.TimeDateStamp
    )

    info = {

        "Architecture": architecture,

        "Entry Point": hex(
            pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ),

        "Image Base": hex(
            pe.OPTIONAL_HEADER.ImageBase
        ),

        "Compile Time": str(compile_time),

        "Sections": len(pe.sections)

    }

    return info