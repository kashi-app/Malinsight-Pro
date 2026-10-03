from signature import check_signature
from hash_analyzer import calculate_hashes
from analyzer import analyze_pe
from imports import analyze_imports
from strings import extract_strings
from ioc import extract_iocs
from entropy import analyze_entropy
from risk import calculate_risk


sample = r"C:\Windows\System32\notepad.exe"


signature_info = check_signature(sample)

print("\n=== SIGNATURE ===")
print(signature_info)
print("\n=== HASH ===")
hashes = calculate_hashes(sample)
print(hashes)


print("\n=== PE INFO ===")
pe = analyze_pe(sample)
print(pe)


print("\n=== IMPORTS ===")
imports = analyze_imports(sample)
print(imports)


print("\n=== STRINGS ===")
strings = extract_strings(sample)
print(strings["count"])


print("\n=== IOC ===")
iocs = extract_iocs(strings["strings"])
print(iocs)


print("\n=== ENTROPY ===")
entropy = analyze_entropy(sample)
print(entropy)


signature_data = check_signature(sample)

print("\n=== SIGNATURE ===")
print(signature_data)

print("\n=== RISK ===")

risk = calculate_risk(
    imports,
    iocs,
    entropy,
    strings,
    signature_data


)

print(risk)