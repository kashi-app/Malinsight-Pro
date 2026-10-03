from datetime import datetime


def calculate_risk(
    suspicious_imports,
    ioc_data,
    entropy_data,
    strings_data,
    signature_data=None
):

    score = 0
    reasons = []

    # -----------------------------------
    # 1. Suspicious APIs
    # -----------------------------------

    suspicious_count = len(
        suspicious_imports.get("suspicious", [])
    )

    categories = suspicious_imports.get(
        "categories",
        {}
    )

    if suspicious_count > 0:

        score += min(suspicious_count * 2, 25)

        reasons.append(
            f"Suspicious APIs detected: {suspicious_count}"
        )

    # -----------------------------------
    # 2. Suspicious Categories
    # -----------------------------------

    dangerous_categories = [
        "Process Injection",
        "Execution",
        "Networking",
        "Services"
    ]

    for category in dangerous_categories:

        if category in categories:

            score += 10

            reasons.append(
                f"Suspicious category detected: {category}"
            )

    # -----------------------------------
    # 3. IOC Analysis
    # -----------------------------------

    summary = ioc_data.get(
        "summary",
        {}
    )

    total_iocs = sum(
        summary.values()
    )

    if total_iocs > 0:

        score += min(
            total_iocs * 3,
            20
        )

        reasons.append(
            f"Indicators of compromise detected: {total_iocs}"
        )

    # -----------------------------------
    # 4. Entropy Analysis
    # -----------------------------------

    if entropy_data.get("packed"):

        score += 20

        reasons.append(
            "High entropy detected - possible packing or obfuscation"
        )

    # -----------------------------------
    # 5. Strings Analysis
    # -----------------------------------

    string_count = strings_data.get(
        "count",
        0
    )

    if string_count > 1000:

        score += 5

        reasons.append(
            f"Large number of printable strings detected: {string_count}"
        )

    # -----------------------------------
    # 6. Signature and Trust Analysis
    # -----------------------------------

    if signature_data:

        signed = signature_data.get(
            "signed",
            False
        )

        trusted = signature_data.get(
            "trusted",
            False
        )

        system_file = signature_data.get(
            "system_file",
            False
        )

        # Trusted Microsoft/system files receive a significant
        # risk reduction.

        if signed and trusted and system_file:

            score -= 40

            reasons.append(
                "Valid trusted digital signature detected"
            )

            reasons.append(
                "File is located in a Windows system directory"
            )

        elif signed and trusted:

            score -= 25

            reasons.append(
                "Valid trusted digital signature detected"
            )

        elif not signed:

            score += 10

            reasons.append(
                "File is not digitally signed"
            )

    # -----------------------------------
    # Score Normalization
    # -----------------------------------

    score = max(
        0,
        min(score, 100)
    )

    # -----------------------------------
    # Verdict
    # -----------------------------------

    if score <= 20:

        verdict = "SAFE"

    elif score <= 40:

        verdict = "LOW"

    elif score <= 60:

        verdict = "MEDIUM"

    elif score <= 80:

        verdict = "HIGH"

    else:

        verdict = "CRITICAL"

    return {

        "score": score,

        "verdict": verdict,

        "reasons": reasons,

        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }