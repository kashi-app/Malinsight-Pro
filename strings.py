import re


MIN_LENGTH = 5


def extract_strings(file_path, min_length=MIN_LENGTH):
    """
    Extract printable ASCII strings from a binary file.
    """

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Printable ASCII characters (space to ~)
        pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"

        matches = re.findall(pattern, data)

        strings = sorted(set(s.decode(errors="ignore") for s in matches))

        return {
            "count": len(strings),
            "strings": strings
        }

    except Exception as e:
        return {
            "count": 0,
            "strings": [],
            "error": str(e)
        }