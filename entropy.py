import math
import pefile


def calculate_entropy(data):
    """
    Calculates Shannon entropy.
    """

    if not data:
        return 0


    frequency = {}

    for byte in data:

        if byte not in frequency:
            frequency[byte] = 0

        frequency[byte] += 1


    entropy = 0

    length = len(data)


    for count in frequency.values():

        probability = count / length

        entropy -= probability * math.log2(probability)


    return round(entropy, 2)



def analyze_entropy(file_path):

    result = {

        "file_entropy": 0,
        "sections": [],
        "average_entropy": 0,
        "packed": False

    }


    try:

        # Whole file entropy

        with open(file_path, "rb") as file:

            data = file.read()


        result["file_entropy"] = calculate_entropy(data)



        # PE section entropy

        pe = pefile.PE(file_path)

        total_entropy = 0
        section_count = 0


        for section in pe.sections:

            name = section.Name.decode(
                errors="ignore"
            ).strip("\x00")


            entropy = calculate_entropy(
                section.get_data()
            )


            result["sections"].append({

                "name": name,
                "entropy": entropy,
                "size": section.SizeOfRawData

            })


            total_entropy += entropy

            section_count += 1



            if entropy >= 7:

                result["packed"] = True



        if section_count:

            result["average_entropy"] = round(
                total_entropy / section_count,
                2
            )


        pe.close()


    except Exception as e:

        result["error"] = str(e)



    return result