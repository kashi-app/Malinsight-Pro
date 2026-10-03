from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

from datetime import datetime



def add_page_number(canvas, doc):

    page_number = canvas.getPageNumber()

    canvas.drawRightString(
        550,
        20,
        f"MalInsight Pro | Page {page_number}"
    )



def create_table(data):

    table = Table(
        data,
        repeatRows=1
    )

    table.setStyle(
        TableStyle(
            [

                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    colors.darkblue
                ),

                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),

                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0,0),
                    (-1,-1),
                    "TOP"
                )

            ]
        )
    )

    return table



def generate_report(
        output_path,
        file_info,
        hashes,
        pe_info,
        imports,
        strings,
        iocs,
        entropy,
        signature,
        risk
):


    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter
    )


    styles = getSampleStyleSheet()

    content = []



    # Title

    content.append(
        Paragraph(
            "MalInsight Pro<br/>Static Malware Analysis Report",
            styles["Title"]
        )
    )


    content.append(
        Spacer(1,20)
    )


    content.append(
        Paragraph(
            f"Generated: {datetime.now()}",
            styles["Normal"]
        )
    )


    content.append(
        Spacer(1,20)
    )



    # Risk Summary

    content.append(
        Paragraph(
            "Risk Assessment",
            styles["Heading2"]
        )
    )


    risk_data = [

        [
            "Risk Score",
            "Verdict"
        ],

        [

            str(risk.get("score")),

            risk.get("verdict")

        ]

    ]


    content.append(
        create_table(risk_data)
    )


    content.append(
        Spacer(1,20)
    )



    # File Information

    content.append(
        Paragraph(
            "File Information",
            styles["Heading2"]
        )
    )


    file_table = [

        [
            "Property",
            "Value"
        ]

    ]


    for key,value in file_info.items():

        file_table.append(
            [
                str(key),
                str(value)
            ]
        )


    content.append(
        create_table(file_table)
    )


    content.append(
        Spacer(1,20)
    )



    # Hashes

    content.append(
        Paragraph(
            "Hashes",
            styles["Heading2"]
        )
    )


    hash_table = [

        [
            "Algorithm",
            "Hash"
        ]

    ]


    for key,value in hashes.items():

        hash_table.append(
            [
                key,
                value
            ]
        )


    content.append(
        create_table(hash_table)
    )


    content.append(
        PageBreak()
    )



    # PE Information

    content.append(
        Paragraph(
            "PE Information",
            styles["Heading2"]
        )
    )


    pe_table = [

        [
            "Property",
            "Value"
        ]

    ]


    for key,value in pe_info.items():

        pe_table.append(
            [
                key,
                value
            ]
        )


    content.append(
        create_table(pe_table)
    )



    content.append(
        Spacer(1,20)
    )



    # Imports

    content.append(
        Paragraph(
            "Suspicious Imports",
            styles["Heading2"]
        )
    )


    content.append(
        create_table(
            [
                [
                    "API"
                ]
            ]
            +
            [
                [
                    api
                ]
                for api in imports.get(
                    "suspicious",
                    []
                )
            ]
        )
    )



    content.append(
        Spacer(1,20)
    )



    # Entropy

    content.append(
        Paragraph(
            "Entropy Analysis",
            styles["Heading2"]
        )
    )


    entropy_table = [

        [
            "Section",
            "Entropy"
        ]

    ]


    for section in entropy.get(
        "sections",
        []
    ):

        entropy_table.append(
            [
                section["name"],
                section["entropy"]
            ]
        )


    content.append(
        create_table(entropy_table)
    )



    content.append(
        Spacer(1,20)
    )



        # Digital Signature

    content.append(
        Paragraph(
            "Digital Signature Analysis",
            styles["Heading2"]
        )
    )


    signature_table = [

        [
            "Property",
            "Value"
        ],

        [
            "Signed",
            str(
                signature.get(
                    "signed",
                    False
                )
            )
        ],

        [
            "Publisher",
            signature.get(
                "publisher",
                "Unknown"
            )
        ],

        [
            "Trusted",
            str(
                signature.get(
                    "trusted",
                    False
                )
            )
        ],

        [
            "Windows System File",
            str(
                signature.get(
                    "system_file",
                    False
                )
            )
        ]

    ]


    content.append(
        create_table(
            signature_table
        )
    )


    content.append(
        Spacer(
            1,
            20
        )
    )



    # Recommendations

    content.append(
        Paragraph(
            "Recommendations",
            styles["Heading2"]
        )
    )


    for reason in risk.get(
        "reasons",
        []
    ):

        content.append(
            Paragraph(
                "• " + reason,
                styles["Normal"]
            )
        )


    doc.build(
        content,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )