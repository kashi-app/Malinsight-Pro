import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import subprocess

from signature import check_signature
from hash_analyzer import calculate_hashes
from analyzer import analyze_pe
from imports import analyze_imports
from strings import extract_strings
from ioc import extract_iocs
from entropy import analyze_entropy
from risk import calculate_risk
from report import generate_report



class MalInsightGUI:


    def __init__(self):

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")


        self.window = ctk.CTk()

        self.window.title(
            "MalInsight Pro - Professional Malware Static Analysis Tool"
        )

        self.window.geometry(
            "1400x850"
        )

        self.window.minsize(
            1200,
            700
        )


        self.current_file = None

        self.analysis_data = {}



        self.create_layout()



    def create_layout(self):


        # Main container

        self.window.grid_columnconfigure(
            1,
            weight=1
        )

        self.window.grid_rowconfigure(
            0,
            weight=1
        )



        # Sidebar

        self.sidebar = ctk.CTkFrame(
            self.window,
            width=220,
            corner_radius=0
        )

        self.sidebar.grid(
            row=0,
            column=0,
            sticky="nsew"
        )


        self.logo = ctk.CTkLabel(
            self.sidebar,
            text="MalInsight Pro",
            font=ctk.CTkFont(
                size=24,
                weight="bold"
            )
        )

        self.logo.pack(
            pady=30
        )


        self.subtitle = ctk.CTkLabel(
            self.sidebar,
            text="Static Malware\nAnalysis Platform",
            font=ctk.CTkFont(
                size=13
            )
        )

        self.subtitle.pack(
            pady=10
        )



        self.browse_button = ctk.CTkButton(
            self.sidebar,
            text="Select PE File",
            command=self.select_file
        )

        self.browse_button.pack(
            padx=20,
            pady=20
        )



        self.analyze_button = ctk.CTkButton(
            self.sidebar,
            text="Analyze File",
            command=self.run_analysis
        )

        self.analyze_button.pack(
            padx=20,
            pady=10
        )



        self.report_button = ctk.CTkButton(
            self.sidebar,
            text="Export Report",
            command=self.export_report
        )

        self.report_button.pack(
            padx=20,
            pady=10
        )



        # Main area

        self.main_frame = ctk.CTkFrame(
            self.window
        )

        self.main_frame.grid(
            row=0,
            column=1,
            padx=20,
            pady=20,
            sticky="nsew"
        )


        self.main_frame.grid_columnconfigure(
            0,
            weight=1
        )

        self.main_frame.grid_rowconfigure(
            2,
            weight=1
        )



        # Header

        self.header = ctk.CTkLabel(
            self.main_frame,
            text="Malware Static Analysis Dashboard",
            font=ctk.CTkFont(
                size=26,
                weight="bold"
            )
        )

        self.header.grid(
            row=0,
            column=0,
            pady=20
        )



        # Status

        self.status = ctk.CTkLabel(
            self.main_frame,
            text="Ready",
            font=ctk.CTkFont(
                size=14
            )
        )

        self.status.grid(
            row=1,
            column=0,
            pady=10
        )



    def create_dashboard(self):


          self.dashboard = ctk.CTkFrame(
        self.main_frame
    )

          self.dashboard.grid(
        row=2,
        column=0,
        sticky="nsew",
        padx=10,
        pady=10
    )


          self.dashboard.grid_columnconfigure(
        (0, 1, 2, 3, 4),
        weight=1
    )


          self.file_card = self.create_card(
        "File",
        "No File",
        0
    )


          self.arch_card = self.create_card(
        "Architecture",
        "-",
        1
    )


          self.risk_card = self.create_card(
        "Risk",
        "-",
        2
    )


          self.score_card = self.create_card(
        "Score",
        "-",
        3
    )


          self.trust_card = self.create_card(
        "Trust",
        "-",
        4
    )



    def create_card(
            self,
            title,
            value,
            column
    ):


        card = ctk.CTkFrame(
            self.dashboard,
            width=200,
            height=120
        )


        card.grid(
            row=0,
            column=column,
            padx=10,
            pady=10,
            sticky="nsew"
        )


        label = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(
                size=15,
                weight="bold"
            )
        )

        label.pack(
            pady=10
        )


        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(
                size=18
            )
        )

        value_label.pack()


        return value_label



    def create_tabs(self):


        self.tabs = ctk.CTkTabview(
            self.main_frame
        )

        self.tabs.grid(
            row=3,
            column=0,
            sticky="nsew",
            padx=10,
            pady=10
        )


        tab_names = [

            "File Info",
            "PE Info",
            "Imports",
            "Strings",
            "IOCs",
            "Entropy",
            "Signature",
            "Risk",
            "Report"

        ]


        for tab in tab_names:

            self.tabs.add(tab)



        self.textboxes = {}


        for tab in tab_names:


            box = ctk.CTkTextbox(
                self.tabs.tab(tab),
                wrap="word"
            )

            box.pack(
                fill="both",
                expand=True,
                padx=10,
                pady=10
            )


            self.textboxes[tab] = box




    def select_file(self):


        file = filedialog.askopenfilename(

            title="Select Windows PE File",

            filetypes=[
                (
                    "Executable Files",
                    "*.exe;*.dll"
                )
            ]

        )


        if file:


            self.current_file = file


            self.status.configure(
                text=f"Selected: {os.path.basename(file)}"
            )



    def run_analysis(self):


        if not self.current_file:


            messagebox.showwarning(
                "No File",
                "Please select a PE file first."
            )

            return



        self.status.configure(
            text="Analyzing..."
        )


        file = self.current_file



        hashes = calculate_hashes(file)

        pe = analyze_pe(file)

        imports = analyze_imports(file)

        strings = extract_strings(file)

        iocs = extract_iocs(
            strings["strings"]
        )

        entropy = analyze_entropy(file)

        signature_data = check_signature(file)



        risk = calculate_risk(

            imports,

            iocs,

            entropy,

            strings,

            signature_data

        )



        self.analysis_data = {


            "file": file,

            "hashes": hashes,

            "pe": pe,

            "imports": imports,

            "strings": strings,

            "iocs": iocs,

            "entropy": entropy,

            "signature": signature_data,

            "risk": risk

        }



        self.update_dashboard()


        self.status.configure(
            text="Analysis Completed"
        )



    def update_dashboard(self):


        data = self.analysis_data


        self.file_card.configure(
            text=os.path.basename(
                data["file"]
            )
        )


        self.arch_card.configure(
            text=data["pe"].get(
                "Architecture",
                "-"
            )
        )


        verdict = data["risk"].get(
            "verdict",
            "-"
        )


        self.risk_card.configure(
            text=verdict
        )


        risk_colors = {

            "SAFE": "#2ECC71",

            "LOW": "#F1C40F",

            "MEDIUM": "#E67E22",

            "HIGH": "#E74C3C",

            "CRITICAL": "#8E0000"

        }


        risk_color = risk_colors.get(
            verdict,
            "#808080"
        )


        self.risk_card.configure(
            text_color=risk_color
        )


        self.score_card.configure(
            text=str(
                data["risk"].get(
                    "score",
                    0
                )
            )
        )


        signature = data.get(
            "signature",
            {}
        )


        if signature.get(
            "trusted",
            False
        ):

            trust_status = "TRUSTED"

        else:

            trust_status = "UNTRUSTED"


        self.trust_card.configure(
            text=trust_status
        )



        # File Information

        self.fill_text(
            "File Info",
            data["hashes"]
        )


        # PE Information

        self.fill_text(
            "PE Info",
            data["pe"]
        )


        # Imports

        self.fill_text(
            "Imports",
            data["imports"]
        )


        # Strings

        self.fill_text(
            "Strings",
            data["strings"]
        )


        # IOC

        self.fill_text(
            "IOCs",
            data["iocs"]
        )


        # Entropy

        self.fill_text(
            "Entropy",
            data["entropy"]
        )


        #Sinature

        self.fill_text(
    "Signature",
    data["signature"]
)


        # Risk

        self.fill_text(
            "Risk",
            data["risk"]
        )



        self.fill_text(
            "Report",
            {
                "Status":
                "Ready for export"
            }
        )



    def fill_text(
            self,
            tab,
            content
    ):


        textbox = self.textboxes[tab]


        textbox.delete(
            "1.0",
            "end"
        )


        textbox.insert(
            "end",
            str(content)
        )



    def export_report(self):


        if not self.analysis_data:


            messagebox.showwarning(
                "No Analysis",
                "Analyze a file first."
            )

            return



        save_path = filedialog.asksaveasfilename(

            defaultextension=".pdf",

            filetypes=[
                (
                    "PDF Report",
                    "*.pdf"
                )
            ]

        )


        if save_path:


            data = self.analysis_data


            generate_report(

                save_path,

                {
                    "Filename":
                    os.path.basename(
                        data["file"]
                    )
                },

                data["hashes"],

                data["pe"],

                data["imports"],

                data["strings"],

                data["iocs"],

                data["entropy"],

                data["signature"],

                data["risk"]

            )


            messagebox.showinfo(

                "Report Created",

                "PDF report generated successfully."

            )



    def run(self):

        self.create_dashboard()

        self.create_tabs()


        self.window.mainloop()