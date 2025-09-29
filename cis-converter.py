#!/usr/bin/env python3

import argparse
import re
import os
import logging
import unicodedata
import fitz  # PyMuPDF library for PDF handling

class CISConverter:
    """
    A class to convert PDF documents into structured data for CSV or Excel output.
    """

    def __init__(self, args):
        self.args = args
        # Configure logging level based on user input
        logging.basicConfig(level=getattr(logging, self.args.log_level))

    # Regular expression pattern to match CIS recommendation title structure.
    # Format example:
    # 2.3.1.6 (L1)    Configure 'Accounts: Rename guest account' (Automated)
    # cisnum  (level) policy                                     (scored)
    searcher = re.compile(
        rf'^(?P<cisnum>[.\d]+) (?:\((?P<level>[\w\d]+)\) )?(?P<policy>.+) \((?P<scored>Not\ Scored|Scored|Manual|Automated)\).*?(?P<page>\d+)\s*$'
    )

    # List of unwanted text patterns in the PDF
    garbage_list = [
        '| P a g e',
        'Internal Only - General'
    ]

    # Modes representing sections in the recommendations. Used as columns in output table.
    modes = [
        'Profile Applicability',
        'Description',
        'Rationale',
        'Audit',
        'Remediation',
        'Impact',
        'Default Value',
        'References',
        'Additional Information',
        'CIS Controls'
    ]

    @staticmethod
    def build_blank():
        """
        Creates a dictionary template for storing CIS data fields.
        """
        return {
            'Benchmark': None,
            'CIS #': '',
            'Scored': '',
            'Type': '',
            'Policy': '',
            'Profile Applicability': [],
            'Description': '',
            'Rationale': '',
            'Audit': '',
            'Result': '',
            'Comments': '',
            'Remediation': '',
            'Impact': '',
            'Default Value': '',
            'References': '',
            'Additional Information': '',
            'CIS Controls': ''
        }

    def clean_page(self, page):
        """
        Cleans a page of text extracted from a PDF.

        Args:
            page (str): The page of text to clean.

        Returns:
            str: The cleaned text.
        """
        # Normalize Unicode characters and remove carriage returns
        text_page = unicodedata.normalize("NFC", page.get_text()).replace('\r', '')
        
        # Remove garbage special characters
        text_page = text_page.replace("", "")
        text_page = text_page.replace("", "")
        text_page = text_page.replace("●", "")
        text_page = re.sub(r"•( )*\n", r"•\1", text_page)

        # Remove line breaks in paragraphs (when they can be easily identified)
        text_page = re.sub(r"([^\.] )\n([a-z])", r"\1\2", text_page)
        
        # Remove garbage text
        text_page = text_page = '\n'.join([line for line in text_page.split('\n') if not any(ele in line for ele in CISConverter.garbage_list)])
        text_page = re.sub(r"\s*Page\s+\d+\s*", "\n", text_page)

        # Format CIS Control sections.
        # These sections are extracted from tables, and their format is difficult to process if it is not standardised.
        text_page = re.sub(r"Controls\s*\n?Version\s*\n?Control\s*\n?(?:IG \d )+", "", text_page)

        # Remove empty lines at the beginning of the page
        lines = text_page.split('\n')
        while lines and lines[0].strip() == '':
            lines.pop(0)
        text_page = '\n'.join(lines)
        
        return text_page

    def extract_text(self, file_path):
        """
        Extracts and cleans text from a PDF file.

        Args:
            file_path (str): The path to the PDF file.

        Returns:
            str: The extracted and formatted text.
        """
        logging.info(f'Converting {file_path} PDF to text')
        pages = []

        # Open the PDF file
        with fitz.open(file_path) as pdf:

            # Open the debug file once if the logging level is DEBUG
            debug_file = None
            if self.args.log_level == "DEBUG":
                debug_file = open(self.args.debug_file, "a")
                debug_file.write(self.debug_file_title(f"Full text extract - {file_path}"))

            try:
                for page in pdf:
                    cleaned_page = self.clean_page(page)
                    pages.append(cleaned_page)

                    # Write extracted text of the current page to the debug file
                    if debug_file:
                        debug_file.write(unicodedata.normalize("NFC", page.get_text()).replace('\r', ''))

            finally:
                if debug_file:
                    # Write formatted text extract to a debug file if logging level is DEBUG
                    debug_file.write("\n\n")
                    debug_file.write(self.debug_file_title(f"Formatted text extract - {file_path}"))
                    for i,page in enumerate(pages):
                        debug_file.write(f"-- Page {i} --\n")
                        debug_file.write(page)
                    # Ensure the debug file is properly closed
                    debug_file.close()

        return pages

    def extract_toc(self, pages):
        """
        Extracts the Table of Contents from a list of pages.

        Args:
            pages (list): A list of pages to extract the Table of Contents from.

        Returns:
            dict: A dictionary of recommendation titles and their page numbers.
        """
        toc = {}

        # Find the page number of Overview section in first table of contents page
        first_page = None
        last_page = None
        for i, page in enumerate(pages):
            if page.partition('\n')[0].lower().startswith('table of contents'):
                first_page = i
                match = re.search(r"Overview.*[^\d](\d+)\s*", page)
                if match:
                    last_page = int(match.group(1))
                    logging.debug(f'Table of Contents: p{first_page} - p{last_page}')
                    break
        else:
            logging.error(
                'The \'Table of Contents\' could not be found in the PDF.'
                f'{"Run with --log-level=DEBUG to see details." if self.args.log_level != "DEBUG" else ""}'
            )
            exit(-1)

        toc_text = '\n'.join(pages[first_page:last_page])

        toc_formatted = []
        buffer = ""

        # Ignore TOC title
        for line in toc_text.splitlines()[1:]:
            # If the line ends with a page number, it is a complete title
            if re.search(r'[^\d]\d+\s*$', line):
                # If there is a buffer, add it to the line
                if buffer:
                    line = buffer + " " + line
                    buffer = ""
                # Add the line to the list of parsed lines
                toc_formatted.append(line.strip())
            else:
                # If the line does not end with a page number, add it to the buffer
                buffer += " " + line.strip()

        # Append formatted TOC to the debug file if logging level is DEBUG.
        if self.args.log_level == "DEBUG":
            with open(self.args.debug_file, "a") as debug_file:
                debug_file.write(self.debug_file_title(f"Formatted table of contents"))
                debug_file.write('\n'.join(toc_formatted))

        # Extract the page numbers of each recommendation
        for i,line in enumerate(toc_formatted):
            match = CISConverter.searcher.match(line)
            if match:
                match_dict = match.groupdict()
                
                # Get the page number of the next table of contents entry
                next_page = None
                if i + 1 < len(toc_formatted):
                    next_line = toc_formatted[i + 1]
                    next_match = re.match(r".*?(?P<page>\d+)\s*$", next_line)
                    if next_match:
                        next_page = next_match.group('page')

                toc[match_dict['cisnum']] = {
                    "policy": match_dict['policy'],
                    "type": match_dict.get('level', ''),  # Level is optional
                    "scored": match_dict['scored'],
                    "first_page": int(match_dict['page']),
                    "next_page": int(next_page) if next_page is not None else None
                }
        
        return toc

    def parse_text(self, file_path):
        """
        Parses the text from a PDF and extracts CIS control data.

        Args:
            file_path (str): The path to the PDF file.
        """
        
        # Extracts and cleans text from a PDF file
        pages = self.extract_text(file_path)
        logging.info(f'Parsing {file_path} content')

        # Parse table of contents to get the page numbers of each recommendation
        toc = self.extract_toc(pages)

        # Writes the header row. Calls the method of the CISConverter object used to create headers adapted to the output format.
        self.write_header()

        # Browse the recommendations line by line, as the sections are identified in toc dictionary.
        for cisnum, data in toc.items():
            cur_mode = None # Current mode (section) of the recommendation

            # Start a new row of data with first elements identified in the recommendation title
            row = self.build_blank()
            row['Benchmark'] = os.path.splitext(os.path.basename(file_path))[0] # CIS file name (if several files are added to the same result file)
            row['CIS #'] = cisnum    # Recommendation number
            row['Type'] = data['type']      # Profile, if present in title
            row['Policy'] = data['policy']   # Recommendation name
            row['Scored'] = data['scored']   # Scored / Not Scored / Manual / Automated

            # Extract the text of the recommendation from the pages
            text_data = '\n'.join(pages[data['first_page']:data['next_page']])

            # Browse the recommendations line by line, as the sections are identified by single-line sub-headings.
            for line in text_data.splitlines():
                line = line.strip() + '\n' # Remove blank characters to simplify parsing

                mode_set = False
                # If the current line is the name of one of the searched recommendation sections, sets the current mode to this section
                for mode in CISConverter.modes:
                    if line.startswith(f'{mode}:'):
                        cur_mode = mode
                        mode_set = True

                # If the current line is not a new mode (aka the start of a new section)
                if not mode_set and cur_mode:
                    # Append line content to the current row's section data
                    if isinstance(row[cur_mode], str):
                        row[cur_mode] += line
                    elif isinstance(row[cur_mode], list):
                        row[cur_mode].append(line.strip())
                    else:
                        logging.critical(f'Bad type ({type(row[cur_mode])}). This should never happen.')
                        exit(-1)

            # If the "Type" has not been identified, copy "Profile Applicability" if it consists of a single line, otherwise return the value of this column.
            if row['Type'] == None:
                if len(row['Profile Applicability']) == 1:
                    row['Type'] = row['Profile Applicability'][0]
                else:
                    row['Type'] = 'See Profile Applicability'
            
            for key in row.keys():
                # If the value to be placed in a cell in the row is a list, transform it into a string.
                if isinstance(row[key], list):
                    row[key] = '\n'.join(row[key])
                
                # Remove empty lines at the beginning and end of the text in each cell of the row.
                row[key] = row[key].strip()

                # Format CIS Controls
                if key == 'CIS Controls':
                    # Replace double \n by single \n and 3 or more \n by 2 \n
                    row[key] = re.sub(r'\n\n', r'\n', row[key])
                    row[key] = re.sub(r'\n{3,}', r'\n\n', row[key])

            # Writes the row. Calls the method of the CISConverter object used to create row adapted to the output format.
            self.write_row(row)

        # All lines have been parsed (or appendix section has been reached), create the result table
        self.create_table(len(toc), file_path)
        # Print number of lines and recommendations processed (if these numbers are absurd, there is no need to open the results file to see that the parsing has not worked correctly).
        logging.info(f'Written Rows: {len(toc)}')

    def debug_file_title(self, title):
        """
        Formats a title for a section of the debug output file.

        Args:
            title (str): The title to format.

        Returns:
            str: The formatted title string.
        """
        # Print a formatted title in debug file to easily identify its two sections (full extracted text and cleaned text)
        output = '╔' + '═' * (len(title) + 4) + '╗\n'
        output += '║  ' + title + '  ║\n'
        output += '╚' + '═' * (len(title) + 4) + '╝\n'
        return output

class CISConverterCSV(CISConverter):
    """
    A subclass of CISConverter to output CSV files.
    """

    def __init__(self, args):
        super(__class__, self).__init__(args)
        import csv
        import codecs

        for file_path in self.args.input_files:
            try:
                self.output_file_path = os.path.join(self.args.output_dir, f'{os.path.splitext(os.path.basename(file_path))[0]}.csv')

                # Open the CSV output file for writing
                with open(self.output_file_path, 'wt', encoding='utf-8') as out_file:
                    # Add Byte Order Mark to define UTF-8 encoding of the CSV file
                    out_file.write(str(codecs.BOM_UTF8))

                    # Transform string input to csv.QUOTE_{csv_quoting} constant
                    quoting = getattr(csv, f'QUOTE_{args.csv_quoting}')

                    # Define columns names from recommendations sections
                    self.cw = csv.DictWriter(out_file, fieldnames=list(self.build_blank()), quoting=quoting, delimiter=args.csv_delimiter, quotechar=args.csv_quotechar, escapechar=args.csv_escapechar)
                    self.parse_text(file_path)
            except Exception as err:
                logging.error(f'An error happened while parsing {file_path}. {"Run with --log-level=DEBUG to see details." if self.args.log_level != "DEBUG" else ""}')
                logging.exception(err)

    def write_header(self):
        """
        Writes the header row to the CSV file.
        """
        self.cw.writeheader()

    def write_row(self, row):
        """
        Writes a row of data to the CSV file.

        Args:
            row (dict): The row of data to write.
        """
        self.cw.writerow(row)

    def create_table(self, line_number, file_path):
        # This method is only useful for Excel conversion
        pass

class CISConverterExcel(CISConverter):
    """
    A subclass of CISConverter to output Excel files.
    """

    def __init__(self, args):
        super(__class__, self).__init__(args)
        import xlsxwriter

        for file_path in self.args.input_files:
            try:
                self.output_file_path = os.path.join(self.args.output_dir, f'{os.path.splitext(os.path.basename(file_path))[0]}.xlsx')

                # Set the sheet name to the file name (limited to 31 characters)
                self.sheetName = os.path.splitext(os.path.basename(file_path))[0]
                self.sheetName = self.sheetName[:31]

                logging.info(f'Writing to "{self.output_file_path}"')
                self.xrow = 0
                self.xcol = 0

                # Open the Excel workbook for writing
                with xlsxwriter.Workbook(self.output_file_path) as workbook:
                    self.workbook = workbook
                    if workbook.get_worksheet_by_name("data") is None:
                        self.create_data_worksheet()
                    self.worksheet = workbook.add_worksheet(self.sheetName)
                    self.format_text = workbook.add_format({'num_format': '@'})
                    self.format_text.set_align('vcenter')
                    self.format_text.set_text_wrap()
                    self.parse_text(file_path)
            except Exception as err:
                logging.error(f'An error happened while parsing {file_path}. {"Run with --log-level=DEBUG to see details." if self.args.log_level != "DEBUG" else ""}')
                logging.exception(err)

    def create_data_worksheet(self):
        """
        Creates a worksheet named "data" with a table "Result" containing the values "OK", "KO", "N/A", "?".
        """
        data_worksheet = self.workbook.add_worksheet("data")
        data_worksheet.write_row('A1', ['Result'])
        data_worksheet.write_row('A2', ['OK'])
        data_worksheet.write_row('A3', ['KO'])
        data_worksheet.write_row('A4', ['Partial'])
        data_worksheet.write_row('A5', ['N/A'])
        data_worksheet.write_row('A6', ['?'])
        data_worksheet.add_table('A1:A6', {'name': 'Result', 'columns': [{'header': 'Result'}]})

    def write_header(self):
        """
        Writes the header row to the Excel sheet.
        """
        # Cheat and zip together the keys since write_row expects a dictionary (`dict(zip(list,list))` creates a dictionnary from list pairing each element with itself)
        # ("a","b","c") => {"a":"a","b":"b","c":"c"}
        self.write_row(dict(zip(self.build_blank().keys(), self.build_blank().keys())))

    def write_row(self, row):
        """
        Writes a row of data to the Excel sheet.

        Args:
            row (dict): The row of data to write.
        """
        for key, value in row.items():
            self.worksheet.write_string(self.xrow, self.xcol, value.strip(), self.format_text)
            self.xcol += 1
        self.xcol = 0
        self.xrow += 1
    
    def create_table(self, lines, file_path):
        """
        Creates an Excel table from the written data and adds data validation for the "Results" column.

        Args:
            lines (int): The number of lines written.
            file_path (str): The path to the input file.
        """
        headers = [{'header': h} for h in self.build_blank().keys()]
        # Calculate the column letter for the last column in the table
        def get_column_letter(col_num):
            letter = ''
            while col_num >= 0:
                letter = chr(col_num % 26 + ord('A')) + letter
                col_num = col_num // 26 - 1
            return letter

        last_col_letter = get_column_letter(len(headers) - 1)
        self.worksheet.add_table(f"A1:{last_col_letter}{lines + 1}", {'name': os.path.splitext(os.path.basename(file_path))[0], 'columns': headers})

        result_col = get_column_letter(list(self.build_blank().keys()).index('Result'))

        self.worksheet.data_validation(f'{result_col}2:{result_col}{lines + 1}', {
            'validate': 'list',
            'source': '=INDIRECT("Result[Result]")',
            'ignore_blank': True,
            'dropdown': True
        })
        self.worksheet.conditional_format(f'{result_col}2:{result_col}{lines + 1}', {
            'type': 'cell',
            'criteria': '==',
            'value': '"OK"',
            'format': self.workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100', 'bold': True})
        })
        self.worksheet.conditional_format(f'{result_col}2:{result_col}{lines + 1}', {
            'type': 'cell',
            'criteria': '==',
            'value': '"KO"',
            'format': self.workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'bold': True})
        })
        self.worksheet.conditional_format(f'{result_col}2:{result_col}{lines + 1}', {
            'type': 'cell',
            'criteria': '==',
            'value': '"Partial"',
            'format': self.workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500', 'bold': True})
        })
        self.worksheet.conditional_format(f'{result_col}2:{result_col}{lines + 1}', {
            'type': 'cell',
            'criteria': '==',
            'value': '"N/A"',
            'format': self.workbook.add_format({'bg_color': '#9CFFFB', 'font_color': '#497B79', 'bold': True})
        })
        self.worksheet.conditional_format(f'{result_col}2:{result_col}{lines + 1}', {
            'type': 'cell',
            'criteria': '==',
            'value': '"?"',
            'format': self.workbook.add_format({'bg_color': '#EAD3EA', 'font_color': '#761D6F', 'bold': True})
        })

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log-level', dest='log_level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='set the logging level (default: INFO)')
    parser.add_argument('--debug-file', dest='debug_file', default='cis-debug.txt', help='output file for TXT extract from PDF, only if --log-level=DEBUG (default: cis-debug.txt)')
    parser.add_argument('-f', '--format', dest='conversion_format', default='EXCEL', choices=['CSV', 'EXCEL'], help='set the output format (default: EXCEL)')
    parser.add_argument('-o', '--output-folder', dest='output_dir', default='./', help='path to the folder for storing files generated by the script (default: ./)')
    parser.add_argument('input_files', nargs='+', help='path to the input file(s)')

    # CSV options
    csv_group = parser.add_argument_group('CSV options')
    csv_group.add_argument('--csv-quoting', dest='csv_quoting', default='ALL', choices=['ALL', 'MINIMAL', 'NONNUMERIC', 'NONE', 'NOTNULL', 'STRINGS'], help='set the CSV quoting style (default: ALL)')
    csv_group.add_argument('--csv-delimiter', dest='csv_delimiter', default=',', help='set the CSV delimiter (default: ,)')
    csv_group.add_argument('--csv-quotechar', dest='csv_quotechar', default='"', help='set the CSV quote character (default: ")')
    csv_group.add_argument('--csv-escapechar', dest='csv_escapechar', default='\\', help='set the CSV escape character (default: \\)')

    converter = None

    args = parser.parse_args()

    # Create the output directory if it does not exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    # Choose the converter based on the requested format
    if args.conversion_format == 'CSV':
        converter = CISConverterCSV(args)
    else:
        converter = CISConverterExcel(args)
