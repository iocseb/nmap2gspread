#!/usr/bin/env python3

from libnmap.parser import NmapParser
import argparse
import gspread


def get_argument_parser() -> object:
    # helper function to add command line arguments
    # TODO: define which parameters are mendatory
    
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("-xmlfile", type=str,default="", help="input XML file")
    argument_parser.add_argument("-gsheet", type=str,default="vuln-db", help="name of Google Sheet")
    argument_parser.add_argument("-mode", type=str, choices=["create", "update"],
                                 help="create a new Google Sheet or update an existing one")
    argument_parser.add_argument("-hosttype", type=str, choices=["internal", "external"], default="internal",
                                 help="internal or external scan results")
    argument_parser.add_argument("-credsfile", type=str,default="/home/seb/.config/gspread/credentials.json", help="location of credentials.json (instructions: https://docs.gspread.org/en/latest/oauth2.html)")
    argument_parser.add_argument("-authfile", type=str,default="/home/seb/.config/gspread/authorized_user.json", help="location of authorized_user.json (instructions: https://docs.gspread.org/en/latest/oauth2.html)")
    
    return argument_parser.parse_args()


def open_gspread(args) -> object:
    # reads the current content of the Google Sheet

    gc = gspread.oauth(credentials_filename=args.credsfile, authorized_user_filename=args.authfile)
    sh = gc.open(args.gsheet)

    return sh


def writeout_hosts(nreport, spreadsheet, hosttype):
    # writes hosts into Google Sheet

    if hosttype == 'internal':
        sheet = spreadsheet.worksheet("internal hosts")
    else:
        sheet = spreadsheet.                                                  worksheet("external hosts")
    
    host_id_column = sheet.col_values(1)
    row = first_free_row = len(host_id_column) + 1

    # TODO: This must be converted into a single Google Sheet API call.
    for host in nreport.hosts:
        sheet.update_cell(row, 1, str(row))
        sheet.update_cell(row, 2, str(host.hostnames))
        sheet.update_cell(row, 3, str(host.address))
        sheet.update_cell(row, 4, str(host.mac))
        sheet.update_cell(row, 5, str(host.get_open_ports()))
        sheet.update_cell(row, 6, "todo")
        sheet.update_cell(row, 7, "todo")
        sheet.update_cell(row, 8, "todo")
        sheet.update_cell(row, 9, "todo")
        sheet.update_cell(row, 10, str(nreport.summary))
        row = row + 1


if __name__ == '__main__':
    
    arguments = get_argument_parser()

    # parse nmap XML report
    nmap_report = NmapParser.parse_fromfile(arguments.xmlfile)
    print("Nmap scan summary: {0}".format(nmap_report.summary))
    print(nmap_report.hosts[0].get_open_ports())

    # open Google Sheet
    gsheet = open_gspread(arguments)

    writeout_hosts(nmap_report, gsheet, arguments.hosttype)
    
    quit()
