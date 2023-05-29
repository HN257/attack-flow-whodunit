#!/usr/bin/env python


from __future__ import print_function


__description__ = "Recognize an APT group from the techniques used"
__license__ = "GPL"
__VERSION__ = "1.0.3"
__uri__ = "https://gitlab.com/bontchev/whodunit"
__author__ = "Vesselin Bontchev"
__email__ = "vbontchev@yahoo.com"


from argparse import ArgumentParser
from heapq import nlargest, nsmallest
from os import access, R_OK
from os.path import isfile
from sys import argv, stderr, version_info
import pandas as pd #to convert excel


if version_info < (3, 6):
    print("Python 3.6 or higher required.", file=stderr)
    exit()

try:
    from enterpriseattack import Attack
except ImportError:
    print(
        'Could not import module "enterpriseattack"; try "pip install enterpriseattack".',
        file=stderr,
    )
    exit()


def get_options():
    parser = ArgumentParser(description=__description__)
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s version {}".format(__VERSION__),
    )
    parser.add_argument(
        "-n",
        "--numgroups",
        type=int,
        default=10,
        help="Number of closest groups to list (default: %(default)s)",
    )
    parser.add_argument(
        "-b", "--verbose", action="store_true", help="Verbose operation"
    )
    parser.add_argument(
        "-u", "--update", action="store_true", help="Update the MITRE ATT&CK data"
    )
    parser.add_argument(
        "-d",
        "--deprecated",
        action="store_true",
        help="Don't ignore the deprecated techniques",
    )
    parser.add_argument(
        "techniques",
        nargs="*" if "-u" in argv or "--update" in argv else "+",
        help="File containing a list of observed techniques",
    )
    return parser.parse_args()

# original code only reads .txt file
def read_report(report_file, all_techniques, verbose):
    print('Processing report file "{}"...'.format(report_file))
    with open(report_file, encoding="utf-8") as f:
        data = f.readlines()

    techniques = set()
    for line in data:
        line = line.strip()
        pos = line.find("#")
        if pos >= 0:
            line = line[:pos].strip()
        tids = line.split()
        for tid in tids:
            tid = tid.upper()
            if tid in all_techniques:
                techniques.add(tid)
            else:
                print('Unrecognized technique: "{}".'.format(tid), file=stderr)
                continue # ignore 'no technique number' error
                exit()

    if verbose:
        print("Observed techniques:")
        for technique in sorted(techniques):
            print(technique)
        print()

    return techniques

def get_groups_and_techniques(attack, techniques):
    def get_techniques(groupObj):
        # merge techniques with sub-techniques
        mergedTechsAndSubs = groupObj.techniques + groupObj.sub_techniques
        # save as a list of technique IDs
        techIDs = [t.id for t in mergedTechsAndSubs]
        # declare a list to extract parent techniques of sub-techniques e.g., grab 1566 from 1566.001
        parent_techniques = []

        # loop through sub_techniques for parent extraction
        for p in groupObj.sub_techniques:
            # split sub-techniques string on "."
            parent = p.id.split(".")
            # remove sub element
            del(parent[1])
            # append parent to declared
            parent_techniques += parent
        
        # append duplicates-removed list of parent techniques to techIDs
        techIDs += set(parent_techniques)
        return techIDs

    groups = []
    max_name = 0
    for group in attack.groups:
        the_group = {}
        the_group["name"] = group.name
        if len(group.name) > max_name:
            max_name = len(group.name)
        the_group["id"] = group.id
        the_techniques = set(get_techniques(group))
        the_group["techniques"] = the_techniques
        common_techniques = the_techniques.intersection(techniques)
        missing = techniques.difference(the_techniques)
        the_group["confidence"] = len(common_techniques) * 100.0 / len(techniques)
        the_group["number of missing techniques"] = len(missing)
        the_group["missing techniques"] = techniques.difference(the_techniques)
        groups.append(the_group)
    return groups, max_name


def match_groups(groups, num_groups, max_name, techniques):
    closest_groups = nlargest(num_groups, groups, key=lambda x: x["confidence"])
    # get groups with least number of unmatched techniques
    least_missing_techniques_groups = nsmallest(num_groups, groups, key=lambda x: x["number of missing techniques"])
    # for each APT group in groups database
    for APT in groups: 
        # keep a sum of positions of missing techniques
        missing_score = 0
        print("Position of missing technique in attack sequence of threat actor {}".format(APT["name"]))
        # for each missing technique of the APT group
        for technique in APT["missing techniques"]: 
            # convert techniques set to list then sort
            sorted_techniques = sorted(list(techniques))
            # find index of the missing technique in attack techniques list
            pos = sorted_techniques.index(technique) 
            print(
                "{:<{width}} @ {:<{pos_width}} / {}".format(
                technique, pos+1, len(techniques), width=10, pos_width=2))
            # add to sum
            missing_score += (pos+1)
        # work out the missing score - divide by the number of techniques
        missing_score /= len(techniques)
        # save missing score to threat actor key
        APT["missing score"] = missing_score
        print()

    # original
    if num_groups > 1:
        print("The {} APT groups".format(num_groups), end="")
    else:
        print("The APT group", end="")
    print(" most likely responsible:")
    for group in sorted(closest_groups, key=lambda x: (-x["confidence"], x["id"])):
        print(
            "{} ({:<{width}}): {:>6.2f}%".format(
                group["id"], group["name"], group["confidence"], width=max_name
            )
        )
    print()
    
    # check the number of unmatched techniques
    if num_groups > 1:
        print("The {} APT groups".format(num_groups), end="")
    else:
        print("The APT group", end="")
    print(" with the least missing techniques number:")
    for group in sorted(least_missing_techniques_groups, key=lambda x: (x["number of missing techniques"], x["id"])):
        print(
            "{} ({:<{width}}): {:>6d} ({})".format(
                group["id"], group["name"], group["number of missing techniques"], group["missing techniques"], width=max_name
            )
        )
    print()

    # print missing score of unmatched techniques
    if num_groups > 1:
        print("Missing score of the {} APT groups:".format(num_groups), end="")
    else:
        print("Missing score of the APT group:", end="")
    print()
    for group in sorted(least_missing_techniques_groups, key=lambda x: (x["number of missing techniques"], x["id"])):
        print(
            "{} ({:<{width}}): {:.2f}".format(
                group["id"], group["name"], group["missing score"], width=max_name
            )
        )


def main():
    args = get_options()
    attack = Attack(include_deprecated=args.deprecated, update=args.update)
    if len(args.techniques) == 0:
        exit()
    multi_report = len(args.techniques) > 1
    all_techniques = [
        x.id for x in list(attack.techniques) + list(attack.sub_techniques)
    ]
    for report_file in args.techniques:
        if isfile(report_file) and access(report_file, R_OK):
            techniques = read_report(report_file, all_techniques, args.verbose)
            groups, max_name = get_groups_and_techniques(attack, techniques)
            match_groups(groups, args.numgroups, max_name, techniques)
            if multi_report:
                print()
        else:
            print('Could not open file "{}"'.format(report_file), file=stderr)


if __name__ == "__main__":
    main()
