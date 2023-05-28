#!/usr/bin/env python


from __future__ import print_function


__description__ = "Recognize an APT group from the techniques used"
__license__ = "GPL"
__VERSION__ = "1.0.3"
__uri__ = "https://gitlab.com/bontchev/whodunit"
__author__ = "Vesselin Bontchev"
__email__ = "vbontchev@yahoo.com"


from argparse import ArgumentParser
from heapq import nlargest
from os import access, R_OK
from os.path import isfile
from sys import argv, stderr, version_info


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
                exit()

    if verbose:
        print("Observed techniques:")
        for technique in sorted(techniques):
            print(technique)
        print()

    return techniques


def get_groups_and_techniques(attack, techniques):
    def get_techniques(groupObj):
        mergedTechsAndSubs = groupObj.techniques + groupObj.sub_techniques
        return [t.id for t in mergedTechsAndSubs]

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
        the_group["confidence"] = len(common_techniques) * 100.0 / len(techniques)
        groups.append(the_group)
    return groups, max_name


def match_groups(groups, num_groups, max_name):
    closest_groups = nlargest(num_groups, groups, key=lambda x: x["confidence"])
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
            match_groups(groups, args.numgroups, max_name)
            if multi_report:
                print()
        else:
            print('Could not open file "{}"'.format(report_file), file=stderr)


if __name__ == "__main__":
    main()
