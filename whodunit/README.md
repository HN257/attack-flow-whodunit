# whodunit

Recognizing the most likely APT groups responsible for an incident

## Description

This program takes a report from a cybersecurity incident containing
the MITRE ATT&CK techniques that have been detected to have been used
in the incident and tries to recognize which APT groups are the most
likely to have been responsible for the incident.

## Installation

The script depends on the `enterpriseattack` module for easy access to
the various MITRE ATT&CK techniques and groups, so you need to install
this module prior to being able to use the script. Since that module
requires Python version 3.6 or higher, this script also runs only under
such versions of Python.

1. Clone the repo:

    ```bash
    git clone https://gitlab.com/bontchev/whodunit.git
    ```

2. Go to the directory of the script:

    ```bash
    cd whodunit
    ```

3. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
python whodunit.py [-h] [-v] [-n NUMGROUPS] [-b] [-u] [-d] techniques
```

The script accepts the following command-line options:

`-h`, `--help` Displays a short explanation how to use the script and what
the command-line options are.

`-v`, `--version` Displays the version of the script and exits.

`-n NUMGROUPS`, `--numgroups NUMGROUPS` Number of closest groups to list (default: 10).

`-b`, `--verbose` Lists the MITRE ATT&CK techniques from the report.

`-u`, `--update` Updates the local copy of the MITRE ATT&CK data.

`-d`, `--deprecated` Uses the deprecated ATT&CK techniques too.

`techniques` A text file containing a list of the MITRE ATT&CK techniques
observed during the cybersecurity incident. Empty lines are ignored,
everything after a `#` character on a line is considered a comment and is
ignored. More than one technique can be listed on the same line, in which
case they should be separated by one or more white spaces.

## Example

The repository contains a (made up) report from a cybersecurity incident
in the file `report.txt`. The natural language description of what was
observed is in the comments. You can process this report with the script
like this:

```bash
python whodunit.py -u -b -n 5 report.txt
```

This will force the script to update the local copy of the MITRE ATT&CK data
(the `-u` option), to list the techniques recognized in the incident report
(the `-b` option), and to output the 5 APT groups that are the most likely
the have been responsible for the incident (the `-n 5` option):

```stdout
Processing report file "report.txt"...
Observed techniques:
T1003.001
T1005
T1039
T1059.001
T1068
T1078.003
T1110.003
T1114.001
T1133
T1213.002
T1486
T1548.002
T1560
T1562.001
T1573.002

The 5 APT groups most likely responsible:
G0007 (APT28             ):  60.00%
G0016 (APT29             ):  53.33%
G0037 (FIN6              ):  46.67%
G0060 (BRONZE BUTLER     ):  40.00%
G0114 (Chimera           ):  40.00%
```

The script works by finding the intersection of the set of techniques,
known to be used by each APT group and the set of techniques listed in
the incident report and reporting with higher confidence the groups,
for which this intersection is the largest subset of techniques listed
in the incident report.

The first column is the APT group identifier in the MITRE ATT&CK framework,
the second column is the common name for that group, and the third column
is what percentage of the techniques in the incident report are techniques,
known to be used by the corresponding APT group.

**Note**: Only the `Enterprise` matrix of the MITRE ATT&CK framework is
supported (and not, for instance, the `Mobile` or `ICS` matrices), because
this is what the `enterpriseattack` module supports.

## License

This project is licensed under the GNU v3.0 license.
