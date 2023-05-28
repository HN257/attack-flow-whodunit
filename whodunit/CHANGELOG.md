# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3]

### Added in version 1.0.3

* The program can now process more than a single incident report file.

### Changed in version 1.0.3

* Minor fixes to the documentation.

## [1.0.2]

### Changed in version 1.0.2

* Had forgotten to bump the version number in 1.0.1. Fixed.

* Better message syntax when reporting only a single group.

* The `-u` option can now be used on its own (i.e., no `techniques` argument
is needed then).

## [1.0.1]

### Added in version 1.0.1

* Implemented the `-d` option for support of deprecated techniques.

### Changed in version 1.0.1

* Updated the documentation to note that only the `Enterprise` matrix of the
MITRE ATT&CK framework is supported (and not the `Mobile` or `ICS` matrices).

* Minor language fixes in `README.md` and `report.txt`.

* Simplified the script a bit by not storing the set of common attacks and
just keeping the confidence number.

* Fixed a bug where a technique listed in the incident report would not be
recognized as valid, if it was not used by a known group.

* Re-arranged and optimized the code, in order to reduce the number of times
that the MITRE ATT&CK structure is traversed for groups and techniques.

## [1.0.0]

### Added in version 1.0.0

* Initial release
