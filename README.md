# attack-flow-whodunit
advanced topics work 

this repository contains all the work from Advanced Topics research project

**Scalable Metagraph Algorithms for Provable Network Security**

## attackflows
folder contains `.afb` and `.json` files of 40 attacks used as the database of this research project

## ml-package
folder contains machine learning (ML) code that can extract a list of techniques used in cyber-attacks out from incident reports

***run the code***
Use the command `python3 document_analysis_Hattie.py FILE_PATH_OF_REPORT`

## whodunit
folder contains `whodunit` code from https://gitlab.com/bontchev/whodunit with modified version `whodunit-Hattie.py` that is able to:
* output groups with high matching percentage
* output groups with a low number of missing techniques
* list the missing techniques
* output position of missing techniques in attack sequence of each threat actor
* output groups with low missing score

***run the code***
Use the command `python whodunit-Hattie.py [-h] [-v] [-n NUMGROUPS] [-b] [-u] [-d] FILE_PATH_OF_TECHNIQUES_LIST`
* input file must be of extension `.txt` only
* text file contains list of techniques used in attack
