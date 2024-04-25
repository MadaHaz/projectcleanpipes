# ISP-Filtering
Code for detecting censorship by ISP's

This is a fork made by **Team 7** from **COMP3850 PACE**, **Macquarie University**.

## Team Members
[Adam Shah](https://github.com/MadaHaz)
[Jingyuan Chen](https://github.com/jingyuan6)
[Marc Deberardinis](https://github.com/Marco-Paul1)
[Thomas Alfonso](https://github.com/thomasalfonso)
[Samer Almasri](https://github.com/HeTheKnight)
[Jaden Poernomo](https://github.com/CAPSLOCKENJOYER)

## Project Directory Structure
```
projectcleanpipes
├── code/
│   └── CODE FILES GO HERE
├── data/
│   └── DATA USED TO GENERATE RESULTS GOES HERE
├── results/
│   └── RESULTS GENERATED ARE PLACED HERE
├── .gitignore
└── README.md
```

## How To Install
1. Open a terminal window and navigate to the base directory of the project `projectcleanpipes`.
2. Run the command `pip install requests bs4 scapy dnspython nslookup pydnsbl
` to install all dependencies.
3. Finished.

## How To Run
To run the program you must first decide if you are running it in **Data Collection** or **Data Interpret** mode.

**Data Collection Mode:**
1. Open `main.py` inside the `code` directory.
2. In the `main` function, uncomment the function, `CalculateListOfDomains()` and comment out the function `interpretResults()`.
3. `CalculateListOfDomains(INPUT, OUTPUT)` takes two values, an `INPUT` which is the list of sites you wish to scan and an `OUTPUT`, the file to store the results in.

**NOTE**
> The `INPUT` file is stored in the **data** folder.
A correct `INPUT` would be, `"../data/INPUT_FILE.txt"`.

> The `OUTPUT` file is stored in the **results** folder.
A correct `OUTPUT` would be, `"../results/OUTPUT_FILE.csv"`.

4. Open a terminal window and go into the `code` folder containing `main.py`.
5. Run the command `python main.py` and wait for the results to be compiled.

**Data Interpret Mode:**
1. Open `main.py` inside the `code` directory.
2. In the `main` function, uncomment the function, `interpretResults()` and comment out the function `CalculateListOfDomains()`.
3. The `interpretResults(interpret_files)` takes a single input, `interpret_files`, this is a list of files to be read.

**NOTE**
> The `interpret_files` value is a list of files. The value is declared in the main function.
A correct `interpret_files` would be, `['Optus_25Mar.csv','AARC_12Apr.csv']`.

4. Open a terminal window and go into the `code` folder containing `main.py`.
5. Run the command `python main.py`.
6. Results will be printed to the terminal and output to a file called `collated_results_interpreted.csv` in the `results` folder.