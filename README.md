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
2. Run the command `pip install requests bs4 scapy dnspython nslookup pydnsbl customtkinter` to install all dependencies.
3. Finished.

## How To Run
**RUN GUI**
> ⚠ THE TERMINAL WINDOW MUST BE OPENED TO THE `CODE` directory!

1. For Windows & Linux, run the command `python main.py`. For MacOS, run `python3 main.py`.
2. Select either Collection or Interpret mode from the tab selector.
3. Fill in the required information and execute the mode.
4. Results are found within the `results` folder.

> For `Collection Mode`, the result is called `<ISP_NAME>.csv`.
> 
> For `Interpret Mode`, the result is called `<SITE_LIST>_CRF.csv`.

**Data Collection Mode:**
1. The progam opens in **Collection Mode**.
2. Enter in the name of the ISP being tested. (No need to include the `.csv`)

> It is reccomended to use a naming format, here is ours.
>
> `<ISPNAME>_<DAYMONTH>_<YEAR>.csv`, an example is, `AussieBroadband_10May_2024.csv`.

3. Input the file which lists the sites to be scanned.
4. Run the scan.
5. Results are found within the `results` folder.

**Data Interpret Mode:**
1. The progam opens in **Collection Mode**, switch to **Interpret Mode** by selecting it from the tabs at the top.
2. Input the file used to make the collection results, the site list file from **Data Collection Mode**, Step 4.
3. Input the results files to be interpreted.
4. Run the interpreter.
5. Results are found within the `results` folder.

> The results file will be in the following format:
>
> `<SITELIST FILENAME>_CRF.csv`
