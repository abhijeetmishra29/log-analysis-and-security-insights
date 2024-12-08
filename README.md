
# Log Analysis Script

This repository contains the solution for a Python assignment to analyze log files, demonstrating proficiency in file handling, string manipulation, and data analysis, which are essential for cybersecurity programming tasks.

---

## Table of Contents
1. [Objective](#objective)
2. [Features](#features)
3. [Installation](#installation)
4. [File Structure](#file-structure)
5. [Requirements](#requirements)
6. [Setup](#setup)
7. [Results](#results)
8. [Usage](#usage)
9. [Output Details](#output-details)
10. [Evaluation Criteria](#evaluation-criteria)
11. [Author](#author)

---

## Objective
The primary goal of this script is to:
- Process log files to extract valuable insights.
- Automate tasks like identifying suspicious activities and determining user behavior trends.
- Produce a clean, structured output in the terminal and a CSV file for reporting purposes.

---

## Features
The script implements the following functionalities:
1. **Count Requests per IP Address**:
   - Parses the log file to identify unique IP addresses and their request counts.
   - Sorts the results in descending order of request counts for quick interpretation.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts all accessed endpoints from the log file.
   - Highlights the most frequently accessed endpoint along with its access count.

3. **Detect Suspicious Activity**:
   - Identifies potential brute force login attempts:
     - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).
   - Detects log entries indicating failed login attempts using HTTP status codes (`401`) or failure messages.

4. **Output Results**:
   - Displays findings in an organized format in the terminal.
   - Saves results to a CSV file named `log_analysis_results.csv` with the following structure:
     - **Requests per IP**: IP Address, Request Count
     - **Most Accessed Endpoint**: Endpoint, Access Count
     - **Suspicious Activity**: IP Address, Failed Login Count

---

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/<log-analysis-and-security-insights>.git
   ```

2. Navigate to the project directory:
   ```bash
   cd Log-Analysis-Script
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## File Structure
```
.
├── log_analysis.py             # Main Python script
├── sample.log                  # Example log file for testing
├── log_analysis_results.csv    # Output CSV file with analysis results
└── README.md                   # Project documentation
```

---

## Requirements
- **Python 3.8+**
- Libraries:
  - `pandas`
  - `numpy`

---

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/<abhijeetmishra29>/log-analysis-script.git
   cd log-analysis-script
   ```

2. Install the required libraries:
   ```bash
   pip install pandas numpy
   ```

3. Place your log file in the project directory with the name `sample.log`.

---

## Results

### Terminal Output Example:
```plaintext
IP Address Analysis:
192.168.1.1 - 234 requests
203.0.113.5 - 187 requests
...

Most Accessed Endpoint:
/home - Accessed 403 times

Suspicious IPs:
192.168.1.100 - 56 failed login attempts
203.0.113.34 - 12 failed login attempts
```

### CSV Output:
The CSV file `log_analysis_results.csv` will include:
| IP Address       | Request Count | Most Accessed Endpoint | Suspicious Activity         |
|------------------|---------------|-------------------------|-----------------------------|
| 192.168.1.1      | 7             | /login                  | No                          |
| 10.0.0.2         | 6             | /login                  | No                          |
| 192.168.1.100    | 5             | /login                  | Yes (5 failed attempts)     |
| 203.0.113.5      | -             | -                       | Yes (8 failed attempts)     |

---

## Usage
1. Place the log file in the project directory.
2. Run the script by providing the log file as an argument:
   ```bash
   python log_analysis.py <logfile>
   ```
3. View the results in the terminal and check `log_analysis_results.csv` for a detailed report.

---

## Output Details
The script generates the following:
1. **Terminal Output**:
   - Count of requests per IP, sorted in descending order.
   - The most frequently accessed endpoint and its count.
   - Suspicious activities with flagged IPs and failed login counts.

2. **CSV File**:
   - `log_analysis_results.csv` with:
     - Requests per IP: IP Address, Request Count
     - Most Accessed Endpoint: Endpoint, Access Count
     - Suspicious Activity: IP Address, Failed Login Count

---

## Evaluation Criteria
1. **Functionality**:
   - Properly implements all required analysis features.
   - Handles the provided log file accurately and efficiently.
2. **Code Quality**:
   - Follows Python best practices with clean, modular, and well-commented code.
   - Uses meaningful variable names and clear function definitions.
3. **Performance**:
   - Processes large log files without significant delays.
4. **Output**:
   - Displays a structured and accurate terminal output.
   - Creates a correctly formatted CSV file matching specifications.

---

## Author
This project was developed by **Abhijeet Mishra**.
