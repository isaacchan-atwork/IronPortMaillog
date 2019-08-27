# Cisco IronPort Maillog Analyzer
 


## Overview of the script

1. Read IronPort log file.
	- Default is `mail.current` at your profile folder.
	- You can specify the start and/or end date to limit the amount of log before processing, as it takes tens of minutes to analyze a large log file.

2. Get information from the log.
	- Read the file line by line and extract related information using regex patterns. Information is stored into separate lists.
	- You may need to modify those regex patterns to suit your environment. You can use https://regex101.com/ or https://regexr.com/ to test your patterns first. I would suggest https://regex101.com/ as it supports the syntax of "Named Capture Group" used by PowerShell.
	- Only logs for incoming email will be analyzed. This is done by ignoring `New SMTP` lines with internal IP. You can change it by modifying the IP regex pattern in `$ICIDStartre` (`(?!192\.168\.\d*\.\d*)`)
	- If parameter `-Verify` is added, the script will include date columns to all lists and export all parsed results to CSV files.

3. Join the list and export final result as CSV file, with name starting with "ICID Incoming" under your profile folder.


## Installation

Download [the script](https://github.com/isaacchan-atwork/IronPortMaillog/blob/master/IronPortMaillog.ps1) and place it to your profile folder (`%USERPROFILE%`), as it is the default location when starting PowerShell.

## Requirements
* "[Join-Object](http://ramblingcookiemonster.github.io/Join-Object/)" from Warren Frame. Default is placed at current folder.
* "[ChilkatDotNet47.dll](http://www.chilkatsoft.com/x64_Framework47.asp)" from Chilkat Software, Inc. to decode MIME subjects.

	You can also put them to your profile folder or you will need to modify their path in the script.


## Usage

```
IronPortMaillogv4.ps1 [[-LogFile] <String>] [-StartDate <String>] [-EndDate <String>] [-Verify] [<CommonParameters>]
```

