<#
.SYNOPSIS
Cisco IronPort Maillog Analyzer

.DESCRIPTION
Cisco IronPort Maillog Analyzer
- Able to read maillog and generate report in CSV
- Extract and combine the following data columns from maillog:
	- ICIDStart, ICIDEnd, MIDStart, MIDEnd, ICID, MID, SenderIP, SenderHost, ReverseDNS,
	  SBRSState, HAT, SBRS, Country, From, To, Subject, Size, ToState, MIDState,
	  Spam, Bounce, Policy, VirusFound
- Read the whole log as default, or you can specify the start and/or end date to process.
- Requires "Join-Object" from Warren Frame. Default is placed at current folder.
  (http://ramblingcookiemonster.github.io/Join-Object/)
- Requires "ChilkatDotNet47.dll" from Chilkat Software, Inc. to decode MIME subjects
  (http://www.chilkatsoft.com/x64_Framework47.asp)



.PARAMETER LogFile
Optional. Path and filename of maillog. Default is ".\mail.current".

.PARAMETER StartDate
Optional. Will only process maillog starting from "StartDate" till end of log or "EndDate", if provided.

.PARAMETER EndDate
Optional. Will only process maillog from start of log or "StartDate" till "EndDate", if provided.

.PARAMETER Verify
Optional. Export interim results for verification.

.OUTPUTS
Output file will save as "ICIDAll yyyy-MM-dd HHmm.csv"

.NOTES
1. May take hours to process large log files.
2. You are adviced to trim down the file or set start and/or end date.

.EXAMPLE
IronPortMaillog.ps1
Process whole maillog with default path and file name.
#>

<#
Update History

v4:
	-	Added garbage collection to free resources after log parsed, and after each "Join-Object" sections
	-	Added "$Bouncere" Regex to get Bounce responses
	-	Added "$Policyre" Regex to get Policy matched
	-	Added "$AntiVirusre" Regex to get Virus name if AV positive
	-	Added "$MIDAbortre" Regex to get reasons of message aborted
	-	Added Base64 Subject decoding
			Requires "ChilkatDotNet47.dll" from http://www.chilkatsoft.com/x64_Framework47.asp
	-	Updated and fixed other Regex patterns
	-	Added "-Verify" switch to export interim results.
		Date columns will not be added to the lists, except the start and end list for ICID and MID
		Seems skipping those obsolete columns will save some time on joining the lists.
	-	Reordered log parsing sequence, descending order according to hit rates
			Initial result: Seems used few seconds more then original order
	-	Add empty row to list arrays to prevent error when joining with empty array
		Can be modified if able to add heading without empty row
	- 	Tried "Join-Object LINQ Edition" from https://www.powershellgallery.com/packages/Join-Object/
		Result: Failed to get same result as the script from Warren Frame

#>

Param (
[Parameter(mandatory=$false,Position=0,HelpMessage = "Path and filename of maillog")]
[String]$LogFile = ".\mail.current",

[String]$StartDate,

[String]$EndDate,

[Switch]$Verify = $false
)

$StartTime = Get-Date
Write-Host "`nStarts at: $StartTime`n"

# Check file availability, and terminates if file not found.
if (Test-Path $LogFile) {
	$MailLog = Get-Content $LogFile
} else {
	Write-Host "`n""$LogFile"" not found.`n`nPlease provide correct IronPort log file name and path.`n"
	Exit
}

# Requires "ChilkatDotNet47.dll" to decode MIME subjects
# http://www.chilkatsoft.com/x64_Framework47.asp
# http://www.chilkatsoft.com/refdoc/csStringBuilderRef.html
# https://www.example-code.com/powershell/q_b_encoding.asp

# Requires DLL file from http://www.chilkatsoft.com/x64_Framework47.asp
# Assume it is located under $ENV:USERPROFILE
$MIMEDecodePath = "$ENV:USERPROFILE\ChilkatDotNet47.dll"

if (-Not (Test-Path $MIMEDecodePath)) {
	Write-Host "`nChilkatDotNet47.dll not found! Please download it from:`n`nhttp://www.chilkatsoft.com/x64_Framework47.asp`n`nThen save it as: $MIMEDecodePath`n"
	Exit
}

# Extract log if user entered StartDate or EndDate
if ($StartDate -or $EndDate) {

	# This Regex pattern is for capturing the date in Cisco IronPort maillog
	$LogDateTime = '\w{3} (?<Month>\w{3})  ?(?<Day>\d+) (?<Hours>\d+:\d+:\d+) (?<Year>\d{4}) .*'
	$StrTimeForm = "MMM d HH:mm:ss yyyy"

	# Temp file for storing extracted maillog
	$TempOutFile = [System.IO.Path]::GetTempFileName()

	# User entered both StartDate and EndDate
	if ($StartDate -and $EndDate) {
		$logstart = Get-Date $StartDate
		$logend = Get-Date $EndDate
		cat $LogFile | Select-String -Pattern $LogDateTime | %{ $_.Matches } | %{
			$logdatestr = "$($_.Groups[1]) $($_.Groups[2]) $($_.Groups[3]) $($_.Groups[4])"
			$logdate = [datetime]::ParseExact($logdatestr,$StrTimeForm,$null)
			if ($logdate -le $logend -and $logdate -ge $logstart) {
				$_.Groups[0] | Add-Content $TempOutFile
			}
		}
	}

	# User entered StartDate only
	if ($StartDate -and !$EndDate) {
		$logstart = Get-Date $StartDate
		cat $LogFile | Select-String -Pattern $LogDateTime | %{ $_.Matches } | %{
			$logdatestr = "$($_.Groups[1]) $($_.Groups[2]) $($_.Groups[3]) $($_.Groups[4])"
			$logdate = [datetime]::ParseExact($logdatestr,$StrTimeForm,$null)
			if ($logdate -ge $logstart) {
				$_.Groups[0] | Add-Content $TempOutFile
			}
		}
	}

	# User entered EndDate only
	if (!$StartDate -and $EndDate) {
		$logend = Get-Date $EndDate
		cat $LogFile | Select-String -Pattern $LogDateTime | %{ $_.Matches } | %{
			$logdatestr = "$($_.Groups[1]) $($_.Groups[2]) $($_.Groups[3]) $($_.Groups[4])"
			$logdate = [datetime]::ParseExact($logdatestr,$StrTimeForm,$null)
			if ($logdate -le $logend) {
				$_.Groups[0] | Add-Content $TempOutFile
			}
		}
	}
	$MailLog = Get-Content $TempOutFile
	Remove-Item $TempOutFile
}

# Requires Join-Object.ps1
# http://ramblingcookiemonster.github.io/Join-Object/
# https://github.com/RamblingCookieMonster/PowerShell/blob/master/Join-Object.ps1
$JoinURL = "https://raw.githubusercontent.com/RamblingCookieMonster/PowerShell/master/Join-Object.ps1"
$JoinPath = ".\Join-Object.ps1"

# Default location of Join-Object.ps1 current folder.
# If not then proceed to download it from web.
if (-Not (Test-Path $JoinPath)) {
	Write-Host "Join-Object.ps1 not found! Proceed to download from web."
	$JoinURL_Request = [System.Net.WebRequest]::Create($JoinURL)
	Try {
		$JoinURLResponse = $JoinURL_Request.GetResponse()
	}
	Catch {
		Write-Host "`nSeems ""Join-Object.ps1"" is moved to another URL.`nPlease get a copy yourself and try again.`n"
		Exit
	}
	(New-Object System.Net.WebClient).DownloadFile($JoinURL, $JoinPath)
	"Downloaded Join-Object.ps1.`n"
}

# Dot source function "Join-Object" before joining the lists
# . .\Join-Object.ps1
. $JoinPath

# Requires "ChilkatDotNet47.dll" to decode MIME subjects
$null = [Reflection.Assembly]::LoadFile($MIMEDecodePath)
$SubjectMIME = New-Object Chilkat.StringBuilder


$FileReadTime = Get-Date
$FileReadLap = $FileReadTime - $StartTime
Write-Host "Finished loading IronPort log file at: $FileReadTime ($($FileReadLap.Hours) hours, $($FileReadLap.Minutes) minutes and $($FileReadLap.Seconds) seconds)`n"

Write-Host "`nProceed to parse log file: $filepath`n"

## Regex patterns
# Assume your local IP range is 192.168.x.x
$ICIDStartre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).* New SMTP (?<ICID>ICID \d+).*address (?!192\.168\.\d*\.\d*)(?<SenderIP>\d*\.\d*\.\d*\.\d*) reverse dns host (?<SenderHost>\w.*) verified (?<ReverseDNS>yes|no)'
$SBRSre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<ICID>ICID \d+).* (?<State>\w+) SG (?<HAT>\w+).*(SBRS (?<SBRS>None|-?[.\d]{1,}))( country )?(?<Country>.*)?'
$MIDStartre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*Start (?<MID>MID \d+) (?<ICID>ICID \d+)'
$Fromre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+) (?<ICID>ICID \d+).*From.*<(?<From>\S+)>'
$Tore = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+) (?<ICID>ICID \d+).*To.*<(?<To>\S+)> ?(?<State>.+)?'
$Subjectre = "(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+).*Subject.*'(?<Subject>.*)'"
$MailSizere = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+).*ready (?<Size>\d+) bytes'
$ICIDEndre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<ICID>ICID \d+) close'
$CASEre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+) using engine.*CASE spam (?<Spam>\w+)'
$Bouncere = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+) .*Bounced by destination server with response: (?<Bounce>.*) '
$Policyre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+) *matched .*policy (?<Policy>.*) in the'
$AntiVirusre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<MID>MID \d+) *antivirus positive (?<Virus>.*) '
$MIDAbortre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*aborted (?<MID>MID \d+) (?<State>\w+.*)'
$MIDEndre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*finished (?<MID>MID \d+) (?<State>\w+)'

## Add empty row to prevent error when joining with empty array
$IRList_ICIDStart = @()
$IRList_MIDStart = @([PSCustomObject]@{ MIDStart = ""; MID = ""; MIDStartICID = "" })
$IRList_MIDEnd = @([PSCustomObject]@{ MIDEnd = ""; MIDEndMID = ""; MIDState = "" })
$IRList_ICIDEnd = @([PSCustomObject]@{ ICIDEnd = ""; ICIDEndICID = "" })

## Date is needed for verification only
if (-Not ($Verify)) {
	$IRList_SBRS = @([PSCustomObject]@{ SBRSICID = ""; SBRSState = ""; HAT = ""; SBRS = ""; Country = "" })
	$IRList_From = @([PSCustomObject]@{ FromMID = ""; FromICID = ""; From = ""; })
	$IRList_To = @([PSCustomObject]@{ ToMID = ""; ToICID = ""; To = ""; ToState = "" })
	$IRList_Subject = @([PSCustomObject]@{ SubjectMID = ""; Subject = "" })
	$IRList_MailSize = @([PSCustomObject]@{MailSizeMID = ""; Size = "" })
	$IRList_CASE = @([PSCustomObject]@{ CASEMID = ""; Spam = "" })
	$IRList_Bounce = @([PSCustomObject]@{ BounceMID = ""; Bounce = "" })
	$IRList_Policy = @([PSCustomObject]@{ PolicyMID = ""; Policy = "" })
	$IRList_AntiVirus = @([PSCustomObject]@{ AVMID = ""; VirusFound = "" })
} else {
	$IRList_SBRS = @([PSCustomObject]@{ SBRSDate = ""; SBRSICID = ""; SBRSState = ""; HAT = ""; SBRS = ""; Country = "" })
	$IRList_From = @([PSCustomObject]@{ FromDate = ""; FromMID = ""; FromICID = ""; From = ""; })
	$IRList_To = @([PSCustomObject]@{ ToDate = ""; ToMID = ""; ToICID = ""; To = ""; ToState = "" })
	$IRList_Subject = @([PSCustomObject]@{ SubjectDate = ""; SubjectMID = ""; Subject = "" })
	$IRList_MailSize = @([PSCustomObject]@{ MailSizeDate = ""; MailSizeMID = ""; Size = "" })
	$IRList_CASE = @([PSCustomObject]@{ CASEDate = ""; CASEMID = ""; Spam = "" })
	$IRList_Bounce = @([PSCustomObject]@{ BounceDate = ""; BounceMID = ""; Bounce = "" })
	$IRList_Policy = @([PSCustomObject]@{ PolicyDate = ""; PolicyMID = ""; Policy = "" })
	$IRList_AntiVirus = @([PSCustomObject]@{ AVDate = ""; AVMID = ""; VirusFound = "" })
}


<#
## For manual testing Regex pattern and export CSV

# Load Log file
$LogFile = ".\mail.current"
$MailLog = Get-Content $LogFile

$Verify = $false
$Verify = $true

# Regex pattern
$SBRSre = '(?<Date>\w{3}  ?\d+ \d+:\d+:\d+ \d{4}).*(?<ICID>ICID \d+).* (?<State>\w+) SG (?<HAT>\w+).*(SBRS (?<SBRS>None|-?[.\d]{1,}))( country )?(?<Country>.*)?'

# Get the lines with selected Regex pattern
cat ".\mail.current" | Select-String -Pattern $SBRSre | Set-Content ".\SBRS $(Get-Date -Format 'yyyy-MM-dd HHmm').txt"

# Get CSV which matched the selected Regex pattern
$IRList_SBRS = @([PSCustomObject]@{ SBRSICID = ""; SBRSState = ""; HAT = ""; SBRS = ""; Country = "" })
$IRList_SBRS = @([PSCustomObject]@{ SBRSDate = ""; SBRSICID = ""; SBRSState = ""; HAT = ""; SBRS = ""; Country = "" })

# Original with date
foreach ($line in $MailLog) {
	if ($line -match $SBRSre ) {
		$obj = New-Object -TypeName psObject -Property @{
			SBRSDate = $Matches.Date
			SBRSICID = $Matches.ICID
			SBRSState = $Matches.State
			HAT = $Matches.HAT
			SBRS = $Matches.SBRS
			Country = $Matches.Country
		}
		$IRList_SBRS += $obj
	}
}

# New, testing with date if $Verify is true
foreach ($line in $MailLog) {
	if ($line -match $SBRSre ) {
		$obj = @{
			SBRSICID = $Matches.ICID
			SBRSState = $Matches.State
			HAT = $Matches.HAT
			SBRS = $Matches.SBRS
			Country = $Matches.Country
		}
		if ($Verify) { $obj.Add("SBRSDate", $Matches.Date) }
		$IRList_SBRS += New-Object -TypeName psObject -Property $obj
	}
}

$IRList_SBRS | Select-Object -Property SBRSICID, SBRSState, HAT, SBRS, Country | Export-Csv ".\SBRS $(Get-Date -Format 'yyyy-MM-dd HHmm').csv" -NoTypeInformation -Encoding UTF8
$IRList_SBRS | Select-Object -Property SBRSDate, SBRSICID, SBRSState, HAT, SBRS, Country | Export-Csv ".\SBRS $(Get-Date -Format 'yyyy-MM-dd HHmm').csv" -NoTypeInformation -Encoding UTF8
#>

foreach ($line in $MailLog) {
	switch -regex ($line) {
		$ICIDStartre {
			$obj = New-Object -TypeName psObject -Property @{
				ICIDStart = $Matches.Date
				ICID = $Matches.ICID
				SenderIP = $Matches.SenderIP
				SenderHost = $Matches.SenderHost
				ReverseDNS = $Matches.ReverseDNS
			}
			$IRList_ICIDStart += $obj
			break
		}
		$ICIDEndre {
			$obj = New-Object -TypeName psObject -Property @{
				ICIDEnd = $Matches.Date
				ICIDEndICID = $Matches.ICID
			}
			$IRList_ICIDEnd += $obj
			break
		}
		$SBRSre {
			$obj = @{
				#SBRSDate = $Matches.Date
				SBRSICID = $Matches.ICID
				SBRSState = $Matches.State
				HAT = $Matches.HAT
				SBRS = $Matches.SBRS
				Country = $Matches.Country
			}
			if ($Verify) { $obj.Add("SBRSDate", $Matches.Date) }
			$IRList_SBRS += New-Object -TypeName psObject -Property $obj
			break
		}
		$Tore {
			$obj = @{
				#ToDate = $Matches.Date
				ToMID = $Matches.MID
				ToICID = $Matches.ICID
				To = $Matches.To
				ToState = $Matches.State
			}
			if ($Verify) { $obj.Add("ToDate", $Matches.Date) }
			$IRList_To += New-Object -TypeName psObject -Property $obj
			break
		}
		$MIDStartre {
			$obj = New-Object -TypeName psObject -Property @{
				MIDStart = $Matches.Date
				MID = $Matches.MID
				MIDStartICID = $Matches.ICID
			}
			$IRList_MIDStart += $obj
			break
		}
		$MIDAbortre {
			$obj = New-Object -TypeName psObject -Property @{
				MIDEnd = $Matches.Date
				MIDEndMID = $Matches.MID
				MIDState = $Matches.State
			}
			$IRList_MIDEnd += $obj
			break
		}
		$MIDEndre {
			$obj = New-Object -TypeName psObject -Property @{
				MIDEnd = $Matches.Date
				MIDEndMID = $Matches.MID
				MIDState = $Matches.State
			}
			$IRList_MIDEnd += $obj
			break
		}
		$MailSizere {
			$obj = @{
				#MailSizeDate = $Matches.Date
				MailSizeMID = $Matches.MID
				Size = $Matches.Size
			}
			if ($Verify) { $obj.Add("MailSizeDate", $Matches.Date) }
			$IRList_MailSize += New-Object -TypeName psObject -Property $obj
			break
		}
		$Fromre {
			$obj = @{
				#FromDate = $Matches.Date
				FromMID = $Matches.MID
				FromICID = $Matches.ICID
				From = $Matches.From
			}
			if ($Verify) { $obj.Add("FromDate", $Matches.Date) }
			$IRList_From += New-Object -TypeName psObject -Property $obj
			break
		}
		$Subjectre {
<# Original code without decoding
			$obj = New-Object -TypeName psObject -Property @{
				SubjectDate = $Matches.Date
				SubjectMID = $Matches.MID
				Subject = $Matches.Subject
			}
			$IRList_Subject += $obj
			break
#>
# New code with decoding using ChilkatDotNet47.dll
			$SubjectDate = $Matches.Date
			$SubjectMID = $Matches.MID
			$Subject = $Matches.Subject

			$SubjectMIME.Clear()
			<#
			# Seems most Base64 tested are using UTF-8 Charset
			switch -regex ($Subject) {
				'(?:=[0-9a-fA-F]{2}){1,}' {
					$Subject -match "=\?(?<Charset>.*?)\?(?<Encoding>.)\?"
					$SubjectMIME.Append($Subject)
					$SubjectMIME.Decode($Matches.Encoding,"utf-8")
					Write-Host "Matched regex '(?:=[0-9a-fA-F]{2}){1,}'`n"
					$($SubjectMIME.GetAsString())
					break
				}
				'=\?(?<Charset>.*?)\?(?<Encoding>.)\?' {
					$SubjectMIME.Append($Subject)
					$SubjectMIME.Decode($Matches.Encoding,$Matches.Charset)
					Write-Host "Matched regex '=\?(?<Charset>.*?)\?(?<Encoding>.)\?'`n"
					$($SubjectMIME.GetAsString())
					break
				}
			}
			#>
			if ($Subject -match "=\?(?<Charset>.*?)\?(?<Encoding>.)\?" ) {
				$null = $SubjectMIME.Append($Subject)
				# $SubjectMIME.Decode($Matches.Encoding,$Matches.Charset)
				$null = $SubjectMIME.Decode($Matches.Encoding,"utf-8")
				$Subject = $SubjectMIME.GetAsString()
			}
			$obj = @{
				#SubjectDate = $SubjectDate
				SubjectMID = $SubjectMID
				Subject = $Subject
			}
			if ($Verify) { $obj.Add("SubjectDate", $SubjectDate) }
			$IRList_Subject += New-Object -TypeName psObject -Property $obj
			break
		}
		$Policyre {
			$obj = @{
				#PolicyDate = $Matches.Date
				PolicyMID = $Matches.MID
				Policy = $Matches.Policy
			}
			if ($Verify) { $obj.Add("PolicyDate", $Matches.Date) }
			$IRList_Policy += New-Object -TypeName psObject -Property $obj
			break
		}
		$CASEre {
			$obj = @{
				#CASEDate = $Matches.Date
				CASEMID = $Matches.MID
				Spam = $Matches.Spam
			}
			if ($Verify) { $obj.Add("CASEDate", $Matches.Date) }
			$IRList_CASE += New-Object -TypeName psObject -Property $obj
			break
		}
		$Bouncere {
			$obj = @{
				#BounceDate = $Matches.Date
				BounceMID = $Matches.MID
				Bounce = $Matches.Bounce
			}
			if ($Verify) { $obj.Add("BounceDate", $Matches.Date) }
			$IRList_Bounce += New-Object -TypeName psObject -Property $obj
			break
		}
		$AntiVirusre {
			$obj = @{
				#AVDate = $Matches.Date
				AVMID = $Matches.MID
				VirusFound = $Matches.Virus
			}
			if ($Verify) { $obj.Add("AVDate", $Matches.Date) }
			$IRList_AntiVirus += New-Object -TypeName psObject -Property $obj
			break
		}
	}
}

$LogParseTime = Get-Date
$LogParseLap = $LogParseTime - $FileReadTime
Write-Host "Finished parsing IronPort log file at: $LogParseTime ($($LogParseLap.Hours) hours, $($LogParseLap.Minutes) minutes and $($LogParseLap.Seconds) seconds)`n"

# Optional, Export interim results for verification
if ($Verify) {
	Write-Host "`nProceed to export parsed results.`n"

	$IRList_ICIDStart | Select-Object -Property ICIDStart, ICID, SenderIP, SenderHost, ReverseDNS | Export-Csv ".\ICIDStart $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_SBRS | Select-Object -Property SBRSDate, SBRSICID, SBRSState, HAT, SBRS, Country | Export-Csv ".\SBRS $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_MIDStart | Select-Object -Property MIDStart, MID, MIDStartICID | Export-Csv ".\MIDStart $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_From | Select-Object -Property FromDate, FromMID, FromICID, From | Export-Csv ".\From $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_To | Select-Object -Property ToDate, ToMID, ToICID, To, ToState | Export-Csv ".\To $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_Subject | Select-Object -Property SubjectDate, SubjectMID, Subject | Export-Csv ".\Subject $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8
	$IRList_MailSize | Select-Object -Property MailSizeDate, MailSizeMID, Size | Export-Csv ".\MailSize $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_ICIDEnd | Select-Object -Property ICIDEnd, ICIDEndICID | Export-Csv ".\ICIDEnd $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_CASE | Select-Object -Property CASEDate, CASEMID, Spam | Export-Csv ".\CASE $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_Bounce | Select-Object -Property BounceDate, BounceMID, Bounce | Export-Csv ".\Bounce $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_Policy | Select-Object -Property PolicyDate, PolicyMID, Policy | Export-Csv ".\Policy $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_AntiVirus | Select-Object -Property AVDate, AVMID, VirusFound | Export-Csv ".\AntiVirus $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation
	$IRList_MIDEnd | Select-Object -Property MIDEnd, MIDEndMID, MIDState | Export-Csv ".\MIDEnd $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation

	$LogExportTime = Get-Date
	$LogExportLap = $LogExportTime - $LogParseTime
	Write-Host "Finished exporting parsed results at: $LogExportTime ($($LogExportLap.Hours) hours, $($LogExportLap.Minutes) minutes and $($LogExportLap.Seconds) seconds)`n"
}

# Log parsed, variables other than parsed lists can be removed
Remove-Variable "MailLog" -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Count steps for Join-Object
$IRSteps_Total = (Get-Variable IRList_*).Count -1
$IRStep = 1

Write-Host "`nProceed to join parsed results.`n"

# Combine all information according to ICID
# Join IRList_ICIDStart with IRList_SBRS
Write-Host "($IRStep/$IRSteps_Total) Starts Join IRList_ICIDStart with IRList_SBRS at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRS = Join-Object -Left $IRList_ICIDStart -Right $IRList_SBRS -LeftJoinProperty ICID -RightJoinProperty SBRSICID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRS | Select-Object -Property ICIDStart, ICID, SBRSICID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS | Export-Csv ".\ICIDSBRS $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation

# Remove obsoleted lists to free resources
Remove-Variable ("IRList_ICIDStart", "IRList_SBRS") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS with IRList_MIDStart
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_MIDStart at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMID = Join-Object -Left $ICIDSBRS -Right $IRList_MIDStart -LeftJoinProperty ICID -RightJoinProperty MIDStartICID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMID | Select-Object -Property ICIDStart, MIDStart, ICID, SBRSICID, MIDStartICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS | Export-Csv ".\ICIDSBRSMID $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRS", "IRList_MIDStart") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart with IRList_From
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_From at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFrom = Join-Object -Left $ICIDSBRSMID -Right $IRList_From -LeftJoinProperty MID -RightJoinProperty FromMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFrom | Select-Object -Property ICIDStart, MIDStart, ICID, FromICID, MID, FromMID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From | Export-Csv ".\ICIDSBRSMIDSender $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMID", "IRList_From") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From with IRList_To
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_To at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromTo = Join-Object -Left $ICIDSBRSMIDFrom -Right $IRList_To -LeftJoinProperty MID -RightJoinProperty ToMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromTo | Select-Object -Property ICIDStart, MIDStart, ICID, MID, ToMID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, ToState | Export-Csv ".\ICIDSBRSMIDSenderTo $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFrom", "IRList_To") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To with IRList_Subject
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_Subject at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSub = Join-Object -Left $ICIDSBRSMIDFromTo -Right $IRList_Subject -LeftJoinProperty MID -RightJoinProperty SubjectMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSub | Select-Object -Property ICIDStart, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, ToState | Export-Csv ".\ICIDSBRSMIDFromToSub $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromTo", "IRList_Subject") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject with IRList_MailSize
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_MailSize at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSubSize = Join-Object -Left $ICIDSBRSMIDFromToSub -Right $IRList_MailSize -LeftJoinProperty MID -RightJoinProperty MailSizeMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSubSize | Select-Object -Property ICIDStart, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, Size, ToState | Export-Csv ".\ICIDSBRSMIDFromToSubSize $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromToSub", "IRList_MailSize") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject, IRList_MailSize with IRList_ICIDEnd
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_ICIDEnd at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSubSizeICIDEnd = Join-Object -Left $ICIDSBRSMIDFromToSubSize -Right $IRList_ICIDEnd -LeftJoinProperty ICID -RightJoinProperty ICIDEndICID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSubSizeICIDEnd | Select-Object -Property ICIDStart, ICIDEnd, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, Size, ToState | Export-Csv ".\ICIDSBRSMIDFromToSubSizeICIDEnd $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromToSubSize", "IRList_ICIDEnd") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject, IRList_MailSize, IRList_ICIDEnd with IRList_CASE
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_CASE at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSubSizeCASE = Join-Object -Left $ICIDSBRSMIDFromToSubSizeICIDEnd -Right $IRList_CASE -LeftJoinProperty MID -RightJoinProperty CASEMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSubSizeCASE | Select-Object -Property ICIDStart, ICIDEnd, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, Size, ToState, Spam | Export-Csv ".\ICIDSBRSMIDFromToSubSizeCASE $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromToSubSizeICIDEnd", "IRList_CASE") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject, IRList_MailSize, IRList_ICIDEnd, IRList_CASE with IRList_Bounce
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_Bounce at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSubSizeCASEBounce = Join-Object -Left $ICIDSBRSMIDFromToSubSizeCASE -Right $IRList_Bounce -LeftJoinProperty MID -RightJoinProperty BounceMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSubSizeCASEPolicy | Select-Object -Property ICIDStart, ICIDEnd, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, Size, ToState, Spam, Bounce | Export-Csv ".\ICIDSBRSMIDFromToSubSizeCASEPolicy $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromToSubSizeCASE", "IRList_Bounce") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject, IRList_MailSize, IRList_ICIDEnd, IRList_CASE, IRList_Bounce with IRList_Policy
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_Policy at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSubSizeCASEBouncePolicy = Join-Object -Left $ICIDSBRSMIDFromToSubSizeCASEBounce -Right $IRList_Policy -LeftJoinProperty MID -RightJoinProperty PolicyMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSubSizeCASEPolicy | Select-Object -Property ICIDStart, ICIDEnd, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, Size, ToState, Spam, Bounce, Policy | Export-Csv ".\ICIDSBRSMIDFromToSubSizeCASEPolicy $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromToSubSizeCASEBounce", "IRList_Policy") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject, IRList_MailSize, IRList_ICIDEnd, IRList_CASE, IRList_Bounce, IRList_Policy with IRList_AntiVirus
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_AntiVirus at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDSBRSMIDFromToSubSizeCASEBouncePolicyAV = Join-Object -Left $ICIDSBRSMIDFromToSubSizeCASEBouncePolicy -Right $IRList_AntiVirus -LeftJoinProperty MID -RightJoinProperty AVMID -Type AllInLeft
# Optional, Export interim joined results for verification
# $ICIDSBRSMIDFromToSubSizeCASEPolicyAV | Select-Object -Property ICIDStart, ICIDEnd, MIDStart, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, From, To, Subject, Size, ToState, Spam, Bounce, Policy, VirusFound | Export-Csv ".\ICIDSBRSMIDFromToSubSizeCASEPolicyAV $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8

# Remove obsoleted lists to free resources
Remove-Variable ("ICIDSBRSMIDFromToSubSizeCASEBouncePolicy", "IRList_AntiVirus") -ErrorAction SilentlyContinue
[System.GC]::Collect()

# Join IRList_ICIDStart, IRList_SBRS, IRList_MIDStart, IRList_From, IRList_To, IRList_Subject, IRList_MailSize, IRList_ICIDEnd, IRList_CASE, IRList_Bounce, IRList_Policy, IRList_AntiVirus with IRList_MIDEnd
$IRStep++
Write-Host "($IRStep/$IRSteps_Total) Starts Join last result with IRList_MIDEnd at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ICIDAll = Join-Object -Left $ICIDSBRSMIDFromToSubSizeCASEBouncePolicyAV -Right $IRList_MIDEnd -LeftJoinProperty MID -RightJoinProperty MIDEndMID -Type AllInLeft

Write-Host "`nFinished combining all information according to ICID at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Final output for combining information according to ICID
$ICIDAll | Select-Object -Property ICIDStart, ICIDEnd, MIDStart, MIDEnd, ICID, MID, SenderIP, SenderHost, ReverseDNS, SBRSState, HAT, SBRS, Country, From, To, Subject, Size, ToState, MIDState, Spam, Bounce, Policy, VirusFound | Sort-Object ICID, MID, ICIDStart, MIDStart, From, To, Subject | Export-Csv ".\ICID Incoming $($StartTime.ToString('yyyy-MM-dd HHmm')).csv" -NoTypeInformation -Encoding UTF8


$JoinTime = Get-Date
#$JoinLap = $JoinTime - $LogExportTime
$JoinLap = $JoinTime - $LogParseTime
$Total = $JoinTime - $StartTime
Write-Host "Finished joining parsed IronPort log file at: $JoinTime ($($JoinLap.Hours) hours, $($JoinLap.Minutes) minutes and $($JoinLap.Seconds) seconds)`n"
Write-Host "`nTask completed.`nTime used for this task: $($Total.Hours) hours, $($Total.Minutes) minutes and $($Total.Seconds) seconds`n"

Remove-Variable ("ICIDAll", "ICIDSBRSMIDFromToSubSizeCASEBouncePolicyAV", "IRList_MIDEnd") -ErrorAction SilentlyContinue
[System.GC]::Collect()
