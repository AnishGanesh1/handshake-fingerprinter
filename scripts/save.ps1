<#
  save.ps1 — stage, commit, and push in one step (Windows PowerShell).
  Usage:   .\scripts\save.ps1 "day 3: implement JA3"
#>
param([Parameter(Mandatory = $true)][string]$Message)

git add -A
git commit -m $Message
git push
