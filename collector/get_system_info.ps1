Get-Process | Where-Object { $_.Path } | Select-Object ProcessName, Path | ForEach-Object {
    "$($_.ProcessName)|$($_.Path)"
}
