Get-Process | Where-Object { $_.Path } | Select-Object ProcessName, Path | ForEach-Object {
    "$($_.ProcessName)|$($_.Path)"
}

Write-Output "---NETWORK---"
Get-NetTCPConnection -State Established | Select-Object OwningProcess, RemoteAddress, RemotePort | ForEach-Object {
    "$($_.OwningProcess)|$($_.RemoteAddress)|$($_.RemotePort)"
}
