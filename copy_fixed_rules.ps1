$sourceDir = "d:\Downloads in D\Data Amides\Auto_test_linux_Command\fixed_rule_process_creation"
$destDir = Join-Path $sourceDir "all"

# Create destination directory if it doesn't exist
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
    Write-Host "Created directory: $destDir"
}

# Get all subdirectories in the source directory (excluding 'all' itself to avoid recursion issues if re-run)
$subdirs = Get-ChildItem -Path $sourceDir -Directory | Where-Object { $_.Name -ne "all" }

foreach ($subdir in $subdirs) {
    # Find fixed_*.yml files in the subdirectory
    $files = Get-ChildItem -Path $subdir.FullName -Filter "fixed_*.yml"
    
    foreach ($file in $files) {
        $destFile = Join-Path $destDir $file.Name
        Write-Host "Copying $($file.FullName) to $destFile"
        Copy-Item -Path $file.FullName -Destination $destFile -Force
    }
}

Write-Host "Copy operation complete."
