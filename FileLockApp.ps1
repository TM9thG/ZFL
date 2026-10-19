Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:Passcode = 'TM9thG'
$script:StoreDirectory = Join-Path $env:LOCALAPPDATA 'TM9thGFileLock'
$script:StorePath = Join-Path $script:StoreDirectory 'locks.json'
$script:Locks = @()

function Show-ErrorMessage {
    param([string]$Message)

    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        'File Lock',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Show-PasscodePrompt {
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'File Lock - Passcode'
    $dialog.StartPosition = 'CenterScreen'
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.ClientSize = New-Object System.Drawing.Size(360, 145)
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.ShowInTaskbar = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Enter the passcode to open File Lock:'
    $label.Location = New-Object System.Drawing.Point(16, 16)
    $label.Size = New-Object System.Drawing.Size(328, 24)

    $passcodeInput = New-Object System.Windows.Forms.TextBox
    $passcodeInput.Location = New-Object System.Drawing.Point(16, 48)
    $passcodeInput.Size = New-Object System.Drawing.Size(328, 25)
    $passcodeInput.UseSystemPasswordChar = $true

    $continue = New-Object System.Windows.Forms.Button
    $continue.Text = 'Continue'
    $continue.Location = New-Object System.Drawing.Point(168, 94)
    $continue.Size = New-Object System.Drawing.Size(84, 30)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Exit'
    $cancel.Location = New-Object System.Drawing.Point(260, 94)
    $cancel.Size = New-Object System.Drawing.Size(84, 30)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $continue.Add_Click({
        if ($passcodeInput.Text -ceq $script:Passcode) {
            $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $dialog.Close()
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                $dialog,
                'Incorrect passcode.',
                'File Lock',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            $passcodeInput.Clear()
            $passcodeInput.Focus()
        }
    })

    $dialog.Controls.AddRange(@($label, $passcodeInput, $continue, $cancel))
    $dialog.AcceptButton = $continue
    $dialog.CancelButton = $cancel
    $passcodeInput.Focus()
    return ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
}

function Read-Locks {
    if (-not (Test-Path -LiteralPath $script:StorePath -PathType Leaf)) {
        return
    }

    try {
        $storedJson = [System.IO.File]::ReadAllText($script:StorePath, [System.Text.Encoding]::UTF8)
        $storedLocks = $storedJson | ConvertFrom-Json
        foreach ($entry in @($storedLocks)) {
            if ($null -ne $entry -and
                -not [string]::IsNullOrWhiteSpace([string]$entry.Path) -and
                -not [string]::IsNullOrWhiteSpace([string]$entry.Message)) {
                $script:Locks += [pscustomobject]@{
                    Path = [string]$entry.Path
                    Message = [string]$entry.Message
                    Sid = if ($entry.PSObject.Properties['Sid']) { [string]$entry.Sid } else { '' }
                    RuleAdded = if ($entry.PSObject.Properties['RuleAdded']) { [bool]$entry.RuleAdded } else { $false }
                }
            }
        }
    }
    catch {
        throw "Could not read the saved lock list at '$script:StorePath'. $($_.Exception.Message)"
    }
}

function Write-Locks {
    param([object[]]$Items)

    $temporaryPath = "$script:StorePath.tmp"
    try {
        if (-not (Test-Path -LiteralPath $script:StoreDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $script:StoreDirectory -Force | Out-Null
        }

        $json = ConvertTo-Json -InputObject @($Items) -Depth 4
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($temporaryPath, $json, $encoding)
        Move-Item -LiteralPath $temporaryPath -Destination $script:StorePath -Force
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
        throw "Could not save the lock list. $($_.Exception.Message)"
    }
}

function Add-FileLockRule {
    param(
        [string]$Path,
        [string]$Sid = '',
        [bool]$PreviouslyAdded = $false
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    }
    else {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    }

    $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [System.Security.AccessControl.FileSystemRights]::Write
    try {
        $acl = Get-Acl -LiteralPath $Path
        $rules = $acl.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )

        foreach ($existingRule in $rules) {
            $coversRequestedRights = (
                ([int]$existingRule.FileSystemRights -band [int]$rights) -eq [int]$rights
            )
            if ($existingRule.IdentityReference.Value -eq $identity.Value -and
                $existingRule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                $coversRequestedRights) {
                return [pscustomobject]@{
                    Sid = $identity.Value
                    RuleAdded = $PreviouslyAdded
                    AddedNow = $false
                }
            }
        }

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            $rights,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
        $acl.AddAccessRule($rule)
        try {
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
        catch {
            throw "Could not change permissions for '$Path'. Try running start-file-lock.bat as administrator. $($_.Exception.Message)"
        }

        return [pscustomobject]@{
            Sid = $identity.Value
            RuleAdded = $true
            AddedNow = $true
        }
    }
    catch {
        throw "Could not apply the file lock to '$Path'. $($_.Exception.Message)"
    }
}

function Remove-FileLockRule {
    param(
        [string]$Path,
        [string]$Sid,
        [bool]$RuleAdded
    )

    if (-not $RuleAdded) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($Sid)) {
        throw "The saved lock for '$Path' is missing its Windows user ID, so its permission rule cannot be safely removed."
    }

    $identity = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [System.Security.AccessControl.FileSystemRights]::Write
    try {
        $acl = Get-Acl -LiteralPath $Path
        $rules = $acl.GetAccessRules(
            $true,
            $false,
            [System.Security.Principal.SecurityIdentifier]
        )
        $matchingRuleExists = $false
        foreach ($existingRule in $rules) {
            if ($existingRule.IdentityReference.Value -eq $identity.Value -and
                $existingRule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                $existingRule.FileSystemRights -eq $rights -and
                $existingRule.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None -and
                $existingRule.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None) {
                $matchingRuleExists = $true
                break
            }
        }

        if ($matchingRuleExists) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $identity,
                $rights,
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Deny
            )
            $acl.RemoveAccessRuleSpecific($rule)
            Set-Acl -LiteralPath $Path -AclObject $acl
        }
    }
    catch {
        throw "Could not remove File Lock's permission rule from '$Path'. $($_.Exception.Message)"
    }
}

try {
    Read-Locks
}
catch {
    Show-ErrorMessage $_.Exception.Message
    exit 1
}

if (-not (Show-PasscodePrompt)) {
    exit 0
}

$script:StartupWarnings = @()
for ($index = 0; $index -lt $script:Locks.Count; $index++) {
    $existing = $script:Locks[$index]
    $wasAdded = [bool]$existing.RuleAdded
    $lockResult = $null
    try {
        $lockResult = Add-FileLockRule `
            -Path $existing.Path `
            -Sid $existing.Sid `
            -PreviouslyAdded $wasAdded

        $updatedItem = [pscustomobject]@{
            Path = $existing.Path
            Message = $existing.Message
            Sid = $lockResult.Sid
            RuleAdded = $lockResult.RuleAdded
        }
        $updatedLocks = @($script:Locks)
        $updatedLocks[$index] = $updatedItem
        Write-Locks -Items $updatedLocks
        $script:Locks = @($updatedLocks)
    }
    catch {
        if ($null -ne $lockResult -and $lockResult.AddedNow) {
            try {
                Remove-FileLockRule -Path $existing.Path -Sid $lockResult.Sid -RuleAdded $true
            }
            catch {
                $script:StartupWarnings += "Could not roll back a permission change for '$($existing.Path)': $($_.Exception.Message)"
            }
        }
        $script:StartupWarnings += "Could not enforce the lock for '$($existing.Path)': $($_.Exception.Message)"
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'File Lock'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = New-Object System.Drawing.Size(820, 650)
$form.MinimumSize = New-Object System.Drawing.Size(760, 600)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$intro = New-Object System.Windows.Forms.Label
$intro.Text = 'Save a file path to block this Windows account from reading, editing, or launching it.'
$intro.Location = New-Object System.Drawing.Point(18, 16)
$intro.Size = New-Object System.Drawing.Size(780, 26)

$pathLabel = New-Object System.Windows.Forms.Label
$pathLabel.Text = 'File path'
$pathLabel.Location = New-Object System.Drawing.Point(18, 55)
$pathLabel.Size = New-Object System.Drawing.Size(90, 22)

$pathInput = New-Object System.Windows.Forms.TextBox
$pathInput.Location = New-Object System.Drawing.Point(18, 80)
$pathInput.Size = New-Object System.Drawing.Size(635, 25)
$pathInput.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Text = 'Browse...'
$browseButton.Location = New-Object System.Drawing.Point(666, 78)
$browseButton.Size = New-Object System.Drawing.Size(126, 29)
$browseButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right

$messageLabel = New-Object System.Windows.Forms.Label
$messageLabel.Text = 'Popup message'
$messageLabel.Location = New-Object System.Drawing.Point(18, 119)
$messageLabel.Size = New-Object System.Drawing.Size(150, 22)

$messageInput = New-Object System.Windows.Forms.TextBox
$messageInput.Location = New-Object System.Drawing.Point(18, 144)
$messageInput.Size = New-Object System.Drawing.Size(774, 72)
$messageInput.Multiline = $true
$messageInput.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$messageInput.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = 'Save lock'
$saveButton.Location = New-Object System.Drawing.Point(18, 228)
$saveButton.Size = New-Object System.Drawing.Size(112, 32)

$listLabel = New-Object System.Windows.Forms.Label
$listLabel.Text = 'Saved paths'
$listLabel.Location = New-Object System.Drawing.Point(18, 278)
$listLabel.Size = New-Object System.Drawing.Size(150, 22)

$lockList = New-Object System.Windows.Forms.ListView
$lockList.Location = New-Object System.Drawing.Point(18, 303)
$lockList.Size = New-Object System.Drawing.Size(774, 270)
$lockList.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$lockList.View = [System.Windows.Forms.View]::Details
$lockList.FullRowSelect = $true
$lockList.MultiSelect = $false
$lockList.HideSelection = $false
$lockList.Columns.Add('File path', 460) | Out-Null
$lockList.Columns.Add('Popup message', 290) | Out-Null

$openButton = New-Object System.Windows.Forms.Button
$openButton.Text = 'Show saved message in app'
$openButton.Location = New-Object System.Drawing.Point(18, 588)
$openButton.Size = New-Object System.Drawing.Size(220, 34)
$openButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left

$removeButton = New-Object System.Windows.Forms.Button
$removeButton.Text = 'Remove lock'
$removeButton.Location = New-Object System.Drawing.Point(250, 588)
$removeButton.Size = New-Object System.Drawing.Size(120, 34)
$removeButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left

$status = New-Object System.Windows.Forms.Label
$status.Text = 'Opening outside this app shows Windows Access Denied. Select a path and use the button to see your message.'
$status.Location = New-Object System.Drawing.Point(18, 626)
$status.Size = New-Object System.Drawing.Size(774, 20)
$status.ForeColor = [System.Drawing.Color]::DimGray
$status.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
if ($script:StartupWarnings.Count -gt 0) {
    $status.Text = 'Some saved locks could not be enforced. See the error details.'
    [System.Windows.Forms.MessageBox]::Show(
        ($script:StartupWarnings -join [Environment]::NewLine),
        'File Lock - Lock enforcement warning',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
}

function Refresh-LockList {
    $lockList.BeginUpdate()
    try {
        $lockList.Items.Clear()
        foreach ($item in $script:Locks) {
            $row = New-Object System.Windows.Forms.ListViewItem($item.Path)
            $row.SubItems.Add(($item.Message -replace '\s+', ' ').Trim()) | Out-Null
            $row.Tag = $item
            $lockList.Items.Add($row) | Out-Null
        }
    }
    finally {
        $lockList.EndUpdate()
    }
}

$browseButton.Add_Click({
    $picker = New-Object System.Windows.Forms.OpenFileDialog
    $picker.Title = 'Choose a file to add'
    $picker.CheckFileExists = $true
    if (-not [string]::IsNullOrWhiteSpace($pathInput.Text)) {
        $picker.FileName = $pathInput.Text
    }
    if ($picker.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $pathInput.Text = $picker.FileName
    }
    $picker.Dispose()
})

$lockList.Add_SelectedIndexChanged({
    if ($lockList.SelectedItems.Count -eq 1) {
        $selected = $lockList.SelectedItems[0].Tag
        $pathInput.Text = $selected.Path
        $messageInput.Text = $selected.Message
    }
})

$saveButton.Add_Click({
    $enteredPath = $pathInput.Text.Trim()
    $enteredMessage = $messageInput.Text.Trim()

    if ([string]::IsNullOrWhiteSpace($enteredPath)) {
        Show-ErrorMessage 'Enter a file path or use Browse.'
        return
    }
    if (-not [System.IO.Path]::IsPathRooted($enteredPath)) {
        Show-ErrorMessage 'Enter an absolute file path.'
        return
    }
    if (-not (Test-Path -LiteralPath $enteredPath -PathType Leaf)) {
        Show-ErrorMessage 'That file does not exist or is not accessible.'
        return
    }
    if ([string]::IsNullOrWhiteSpace($enteredMessage)) {
        Show-ErrorMessage 'Enter the text to show in the popup.'
        return
    }

    $lockResult = $null
    $fullPath = ''
    $storeCommitted = $false
    try {
        $fullPath = [System.IO.Path]::GetFullPath($enteredPath)
        $previousItem = @($script:Locks | Where-Object {
            [string]::Equals($_.Path, $fullPath, [System.StringComparison]::OrdinalIgnoreCase)
        }) | Select-Object -First 1
        $previousSid = ''
        $previousRuleAdded = $false
        if ($null -ne $previousItem) {
            $previousSid = [string]$previousItem.Sid
            $previousRuleAdded = [bool]$previousItem.RuleAdded
        }

        $lockResult = Add-FileLockRule `
            -Path $fullPath `
            -Sid $previousSid `
            -PreviouslyAdded $previousRuleAdded
        $newItem = [pscustomobject]@{
            Path = $fullPath
            Message = $enteredMessage
            Sid = $lockResult.Sid
            RuleAdded = $lockResult.RuleAdded
        }
        $updatedLocks = @($script:Locks | Where-Object {
            -not [string]::Equals($_.Path, $fullPath, [System.StringComparison]::OrdinalIgnoreCase)
        }) + @($newItem)
        Write-Locks -Items $updatedLocks
        $storeCommitted = $true
        $script:Locks = @($updatedLocks)
        Refresh-LockList
        $status.Text = 'Lock saved. Windows blocks this account; the custom message appears only inside File Lock.'
    }
    catch {
        $failure = $_.Exception.Message
        if (-not $storeCommitted -and $null -ne $lockResult -and $lockResult.AddedNow) {
            try {
                Remove-FileLockRule -Path $fullPath -Sid $lockResult.Sid -RuleAdded $true
            }
            catch {
                $failure += [Environment]::NewLine + 'The permission rule was applied but could not be rolled back: ' + $_.Exception.Message
            }
        }
        Show-ErrorMessage $failure
    }
})

$openButton.Add_Click({
    if ($lockList.SelectedItems.Count -ne 1) {
        Show-ErrorMessage 'Select a saved path first.'
        return
    }

    $selected = $lockList.SelectedItems[0].Tag
    [System.Windows.Forms.MessageBox]::Show(
        $form,
        $selected.Message,
        'File locked',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
})

$removeButton.Add_Click({
    if ($lockList.SelectedItems.Count -ne 1) {
        Show-ErrorMessage 'Select a saved path first.'
        return
    }

    $selectedPath = $lockList.SelectedItems[0].Tag.Path
    $selectedItem = $lockList.SelectedItems[0].Tag
    $permissionRuleRemoved = $false
    $storeCommitted = $false
    try {
        $updatedLocks = @($script:Locks | Where-Object {
            -not [string]::Equals($_.Path, $selectedPath, [System.StringComparison]::OrdinalIgnoreCase)
        })
        Remove-FileLockRule `
            -Path $selectedItem.Path `
            -Sid $selectedItem.Sid `
            -RuleAdded ([bool]$selectedItem.RuleAdded)
        $permissionRuleRemoved = [bool]$selectedItem.RuleAdded
        Write-Locks -Items $updatedLocks
        $storeCommitted = $true
        $script:Locks = @($updatedLocks)
        Refresh-LockList
        $pathInput.Clear()
        $messageInput.Clear()
        $status.Text = 'Lock removed; File Lock removed its permission rule.'
    }
    catch {
        $failure = $_.Exception.Message
        if ($permissionRuleRemoved -and -not $storeCommitted) {
            try {
                Add-FileLockRule -Path $selectedItem.Path -Sid $selectedItem.Sid -PreviouslyAdded $true | Out-Null
            }
            catch {
                $failure += [Environment]::NewLine + 'The permission rule could not be restored: ' + $_.Exception.Message
            }
        }
        Show-ErrorMessage $failure
    }
})

$form.Controls.AddRange(@(
    $intro, $pathLabel, $pathInput, $browseButton, $messageLabel,
    $messageInput, $saveButton, $listLabel, $lockList, $openButton,
    $removeButton, $status
))

Refresh-LockList
[System.Windows.Forms.Application]::Run($form)
