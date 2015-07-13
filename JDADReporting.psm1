#Requires -Version 3.0
#Requires -Modules JDTools,activedirectory
<#
$messages = DATA { 
# culture='en-US'
    ConvertFrom-StringData @'
        Verbose_TestConnection = Testing connection to
        Verbose_UseComputer = Starting retrieve information from computer
        Warning_Connection = Computer unavailable:
        Warning_Access = Maybe you are not authorized to receive information from the computer. Either you entered the correct username / password. Access is denied to 
'@
}
Import-LocalizedData -BindingVariable messages 
#>
# http://winitpro.ru/index.php/2013/06/11/audit-izmeneniya-v-active-directory/
$JD_ADReportFolderPath = "$env:systemdrive\ReportFolder"
function Get-ADGroupMembership
{
#.ExternalHelp JDADReporting.Help.xml
    [CmdletBinding(DefaultParameterSetName = 'Group')]
    Param
    (
        [Parameter(ParameterSetName = 'Group', HelpMessage = 'You must specify at least one Active Directory group')]
	    [ValidateNotNull()]
	    [Alias('DN', 'DistinguishedName', 'GUID', 'SID', 'Name')]
	    [string[]]$Group,
	    
        [Parameter(ParameterSetName = 'OU')]
	    [String]$SearchBase,

	    [Parameter(ParameterSetName = 'OU')]
	    [ValidateSet('Base', 'OneLevel', 'Subtree')]
	    [String]$SearchScope,
	
	    [Parameter(ParameterSetName = 'OU')]
	    [ValidateSet('Global', 'Universal', 'DomainLocal')]
	    [String]$GroupScope,
	
	    [Parameter(ParameterSetName = 'OU')]
	    [ValidateSet('Security', 'Distribution')]
	    [String]$GroupType,
	
	    [Parameter()]
	    [Alias('DomainController', 'Service')]
	    [string]$Server,
        
        [Parameter()]
        [String]$ReportFolder = "$JD_ADReportFolderPath",
        
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
        
    )

    Begin
    {    
        $WinEventParam = @{ }
        $ADGroupMemberParam = @{ }
        $ADGroupParams = @{ }
        If ($PSBoundParameters['Server'])
        {
            Write-Verbose -Message "[BEGIN] Testing connection with $Server"
            IF (checkComputerConnection $Server)
            {
                Write-Verbose -Message "[BEGIN] Connection to $Server successful"
                
                $WinEventParam.ComputerName = $Server 
                $ADGroupMemberParam.Server = $Server 
                $ADGroupParams.Server = $Server 
            }
        }
        
        If ($PSBoundParameters['Credential']){ $WinEventParam.Credentials = $ADGroupMemberParam.Credentials =  $ADGroupParams.Credentials = $Credential }
        If ($PSBoundParameters['SearchBase']){ $ADGroupParams.SearchBase = $SearchBase }
        If ($PSBoundParameters['SearchScope']){ $ADGroupParams.SearchScope = $SearchScope }
        If ($PSBoundParameters['GroupScope']){ $ADGroupParams.Filter = "GroupScope -eq `'$GroupScope`'" }
        If ($PSBoundParameters['GroupType']){ "$($ADGroupParams.Filter) -and GroupCategory -eq `'$GroupType`'" }
        If ( ( (-not $PSBoundParameters['GroupScope']) -and (-not $PSBoundParameters['SearchBase']) -and (-not $PSBoundParameters['SearchScope']) `
            -and (-not $PSBoundParameters['GroupType']) -and (-not $PSBoundParameters['Group']) 
             ) -or ( `
                ($PSBoundParameters['SearchBase'] -or $PSBoundParameters['SearchScope']) -and `
                (-not $PSBoundParameters['GroupScope']) -and (-not $PSBoundParameters['GroupType']) 
             ) 
           ) { $ADGroupParams.Filter = '*' }
        
        If ($PSBoundParameters['Group'] -and ( $PSBoundParameters['Credentials'] -or $PSBoundParameters['Server']) )
        { 
            $Groups = $Group | Get-AdGroup @ADGroupParams
            Write-Verbose -Message "[BEGIN] Смотрим параметры групп: $($Groups.Name)"        
        }
        If ($PSBoundParameters['Group'] -and (-not $PSBoundParameters['Credentials']) -and (-not $PSBoundParameters['Server']) )
        {
            $Groups = $Group | Get-AdGroup
            Write-Verbose -Message "[BEGIN] Смотрим параметры групп: $($Groups.Name)"
        }
        If ( -not $PSBoundParameters['Group'] )
        {
            $Groups = Get-ADGroup @ADGroupParams
            Write-Verbose -Message "[BEGIN] Смотрим параметры групп: $($Groups.Name)"
        }
        # Создаем папку если её нет
        If (-not (Test-Path $ReportFolder))
        {
            Write-Verbose -Message "[BEGIN] Создаем $ReportFolder"
            New-item -ItemType directory -Path $ReportFolder -Force | Out-null
        }
    }
    Process
    {
        foreach ($item in $Groups)
        {
            Write-Verbose -Message "[PROCESS] Работаем с группой $($item.Name)"

            $MembersFile = "Members-$($item.Name).csv" # Имя файла учасников группы
            $StateFile = "State-$($item.Name).csv" # Файл Текущего состояния учасников.
            $HistoryFile = "History-$($item.Name).csv" # История измений.

            $ADGroupMemberParam.Identity = $($item.Name)
            $ADGroupMemberParam.Recursive = $true
            Write-Debug "ADGroupMember"
            $ADGroupMember = Get-ADGroupMember @ADGroupMemberParam |
                             Select-Object -Property *,@{ Name = 'DN'; Expression = { $_.DistinguishedName } }
            $ADGroupMember | Select-Object -Property Name, SamAccountName, DN, SID, objectClass | Export-Csv "$ReportFolder\$StateFile" -Encoding UTF8
            If( -not (Test-Path "$ReportFolder\$MembersFile") )
            {
               Write-Verbose -Message "[PROCESS] Отсутсвует файл текущего досупа $ReportFolder\$MembersFile"
               $ADGroupMember | Select-Object -Property Name, SamAccountName, DN, SID, objectClass | Export-Csv "$ReportFolder\$MembersFile" -Encoding UTF8
            }
            # ---
            $MembersCSV = Import-Csv -Path "$ReportFolder\$MembersFile"
            $StateCSV = Import-Csv -Path "$ReportFolder\$StateFile"
            if ($MembersCSV -ne $null)
            {
                Write-Verbose -Message "[PROCESS] Сравниваем участников группы $($item.Name), с текущим состоянем"
                $MemberChanges = Compare-Object -DifferenceObject $MembersCSV -ReferenceObject $StateCSV -Property Name, SamAccountName, DN |
                Select-Object @{ Name = 'DateTime'; Expression = { Get-Date -Format 'yyyyMMdd-HH:mm:ss' } }, @{
	                n = 'State'; e = {
		                IF ($_.SideIndicator -eq '=>') { 'Removed' }
		                ELSE { 'Added' }
	                }
                }, Name, SamAccountName, DN 
            }
            Write-Verbose -Message "[PROCESS] Удаляем файл состояния: $ReportFolder\$StateFile"
            Remove-Item -Path "$ReportFolder\$StateFile"
            If($MemberChanges)
            {
                Write-Verbose -Message "[PROCESS] Есть изменения в группe $($item.Name)"
                foreach ($change in $MemberChanges)
                {
                    $DateTime = [datetime]::ParseExact("$($Change.DateTime)", 'yyyyMMdd-HH:mm:ss', $null)
                    #$DateTime.AddMinutes(-1)
                    switch ($item.GroupScope)
                    {
                        'DomainLocal' { If ($change.State -eq 'Removed'){$ID = '4733'}
                                    elseif ($change.State -eq 'Added'){$ID = '4732'} 
                                    Write-Verbose -Message "[PROCESS] Тип группы:DomainLocal; ID:$ID" }
                        'Global' { If ($change.State -eq 'Removed'){$ID = '4729'}
                               elseif ($change.State -eq 'Added'){$ID = '4728'} 
                               Write-Verbose -Message "[PROCESS] Тип группы:Global; ID:$ID"}
                        'Universal' { If ($change.State -eq 'Removed'){$ID = '4757'}
                                  elseif ($change.State -eq 'Added'){$ID = '4756'} 
                                  Write-Verbose -Message "[PROCESS] Тип группы:Universal; ID:$ID"}
                    }
                    Write-Debug '[PROCESS] Testing WinEvents'
                    $WinEventParam.FilterHashtable = @{Logname = 'Security';
                                                                   Id = $ID;
                                                            StartTime = $DateTime.AddMinutes(-1);
                                                              EndTime = $DateTime }
                    $Events = Get-WinEvent @WinEventParam 
                    # Parse out the event message data            
                    foreach ($Event in $Events) {            
                        # Convert the event to XML            
                        $eventXML = [xml]$Event.ToXml()            
                        # Iterate through each one of the XML message properties            
                        For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                            # Append these as object properties       
                            Add-Member -InputObject $Event -MemberType NoteProperty -Force `
                                -Name  $eventXML.Event.EventData.Data[$i].name `
                                -Value $eventXML.Event.EventData.Data[$i].'#text'            
                        }            
                    }
                    $MemberName = $change.DN
                    $Event = $Events | Where-Object MemberName -EQ $MemberName
                    Add-Member @{UserSidThatMadeChanges = $($Event.SubjectUserSid);
                                UserNameThatMadeChanges = $($Event.SubjectUserName);
                              UserDomainThatMadeChanges = $($Event.SubjectDomainName)} -InputObject $change -Force
                }#END foreach
                $props = @{ 'GroupName' = $($item.Name)
                    'DistinguishedName' = $($item.DistinguishedName)
                        'GroupCategory' = $($item.GroupCategory)
                           'GroupScope' = $($item.GroupScope)
                          'ObjectClass' = $($item.ObjectClass )
                           'ObjectGUID' = $($item.ObjectGUID)
                       'SamAccountName' = $($item.SamAccountName)
                                  'SID' = $($item.SID)
                              'Members' = $MemberChanges
                        'HistorySwitch' = $false
                       'MembersCsvPath' = "$ReportFolder\$MembersFile"
                       'HistoryCsvPath' = "$ReportFolder\$HistoryFile" }
                    
                $obj = New-Object PSObject -Property $props
                $obj.psobject.typenames.insert(0,'Report.ADGroupMember')
                Write-Output $obj
                
                
                Write-Verbose "[PROCESS] Write changes in to $ReportFolder\$MembersFile"
                $ADGroupMember | Export-Csv "$ReportFolder\$MembersFile" -Encoding UTF8
               
                Write-Verbose "[PROCESS] Write changes in to $ReportFolder\$HistoryFile"
                $MemberChanges | Export-Csv "$ReportFolder\$HistoryFile" -Encoding UTF8 -Append
            }
            else
            {
                Write-Verbose "No changes in $($item.Name) found" -Verbose
            }
        }
    }
}

function Get-ADGroupMembershipHistory
{
#.ExternalHelp JDADReporting.Help.xml
    [CmdletBinding(DefaultParameterSetName = 'Group')]
    Param
    (
        [Parameter()]
        [String]$ReportFolder = $JD_ADReportFolderPath,
        [Parameter()]
        [Alias('DN', 'DistinguishedName', 'GUID', 'SID', 'Name')]
	    [string[]]$Group

    )

    if ($PSBoundParameters['Group'])
    {
        try
        {
            $Groups = $Group | Get-ADGroup -ErrorAction Stop
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "OOPS! Group $Group dosen't exists"
        }
        
        foreach ($GroupItem in $Groups)
        {
            [string[]]$CSVFiles += Get-ChildItem -Name $ReportFolder -Filter "History-$($GroupItem.Name).csv" -File
        }
    }
    else
    {
        [string[]]$CSVFiles = Get-ChildItem -Name $ReportFolder -Filter History-*.csv
    }
    foreach ($file in $CSVFiles)
    {
        try
        {
            $GroupObj = Get-ADGroup ($file -replace 'History-' -replace '.csv') -ErrorAction Stop
        }catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
            Write-Warning "OOPS! Group $GroupObj dosen't exists"
        }
                
        $History = Import-CSV -Path "$ReportFolder\$file"
        
        $props = @{ 'GroupName' = $($GroupObj.Name)
            'DistinguishedName' = $($GroupObj.DistinguishedName)
                'GroupCategory' = $($GroupObj.GroupCategory)
                   'GroupScope' = $($GroupObj.GroupScope)
                  'ObjectClass' = $($GroupObj.ObjectClass )
                   'ObjectGUID' = $($GroupObj.ObjectGUID)
               'SamAccountName' = $($GroupObj.SamAccountName)
                          'SID' = $($GroupObj.SID)
                      'Members' = $History
                'HistorySwitch' = $true
               'HistoryCsvPath' = "$ReportFolder\$File" }
                    
        $obj = New-Object PSObject -Property $props
        $obj.psobject.typenames.insert(0,'Report.ADGroupMembershipHistory')
        Write-Output $obj
    }
}

function ConvertTo-HTMLReport
{
#.ExternalHelp JDADReporting.Help.xml
    [CmdletBinding()]
    Param
    (
        # Справочное описание параметра 1
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        $InputObject
    )
    BEGIN 
    {
        $html = "
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <title>Active Directory Group membership report</title>
            <style>
                #main {
                    margin: 20px auto;

                    font-family: Consolas;
                /*    font-family: Verdana, 'Carier New';*/
                }
                .section {
                    border: 1px solid lightgrey;
                    border-radius: 5px;
                    padding: 0 30px;
                    min-width: 630px;
                    padding-bottom: 20px;
                }
                h1,h2,p {
                    padding:  0px;
                    margin: 0p;
                }
                table {
                    width:90%;
                    text-align:center;
                    border-collapse:collapse;
                    border-bottom:1px solid #E5E5E5;
                    border-top:1px solid #E5E5E5;

                }
                table td {
                    padding:8px 10px;
                    border-right:1px solid #E5E5E5;
                    font-size: 11px
                }
                table tr:hover {
                        background-color:#E6E5FF;
                }
                table th {
                    padding: 8px 5px;
                    color: #1f1f1f;
                    text-align: center;
                    border-right: 1px solid #E5E5E5;
                    font-weight: normal;
                    background: #efefef;
                    font-size: 12px
                }
                table tr {
                    border-left:1px solid #E5E5E5;
                    border-top:1px solid #E5E5E5;
                }

                .Removed {
                    color: red
                }
                .Added {
                    color: Green
                }
                hr {
                    border: 0;
                    height: 1px;
                    width: 80%;
                    background-image: -webkit-linear-gradient(left, #fff, #004080, #fff);
                    background-image: -moz-linear-gradient(left, #fff, #004080, #fff);
                    background-image: -o-linear-gradient (left, #fff, #004080, #fff);
                    background-image: linear-gradient (left, #fff, #004080, #fff);
                }
            </style>
        </head>
        <body>
            <div id='main'>"
    }
    PROCESS
    {
        foreach ($Group in $InputObject )
        {
            $html += " 
            <div class='section'>
                    <h1>Группа: $($Group.GroupName)</h1>
                    <p>Описание Группы: <br>
                    DN: $($Group.DistinguishedName)<br>
                    SID Группы: $($Group.SID)<br>
                    Область действия / Тип:  $($Group.GroupScope) / $($Group.GroupCategory)<br>
                    </p>"
            if (-not $Group.HistorySwitch) 
            {
                 $html +=  '<h2>Изменение доступа.</h2>
                            <em>Произошли следующие изменения:</em> 
                            <table>
                              <tr>
                                <th>DateTime</th>
                                <th>State</th>
                                <th>Name</th>
                                <th>SamAccountName</th>
                                <th>DN</th>
                                <th>Who Made Change</th>
                              </tr>'
            
                foreach($item in $($Members | Where-Object GroupName -eq $($Group.GroupName) ).Members )
                {
                    
                    if ($item.State -eq 'Removed')
                    {
                        $State = 'Removed'
                    }
                    elseif ($item.State -eq 'Added')
                    {
                        $State = 'Added'
                    }
                    $html += "
                        <tr>
                            <td>$($item.DateTime)</td>
                            <td><span class=$State>$State</span></td>
                            <td>$($item.Name)</td>
                            <td>$($item.SamAccountName)</td>
                            <td>$($item.DN)</td>
                            <td>$($item.UserNameThatMadeChanges)</td>
                        </tr>"
                }
                $html += '</table>'
            }
            $html += '
                <h2>История изменений.</h2>
                <em>Список предыдущих изменений участия в этой группы</em>
                    <table>
                        <tr>
                            <th>DateTime</th>
                            <th>State</th>
                            <th>Name</th>
                            <th>SamAccountName</th>
                            <th>DN</th>
                            <th>Who Made Change</th>
                        </tr>'
            # История изменений
            $HistoryCSV = Import-CSV -Path $($Group.HistoryCsvPath)
            foreach ($item in $HistoryCSV)
            {
                if ($item.State -eq 'Removed')
                {
                    $State = 'Removed'
                }
                elseif ($item.State -eq 'Added')
                {
                    $State = 'Added'
                }
                $html += "
                    <tr>
                        <td>$($item.DateTime)</td>
                        <td><span class=$State>$State</span></td>
                        <td>$($item.Name)</td>
                        <td>$($item.SamAccountName)</td>
                        <td>$($item.DN)</td>
                        <td>$($item.UserNameThatMadeChanges)</td>
                    </tr>"
            }
            $html += '
                </table>
            </div>
            <hr>'
        }
    }
    END
    {
        $html += '
            </div>
        </body>
        </html>
        '
        Write-Output $html
    }
}

function Get-UserLogon
{
<#
.Synopsis
    Собираем пользователей, которые вошли в систему на указанных компьютерах.
.DESCRIPTION
    Собираем пользователей которые вошли в систему на указанных компьютерах.
.EXAMPLE
    Get-adcomputer -LDAPFilter "(name=ws-dn*)" | Select @{label='computername';expression={$_.Name}}| Get-UsersLogon
.EXAMPLE
    	Get-UsersLogon -ComputerName (gc $env:SystemDrive\hostlist.txt)
	   
		Description
    	-----------
		
#>
    [CmdletBinding()]
    Param
    (
        [Parameter( ValueFromPipelineByPropertyName=$true,
                    ValueFromPipeline=$True,
                    Position=0)]
        [string[]]$ComputerName = 'localhost',
        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )
    Begin
    {
	    $WMIObjParam =@{ }
        If ($PSBoundParameters['ComputerName']){ $WMIObjParam.ComputerName = $ComputerName }
        If ($PSBoundParameters['Credential']){ $WMIObjParam.Credential = $Credential }
        $WMIObjParam.Class = 'Win32_ComputerSystem'
    }
    Process
    {
	    Foreach ($Computer in $ComputerName) 
	    {
	        # проверяем доступность хоста
	        if ( checkComputerConnection $Computer ) 
	        {
	            Write-Verbose "$computer UP"
                Write-Debug 'Debug'
	            # выполняем WMI запрос
	            $hostname = Get-WmiObject @WMIObjParam
	            $userName = $HostName.UserName

	            # выводим результат в на экран и в файл
	            Write-Host "$computer – $userName"
	        }
	        else 
	        {
	            Write-Warning "$Computer DOWN"
	        }
	    }
    }
    End{}
}# function end

function checkComputerConnection ($Computer)
{
    $works = $true
    Write-Verbose "$($messages.Verbose_TestConnection) $Computer"
    if (Test-Connection -ComputerName $Computer -Count 2 -Quiet)
    {
        try
        {
            Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop | Out-Null
        }
        catch
        {
            $works=$false
        }
    }
    else
    {
       $works=$false
    }
    return $works
}

Export-ModuleMember -Function 'Get-ADGroupMembershipHistory', 'ConvertTo-HTMLReport', 'Get-ADGroupMembership', 'Get-UserLogon'