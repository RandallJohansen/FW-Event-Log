

        ##################################
        #  ATTN!: for NON-admin account  #
        ##################################
<#

    no need to be in "Event Log Readers" group, does not help anyway
    
    but must regedit this key:
    
    Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security
    
    1)  right-click -> permissions

    2)  add user account with read permission






    windows cli event log utility 
    -----------------------------


    # will dump entire log
    
    wevtutil qe security     



    # three most recent events from the Security log in textual format

    wevtutil qe security /c:3 /rd:true /f:text




    wevtutil qe /?            

    wevtutil parameters:

        qe -OR- query-events
    
        <Path>    e.g. Security
    
        [/lf:<Logfile>] 
        [/sq:<Structquery>] 
        [/q:<Query>] 
        [/bm:<Bookmark>] 
        [/sbm:<Savebm>] 
        [/rd:<Direction>] 
        [/f:<Format>] 
        [/l:<Locale>] 
        [/c:<Count>] 
        [/e:<Element>]

#>
                
                
<#

Message              : The Windows Filtering Platform has blocked a connection.

                       Application Information:
                        Process ID:             3620
                        Application Name:       \device\harddiskvolume3\windows\system32\svchost.exe

                       Network Information:
                        Direction:              Outbound
                        Source Address:         192.168.0.77
                        Source Port:            59492
                        Destination Address:    23.55.248.61
                        Destination Port:               443
                        Protocol:               6

                       Filter Information:
                        Filter Run-Time ID:     77767
                        Layer Name:             Connect
                        Layer Run-Time ID:      48
Id                   : 5157
Version              : 1
Qualifiers           :
Level                : 0
Task                 : 12810
Opcode               : 0
Keywords             : -9218868437227405312
RecordId             : 1235679
ProviderName         : Microsoft-Windows-Security-Auditing
ProviderId           : 54849625-5478-4994-a5ba-3e3b0328c30d
LogName              : Security
ProcessId            : 4
ThreadId             : 7856
MachineName          : DESKTOP-RJ2F399
UserId               :
TimeCreated          : 2/1/2021 4:39:35 PM
ActivityId           :
RelatedActivityId    :
ContainerLog         : Security
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Filtering Platform Connection
KeywordsDisplayNames : {Audit Failure}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty...}




System.Diagnostics.Eventing.Reader.EventBookmark


Value : 3620

Value : \device\harddiskvolume3\windows\system32\svchost.exe

Value : %%14593

Value : 192.168.0.77

Value : 59492

Value : 23.55.248.61

Value : 443

Value : 6

Value : 77767

Value : %%14611

Value : 48

Value : S-1-0-0

Value : S-1-0-0

#>                        
                ################
                #              #
                #  PARAMETERS  #
                #              #
                ################
                #region begin  

<#   paramter examples
     -----------------
   
    $DefaultServer = "http://google.com"
   
    $PasswdPrompt = $( Read-Host "Input password, please" )
  
    # assign default values, read from console if not available, stop script execution
  
    [string]$server = $DefaultServer ,
        
    [string]$password = $PasswdPrompt ,
  
    [Parameter(Mandatory = $true)] [string]$directory ,       <== will prompt if not provided
#>


# 
# # [switch] is parms with $false default,  cli presense = true  ( -allowed ), or enforce "not present" like so: -allowed:$false
# 
#  param(
# 
#     [switch]$blocked  ,
# 
#     [switch]$allowed  ,
# 
#     [switch]$outbound ,
# 
#     [switch]$inbound
#  
#  )
# 
# 
#  if( -not ( ( $blocked -or  $allowed ) -and ( $outbound -or $inbound ) ) ) {  
#  
#         write-host ' Syntax:    -blocked &| -allowed     -outbound &| -inbound '
#  
#         write-host 'Exiting in 30 seconds '
#      
#         sleep -s 30
#      
#         exit
#         
#  } 
#  
# 
# 
# 
# $EventId = @()
# 
# if( $allowed ) { $EventId += 5156 }
# 
# if( $blocked ) { $EventId += 5157 }
# 
#  
# 
# 
# $Direction = @()
# 
# if( $outbound ) { $Direction += "Outbound" }
# 
# if( $inbound ) { $Direction += "Inbound" }
# 




################## TESTING #############################
$EventId = @( 5156 , 5157 )
$Direction = @( "Outbound" , "Inbound" )
################### TESTING #############################


           

#endregion
             



                ################
                #              #
                #     INIT     #
                #              #
                ################




$DefaultVariables = $(Get-Variable).Name   # gets state of variables before script is run, for cleanup at very end





#region begin  console screen stuff


[console]::Title = ( "Events {0}" -f $(  get-date -Format "MMM d  h:mm p" ) )


# $ConsoleBufferWidth = 500                      # Auto-sized tables are limited to the width of screen buffer
# 
# [console]::BufferWidth = $ConsoleBufferWidth
#
# [console]::Bufferheight = 1000
#
# $host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(160,5000)   # last line displayed issues....


 [console]::WindowWidth  = 125          
# 
# [console]::WindowHeight  = 50



# admin prompt, make it red

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )

if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
{

         [console]::backgroundColor  = 'Red'        # elevated reminder
 
         clear-host

} else {

         [console]::backgroundColor  = 'DarkGray'  # I have a custom color of light blue in this color
 
         clear-host

} # else


#endregion




#region begin  variables, psuedo constants


$dtMaxRows = 700

$BatchSize = 64  # 256 max
$MaxEvents = $BatchSize
        
$CutOffTime = (Get-Date).AddSeconds(-5)   # initially go back some


# kind of cheating, but better than cluttering with constant having to pass to function
$script:ConsoleStats   = ''
$script:DispositionStats = ''


#$PerInterface = Get-DnsClientServerAddress                                                    # array of objects
#$DnsServers = $PerInterface.ServerAddresses | Select-String -Pattern  '\d\.' | % { $_.Line }  # array of strings, only ipv4
#   -OR-
$DnsServers = Get-DnsClientServerAddress | % { $_.ServerAddresses }                           # array of strings

# note: can combine two arrays into a third $c = $a + $b

$IgnoreDest = @( '18.191.49.147' , '77.55.235.217' , '127.0.0.1' , '0.0.0.0' , '::' , '::1' )  # AWS, geo

# could do a one dimensional combine by doing this (but don't want to ignore dns):   $IgnoreDest = @( '18.191.49.147' , ... ) + $DnsServers


$IgnoreApp = @(      )#      'wermgr.exe' , 'localbridge.exe' , 'microsoftedgeupdate.exe' , 'yourphone.exe' , 'microsoft.photos.exe' )

$IgnoreSvc = @( 'FileZilla Server'     )#      'Dnscache' , 'wisvc' , 'SSDPSRV' )


$OtherCountries = @( 'China' )


$DnsCacheFwd = @{}   # forward lookups from cache
$DnsCacheRev = @{}   # reverse lookups from cache




$Days = @{          # hi/lo timestamp markers for each of the days processed, key is date, value is timestamp

    $( '{0:MM:dd:yy}' -f $CutOffTime ) = [pscustomobject]@{   
                
                                        # initially, for this day, oldest and newest are same

                                        LoStamp  = $CutOffTime
                                        LoRecord = 0
                                        HiStamp  = $CutOffTime
                                        HiRecord = 0
    } # PSCustomObject
}




$PrettyProtocols = @{

        '1'  =  'ICMP'        # Internet Control Message Protocol (ICMP)
                        
        '2'  =  'IGMP'        # Internet Group Management Protocol (IGMP)
                         
        '6'  =  'TCP'         # Transmission Control Protocol (TCP)
                         
       '17'  =  'UDP'         # User Datagram Protocol (UDP)
                        
       '47'  =  'PPTP'        # General Routing Encapsulation (PPTP data over GRE)
                        
       '51'  =  'AH/IPSec'    # Authentication Header (AH) IPSec
            
       '50'  =  'ESP/IPSec'   # Encapsulation Security Payload (ESP) IPSec
             
        '8'  =  'EGP'         # Exterior Gateway Protocol (EGP)
            
        '3'  =  'GGP'         # Gateway-Gateway Protocol (GGP)
             
       '20'  =  'HMP'         # Host Monitoring Protocol (HMP)
            
       '66'  =  'RVD'         # MIT Remote Virtual Disk (RVD)
                                           
       '88'  =  'EIGRP'       # EIGRP Extended Internet Gateway Routing Protocol
            
       '89'  =  'OSPF'        # OSPF Open Shortest Path First
                         
       '12'  =  'PUP'         # PARC Universal Packet Protocol (PUP)
                         
       '27'  =  'RDP'         # Reliable Datagram Protocol (RDP)
                         
       '46'  =  'RSVP'        # Reservation Protocol (RSVP) QoS
             
}


$PrettyEventId = @{


      '5156' = 'Allowed' 

      '5157' = 'Blocked' 
  
} 




$Tab = [char]9                            # also ok to use a 'backtick' like -> `t

$OutputRow = [ordered]@{}                 # temporary storage to build row of output

$Paths = @{}                              # temporary storage to hold paths to multiple copies seen for one executable


$FlagsHash = @{}                          # temp storage of datatable column to hold updates for existing rows
$HitsHash = @{}                           # temp storage of datatable column to hold updates for existing rows
$TimeHash = @{}                           # temp storage of datatable column to hold updates for existing rows
$PrevRowCount = 0                         # register for reporting
$PrevHitCount = 0                         # register for reporting


$pendingestRecordId = 0                       # s/n of event to avoid dups
$Deadlock = 'no'                          # indicator for console monitoring output
$PrevRecordId = 7                         # register to store temp data, cast/init w/value won't match accidently
$PrevEventCount = 0                       # register to store temp data, cast/init



#endregion




#region begin  message processing structures


<#
    Message              : The Windows Filtering Platform has permitted a connection.
    
                           Application Information:
                            Process ID:             2804
                            Application Name:       \device\harddiskvolume3\windows\system32\svchost.exe
    
                           Network Information:
                            Direction:              Outbound
                            Source Address:         192.168.0.67
                            Source Port:            58641
                            Destination Address:    68.105.28.11
                            Destination Port:               53
                            Protocol:               17
    
                           Filter Information:
                            Filter Run-Time ID:     66529
                            Layer Name:             Connect
                            Layer Run-Time ID:      48
    Id                   : 5156
    Version              : 1
    Qualifiers           :
    Level                : 0
    Task                 : 12810
    Opcode               : 0
    Keywords             : -9214364837600034816
    RecordId             : 695640
    ProviderName         : Microsoft-Windows-Security-Auditing
    ProviderId           : 54849625-5478-4994-a5ba-3e3b0328c30d
    LogName              : Security
    ProcessId            : 4
    ThreadId             : 5392
    MachineName          : DESKTOP-LG64QR0
    UserId               :
    TimeCreated          : 12/16/2020 2:49:48 PM
    ActivityId           :
    RelatedActivityId    :
    ContainerLog         : Security
    MatchedQueryIds      : {}
    Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
    LevelDisplayName     : Information
    OpcodeDisplayName    : Info
    TaskDisplayName      : Filtering Platform Connection
    KeywordsDisplayNames : {Audit Success}
    Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty,
                           System.Diagnostics.Eventing.Reader.EventProperty...}
#>



# data dictionary  ==> also acts as cli output, and dbase loading with ordering

$Fields = [ordered]@{

        “Tuple”         =   “ "
                           
        “LastUpdated”   =   “ "            
                           
        “Rule”          =   “Filter Run-Time ID" 
                           
  #      "FilterOrigin"  =   " "     # Get-NetFirewallRule -Name " {A549B7CF-0542-4B67-93F9-EEBCDD584377} "
                           
  #      “RecordId”      =   “ "    # unique, not useful for aggregated stats being displayed        
                           
        “HitCount”      =   “ "            
                           
        “Action”        =   “ "            
                           
        “Direction”     =   “Direction”
                           
        “PIDx”          =   “Process ID”
                           
        “UserName”      =   “ "                        # ( needs get-WmiObject .Name or get-process -IncludeUserName ) requires elevated user rights
                                    
        “sPort”         =   “Source Port”
                           
        “Source”        =   “Source Address”
                           
        “Protocol”      =   “Protocol”
                           
        “dPort”         =   “Destination Port”
                           
        “Destination”   =   “Destination Address”
                           
        “HostName”      =   “ "            
                           
        “Domain”        =   “ "            
                           
        “Country”       =   “ "            
                              
        “App”           =   “Application Name”
                           
        “Svc”           =   “ "                       # ( needs get-WmiObject .user ) requires elevated user rights
                           
        “Flags”         =   “ "            
                           
        “DisplayName”   =   “ "            
                           
        “FilePath”      =   “ "            
}




$dt = New-Object System.Data.Datatable     # actual db
$dtw = New-Object System.Data.Datatable    # working copy for off screen adds ( note: updates are the real problem, but can't 'merge' w/identical keys)

$Numerics = @( “HitCount” , “PIDx” , “sPort”  , “dPort” )       # cannot put 0 ( or any numeric ) in ordered hash dictionary, messes with message parse

$Fields.Keys.ForEach( { 

        if( $Numerics -contains $_ ) { [void]$dt.Columns.Add( "$_" , [int] )   

                                       [void]$dtw.Columns.Add( "$_" , [int] )

        } else {                       [void]$dt.Columns.Add( "$_" )

                                       [void]$dtw.Columns.Add( "$_" )

        } 
} )

$dt.Columns["Tuple"].ColumnMapping = 4 # MappingType Hidden

# $dt.DefaultView.Sort = 'Action DESC , Direction ASC , Source DESC , App DESC , Svc ASC , dPort DESC , Destination ASC'

$dv = New-Object System.Data.DataView($dt)
$dv.RowStateFilter = 30     # Deleted 8  + CurrentRows 22 Current rows including unchanged, new, and modified rows (default)
                              	

#endregion



                        
                ################
                #              #
                #  FUNCTIONS   #
                #              #
                ################

#region begin  



function UpdateStatusBar {

        Param(
                [switch] $HideConsoleStats ,

                $Op   = ''  ,

                $Step = ''  ,

                $Min  = 0   ,
        
                $Max  = 100 ,
        
                $Val  = 0
        )
        

        if( $form.Visible ) {



                if ( -not $HideConsoleStats ) { 
        
                        $StatusBarConsoleStats.Text = $script:ConsoleStats
                
                        $StatusBarDispositionStats.Text = $script:DispositionStats 

                } # if



                $StatusBarOperation.Text = $Op

                $StatusBarProgress.Text = $Step

                $ProgressBar.Minimum = $Min

                $ProgressBar.Maximum = $Max



                $ProgressBar.Value = $Val
                
                if ( $Val ) { $ProgressBar.Visible = $true 

                } else { $ProgressBar.Visible = $false }
        }
}




function ConsoleErrorMessage {



            # take over error reporting
            # command must use option:  -ErrorAction Stop




            # [enum]::GetValues([System.ConsoleColor]) | Foreach-Object {Write-Host $_ -ForegroundColor $_}
            

            <#  PS D:\4836 snapshots\AMDV10818-S4\192.168.0.7> $error[0] | gm
             
             
                TypeName: System.Management.Automation.ErrorRecord
             
             Name                  MemberType     Definition                                                                                                         
             ----                  ----------     ----------                                                                                                         
             Equals                Method         bool Equals(System.Object obj)                                                                                     
             GetHashCode           Method         int GetHashCode()                                                                                                  
             GetObjectData         Method         void GetObjectData(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingCo...
             GetType               Method         type GetType()                                                                                                     
             ToString              Method         string ToString()                                                                                                  
             CategoryInfo          Property       System.Management.Automation.ErrorCategoryInfo CategoryInfo {get;}                                                 
             ErrorDetails          Property       System.Management.Automation.ErrorDetails ErrorDetails {get;set;}                                                  
             Exception             Property       System.Exception Exception {get;}                                                                                  
             FullyQualifiedErrorId Property       string FullyQualifiedErrorId {get;}                                                                                
             InvocationInfo        Property       System.Management.Automation.InvocationInfo InvocationInfo {get;}                                                  
             PipelineIterationInfo Property       System.Collections.ObjectModel.ReadOnlyCollection[int] PipelineIterationInfo {get;}                                
             ScriptStackTrace      Property       string ScriptStackTrace {get;}                                                                                     
             TargetObject          Property       System.Object TargetObject {get;}                                                                                  
             PSMessageDetails      ScriptProperty System.Object PSMessageDetails {get=& { Set-StrictMode -Version 1; $this.Exception.InnerException.PSMessageDetai...

            #> # $error[0]

            <# PS D:\4836 snapshots\AMDV10818-S4\192.168.0.7> $error[0].InvocationInfo | gm
             
             
            TypeName: System.Management.Automation.InvocationInfo
             
            Name                  MemberType Definition                                                                          
            ----                  ---------- ----------                                                                          
            Equals                Method     bool Equals(System.Object obj)                                                      
            GetHashCode           Method     int GetHashCode()                                                                   
            GetType               Method     type GetType()                                                                      
            ToString              Method     string ToString()                                                                   
            BoundParameters       Property   System.Collections.Generic.Dictionary[string,System.Object] BoundParameters {get;}  
            CommandOrigin         Property   System.Management.Automation.CommandOrigin CommandOrigin {get;}                     
            DisplayScriptPosition Property   System.Management.Automation.Language.IScriptExtent DisplayScriptPosition {get;set;}
            ExpectingInput        Property   bool ExpectingInput {get;}                                                          
            HistoryId             Property   long HistoryId {get;}                                                               
            InvocationName        Property   string InvocationName {get;}                                                        
            Line                  Property   string Line {get;}                                                                  
            MyCommand             Property   System.Management.Automation.CommandInfo MyCommand {get;}                           
            OffsetInLine          Property   int OffsetInLine {get;}                                                             
            PipelineLength        Property   int PipelineLength {get;}                                                           
            PipelinePosition      Property   int PipelinePosition {get;}                                                         
            PositionMessage       Property   string PositionMessage {get;}                                                       
            PSCommandPath         Property   string PSCommandPath {get;}                                                         
            PSScriptRoot          Property   string PSScriptRoot {get;}                                                          
            ScriptLineNumber      Property   int ScriptLineNumber {get;}                                                         
            ScriptName            Property   string ScriptName {get;}                                                            
            UnboundArguments      Property   System.Collections.Generic.List[System.Object] UnboundArguments {get;} 
                         
            #>  # $error[0].InvocationInfo


            write-host   (Get-Date).ToString()                                        -ForegroundColor DarkCyan

            write-host  "Line -->> $( $error[0].InvocationInfo.ScriptLineNumber )"    -ForegroundColor DarkMagenta
            write-host  "Position -->> $( $error[0].InvocationInfo.OffsetInLine )"    -ForegroundColor DarkCyan

            # if no error[0] present, creates error itself:
            #   "You cannot call a method on a null-valued expression"
            #write-host  "GetType -->> $( $error[0].InvocationInfo.GetType() )"       -ForegroundColor DarkMagenta

            write-host "Msg-->> $($error[0].Exception.Message )"                      -ForegroundColor Black


} # ConsoleErrorMessage





Function SuspendTable( ) { 

 #       $CellPtrs = @( $DGV.CurrentCell )                # save current cursor position, default is  1st cell in 1st column, or null if no cells in the control

       # $CellPtrs = $CellPtrs + $DGV.FirstDisplayedCell  # works only with unbound. note: ( typically, cell in the upper left corner)

 #       $CellPtrs = $CellPtrs + $DGV.FirstDisplayedScrollingRowIndex   # also save first row currently displayed 
        $CellPtrs = @( $DGV.FirstDisplayedScrollingRowIndex )  # also save first row currently displayed 

        $DGV.CurrentCell = $null                         # remove the focus cursor, when control receives focus set to FirstDisplayedCell 

        $DGV.SuspendLayout()                             

       # $DGV.Enabled = $false                            # whether the control can respond to user interaction

       # $DGV.DataSource.SuspendBinding - see below


        Return $CellPtrs
} 
 
 



Function ResumeTable( [array]$CellPtrs ) {   # [string[]]

   # NOTES:  when deleting rows, current cell could have disapeared?
   #         using column sort blows up restoring current cell
   
   #     $DGV.CurrentCell = $CellPtrs[0]                 # restore current cursor position

#### alt version = $DGV.CurrentCell = $DGV.Rows[$i].Cells['Name']    

       # $DGV.CurrentCell = $DGV[1,0]                 # Set the current cell to the cell in column 1, Row 0

       # $DGV.FirstDisplayedCell = $CellPtrs[1]          # works only with unbound. note: ( typically, cell in the upper left corner)
          
        if( ( $CellPtrs[1] -gt 0 ) -and ( $CellPtrs[1] -lt $DGV.rows.count ) ) {

  #            $DGV.FirstDisplayedScrollingRowIndex = $CellPtrs[1] } # also set first row currently displayed 
              $DGV.FirstDisplayedScrollingRowIndex = $CellPtrs[0] } # also set first row currently displayed 

       # $DGV.Enabled = $true                            # whether the control can respond to user interaction

        $DGV.ResumeLayout()                             
        
       # $DGV.DataSource.ResumeBinding  - see below 

       # $DGV.Refresh()     # not needed for double buffering, or really anything

        Return 
} 


<#
Using SuspendBinding prevents changes from being pushed into the data source until ResumeBinding is called, 
but does not actually prevent any events from occurring. Controls that use complex data binding, 
such as the DataGridView control, update their values based on change events such as the ListChanged event, 
so calling SuspendBinding will not prevent them from receiving changes to the data source. For this reason, 
this SuspendBinding and ResumeBinding are designed for use with simple-bound controls, such as the TextBox control. 
Alternatively you can use these methods in a complex binding scenario if you suppress ListChanged events by 
setting the RaiseListChangedEvents property to false.
#>
 
 



Function ApplyUpdates( ) { 


        $BtnUpdates.Text = "applying updates"

        UpdateStatusBar -Op "merging new rows"


        $X = SuspendTable



        if( $dtw.Rows.Count -gt 0 ) {

                $dt.Merge($dtw)  # add new

                $dtw.Clear()

        } # if


                                       # ??? $HitsHash[ "$OutputRow.Tuple" ]++ 
        if( $HitsHash.Count -gt 0 ) {

                $i = 0 

                foreach( $key in $FlagsHash.Keys ) {    # note: could have used $HitCountHash, they're always a matched set

                        $i++ ; UpdateStatusBar -Op "updating existing rows" -Max $HitsHash.Count -Val $i

                        [System.Windows.Forms.Application]::DoEvents()

                        if( -not $form.Visible ) { break }

                                                 
                        $existing = $dt.Select( "Tuple = '" + $key + "'" )       # find matching row by tuple in db


                        # row may have been deleted while accumulating stats
                        if( $existing ) {

                                $existing[0]["Flags"]    = ( $( $existing[0]["Flags"] ) , $( $FlagsHash[ $key ] ) -join ' ' ).trim()

                                $existing[0]["HitCount"] = $( $existing[0]["HitCount"] ) + $( $HitsHash[ $key ] )

                                # Write-Host '////////////////////////////////'
                                # Write-Host $( $key )
                                # Write-Host '////////////////////////////////'
                                # Write-Host $HitsHash[ $key ]
                                # Write-Host '\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'
                                # Write-Host $existing[0]["HitCount"]
                                # Write-Host '\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'

                        }

                } # foreach


                $FlagsHash.Clear()

                $HitsHash.Clear()


        } # if



                            
        [void]$dtw.AcceptChanges()
                            
        ResumeTable $X

       
        
        $BtnUpdates.Visible = $false

        $BtnUpdates.SendToBack()

        $BtnUpdates.Text = "updates applied"

        $BtnUpdates.Tag = $False



        Return
} 
 
 



Function TrimTable( ) { 

        $X = SuspendTable

        # limit table size, FIFO

        while( $dt.rows.count -gt $dtMaxRows ) { $dt.Rows.RemoveAt(0) }  # absolute row number, in this case, the first row        
                            
   #     [void]$dt.AcceptChanges()        # RemoveAt is immediate
                            
        ResumeTable $X


        Return
} 





Function DefaultSort( [Switch]$NoJump ) { 



        $X = SuspendTable

        $dv.Sort = 'Action ASC , Direction DESC , Source DESC , App ASC , Svc ASC , dPort DESC , Destination ASC'
 
        ResumeTable $X
       
        if ( $NoJump ) { $NOP++ } else { $DGV.FirstDisplayedScrollingRowIndex = 0 }  # jump to first row to see the results from the beginning
                 

        Return 
} 





Function FilterColumn( [String]$ColName , [String]$FilterValue ) { 

        $X = SuspendTable


        if ( $dv.RowFilter ) { $Append = " AND $($dv.RowFilter)" }

        $dv.RowFilter = "$ColName = '" + $FilterValue + "'" + $Append


        ResumeTable $X

        $DGV.FirstDisplayedScrollingRowIndex = 0   # jump to first row to see the results from the beginning


        Return 
} 
 
 



Function ClearFilter( ) { 

        $X = SuspendTable

        $dv.RemoveFilter()

        ResumeTable $X

        $DGV.FirstDisplayedScrollingRowIndex = 0   # jump to first row to see the results from the beginning


        Return 
} 
 




Function HideColumn( [String]$ColName ) { 

        $X = SuspendTable

        $DGV.Columns[ "$ColName" ].Visible = $false
    #    $dv.Table.Columns.Remove( "$ColName" )
    #    $dt.Columns[ "$ColName" ].ColumnMapping = 4 # MappingType Hidden 

        ResumeTable $X

   #     $DGV.FirstDisplayedScrollingRowIndex = 0   # jump to first row to see the results from the beginning


        Return 
 }




Function ShowAllColumns( ) { 

        $X = SuspendTable

    #    For ( $i = 0 ; $i -lt $DGV.Columns.count ; $i++ ) { $DGV.Columns[ $i ].Visible = $true }
        ForEach ( $ColName in ( $DGV.Columns.name ) ) { $DGV.Columns[ $ColName ].Visible = $true }
    #    $dv.Table.Columns.???( "$ColName" )
    #    $dt.Columns[ "$ColName" ].ColumnMapping = 0 # MappingType ???

        ResumeTable $X

   #     $DGV.FirstDisplayedScrollingRowIndex = 0   # jump to first row to see the results from the beginning


        Return 
} 

 



Function RemoveOccurances( [String]$ColName , [String]$FilterValue ) { 



        # cache rows, can't remove rows while runing select results direct into a pipeline

        $RowsToDelete = $dt.Select( "$ColName = '" + $FilterValue + "'" )    # returns array of "System.Data.DataRow[]" i.e. $row




        if( $RowsToDelete.Count -gt 0 ) { 


                # save filter

                $RowFilter = $dv.RowFilter

                # make it a secondary filter
                if( $RowFilter ) { $RowFilter = " AND " + $RowFilter }

                # hide the rows to be deleted

                $dv.RowFilter = "$ColName <> '" + $FilterValue + "'" + $RowFilter


                $X = SuspendTable




         #        # in conjunction with a DataAdapter and a relational data source, use the Delete method
         #
         #       $RowsToDelete | % {     
         #
         #               $_.Delete()           # mark as deleted
         #
         #              [System.Windows.Forms.Application]::DoEvents()
         #
         #       } # RowsToDelete
         #
         #       [void]$dt.AcceptChanges()     # commit





                # in conjunction with a DataAdapter and a relational data source, use the Delete method

                for( $i = 0 ; $i -lt $RowsToDelete.count ; $i++ ) { 
                
                        $RowsToDelete[$i].Delete()                        # mark as deleted

                        [System.Windows.Forms.Application]::DoEvents()
         
                } # for

                [void]$dt.AcceptChanges()                                 # commit
         
         
         
         
         
         #       for( $i = 0 ; $i -lt $RowsToDelete.count ; $i++ ) { $dt.rows.Remove($RowsToDelete[$i]) }
         
         
         
         
         
         #       $RowsToDelete | % { 
         #       
         #               $dt.rows.Remove($_)   # immediately delete 
         #
         #               [System.Windows.Forms.Application]::DoEvents()
         #
         #       } # RowsToDelete


                      

                ResumeTable $X

                
                # restore the original filter
                $dv.RowFilter = $RowFilter   

        
        } # if


        $DGV.FirstDisplayedScrollingRowIndex = 0   # jump to first row to see the results from the beginning


        Return 
      
} 

<#        
  $dt.Rows.RemoveAt(0)                  # absolute row number, in this case, the first row
 
         -OR-
                                        # do delete by search value
  $asdf = $dt.Select("colname = value") # returns array of "System.Data.DataRow[]" i.e. $row
  $dt.rows.Remove($asdf[0])             # delete first match (1st member of array)
 
         -OR-
 
  $asdf.Delete()                        # mark as deleted 
  dataTable.AcceptChanges()             # actually delete
 
  note:  Delete should not be called in a foreach loop while directly iterating through a 
         DataRowCollection object. Delete modifies the state of the collection.
#>
 
 



Function ConvertTo-BinaryIP( [String]$IP ) { 

  $IPAddress = [Net.IPAddress]::Parse($IP) 
 
  Return [String]::Join('.', $( $IPAddress.GetAddressBytes() | %{ 

            [Convert]::ToString($_, 2).PadLeft(8, '0') 
      
      } )) 
} 
 
 



Function IsPrivateNetwork( [String]$IP)  
{ 

    If ($IP.Contains("/"))   # strip off cidr bit count, e.g. /24
  {
        $Temp = $IP.Split("/") 
        $IP = $Temp[0] 
    } 
   


    [string]$BinaryIP = ConvertTo-BinaryIP $IP



    $Subnet = ' '
    
    Switch -RegEx ($BinaryIP) {

            '^01100100\.01'                  { $Subnet = '* 100.64.0.0/10'   ; $Class = 'A' }
                                               
            '^00000000\.'                    { $Subnet = '* 0.0.0.0/8'       }
                                               
            '^00001010\.'                    { $Subnet = '* 10.0.0.0/8'      }
                                               
            '^01111111'                      { $Subnet = '* 127.0.0.0/8'     }
                                               
                                               
            '^10101001\.11111110'            { $Subnet = '* 169.254.0.0/16'  ; $Class = 'B' } 
                                               
            '^10101100\.0001'                { $Subnet = '* 172.15.0.0/12'   }
                                               
                                               
            '^11000000\.00000000\.00000000'  { $Subnet = '* 192.0.0.0/24'   ;  $Class = 'C' }  
                                               
            '^11000000\.00000000\.00000010'  { $Subnet = '* 192.0.2.0/24'    }
                                               
            '^11000000\.01011000\.01100011'  { $Subnet = '* 192.88.99.0/24'  }
                                               
            '^11000110\.00110011\.01100100'  { $Subnet = '* 198.51.100.0/24' }
                                               
            '^11001011\.00000000\.01110001'  { $Subnet = '* 203.0.113.0/24'  }
                                               
            '^11000000\.10101000'            { $Subnet = '* 192.168.0.0/16'  }
                                               
            '^11000110\.0001001'             { $Subnet = '* 198.18.0.0/15'   }
                                               
                                               
            '^1110'                          { $Subnet = '* multicast'       ; $Class = 'D' }
                                               
                                               
            '^1111'                          { $Subnet = '* experimental'   ;  $Class = 'E' }  
                                               
                                               
             default                         { $Subnet = 'Public'            }

    }  # Switch


    # Write-Host "$BinaryIP   $IP   $Subnet"


    return $Subnet 
}

    <#

    RFC 6890 
    --------
                                   higher order bits 1st octet 
      1.x.x.x – 126.x.x.x          0                                    class A                                         /8
    128.0.x.x – 191.255.x.x        10                                   class B                                         /16
    192.0.0.x – 223.255.255.x      110                                  class C                                         /24
    224.0.0.0 – 239.255.255.255    1110                                 class D - multi-cast                            /
    240.0.0.0 – 255.255.255.254    1111                                 class E - reserved experimental & research      /4
         255.255.255.255           11111111.11111111.11111111.11111111  Limited Broadcast                               /32                 

    IP address range                                                    RFC1918 name    classful description     largest CIDR block    (subnet mask)    number of addresses   host id size
      10.0.0.0 – 10.255.255.255    00001010                             24-bit block    single class A               10.0.0.0/8         (255.0.0.0)         16,777,216         24 bits
     172.16.0.0 – 172.31.255.255   10101100.0001                        20-bit block    16 contiguous class Bs     172.16.0.0/12        (255.240.0.0)        1,048,576         20 bits
    192.168.0.0 – 192.168.255.255  11000000.10101000                    16-bit block    256 contiguous class Cs    192.168.0.0/16       (255.255.0.0)           65,536         16 bits
                                                                    
     100.64.0.0 - 100.127.255.255  01100100.01 - 01100100.01            local communications w/in a private network 100.64.0.0/10              
                                                                    
       0.0.0.0 – 0.255.255.255     00000000                             used to communicate w/in the current network 0.0.0.0/8      
     127.0.0.0 – 127.255.255.255   01111111                             Loop-back addresses                         127.0.0.0/8    
    169.254.0.0 – 169.254.255.255  10101001.11111110                    Link local addresses                       169.254.0.0/16 
      192.0.0.0 – 192.0.0.255      11000000.00000000.00000000           IETF Protocol Assignments                   192.0.0.0/24   
      192.0.0.0 – 192.0.0.7        11000000.00000000.00000000.00000     DS-Lite                                     192.0.0.0/29   
      192.0.2.0 – 192.0.2.255      11000000.00000000.00000010           Documentation (TEST-NET-1)                  192.0.2.0/24   
    192.88.99.0 – 192.88.99.255    11000000.01011000.01100011           6to4 Relay Anycast                          192.88.99.0/24 
     198.18.0.0 – 198.18.0.255     11000110.0001001                     Benchmarking                                198.18.0.0/15
    198.51.100.0 – 198.51.100.255  11000110.00110011.01100100           Documentation (TEST-NET-2)                  198.51.100.0/24
    203.0.113.0 – 203.0.113.255    11001011.00000000.01110001           Documentation (TEST-NET-3)                  203.0.113.0/24



    #>
  
 



function SetPriority() {

        param (

            [string]$ProcessPriorityClass = "Normal"

        ) # param



        <#

        AboveNormal  32768  Specifies that the process has priority higher than Normal but lower than High.

        BelowNormal  16384  Specifies that the process has priority above Idle but below Normal.

        High           128  Specifies that the process performs time-critical tasks that must be executed immediately, 
                            such as the Task List dialog, which must respond quickly when called by the user, 
                            regardless of the load on the operating system. The threads of the process preempt the 
                            threads of normal or idle priority class processes.  Use extreme care when specifying High for 
                            the process's priority class, because a high priority class application can use nearly all available processor time.

        Idle            64  Specifies that the threads of this process run only when the system is idle, such as a screen saver. 
                            The threads of the process are preempted by the threads of any process running in a higher priority class. 
                            This priority class is inherited by child processes.

        Normal          32  Specifies that the process has no special scheduling needs.

        RealTime       256  Specifies that the process has the highest possible priority.  
                            The threads of a process with RealTime priority preempt the threads of all other processes, 
                            including operating system processes performing important tasks. Thus, a RealTime priority process that 
                            executes for more than a very brief interval can cause disk caches not to flush or cause the mouse to be unresponsive.

        #>

        

        $process = Get-Process -Id $pid

        $process.PriorityClass = $ProcessPriorityClass 

        Write-Host "Process ID $pid [$( $process.Description )] is now set to class: $( $process.priorityclass )  base: $( $process.BasePriority )" -ForegroundColor Yellow

}

 



function SleepFor([single]$loopdelay) {

    
    # NOTE: Needs to be an object to persist, else return the value to be held in a variable for all subsequent calls.
    #       If choose quasi-constant(s) ( i.e. $priority , $whenever , etc. ), then calc at load, and use everywere instead of integers.

    if ( $loopdelay -lt 0 ) {  # use absolute value as desired  max pct of cpu, to calibrate for a requested sleep time of 0 in subesquent calls
                               # can also work in conjuntion with 'SetPriority'
    } else { }



    # milliseconds to respond to input
    $responsetime = 200
    $loopiterations = 1000 * $loopdelay / $responsetime



    # push status bar values

    $A = $StatusBarOperation.Text

    $B = $StatusBarProgress.Text 

    $C = $ProgressBar.Minimum 

    $D = $ProgressBar.Maximum

    $E = $ProgressBar.Value 

    $F = $ProgressBar.Visible  



    # pause between loops in case there's nothing new to prevent racing

    for ( $i = 0 ; $i -lt $loopiterations ; $i++ ) {

        #Exit the loop
        if( -not $form.Visible ) { break }
        if( $script:CancelLoop ) { break }  # switch to cancel when handling an event
        
        # shorter spans uneccesarily causes more or less flicker
        if ( $loopdelay -gt 3 ) { UpdateStatusBar -Op 'Sleeping' -Step "$loopdelay seconds" -Max $loopiterations -Val $i }

        Sleep -m $responsetime

        [System.Windows.Forms.Application]::DoEvents()

    } # for



    # pop status bar values

    if( $form.Visible ) {

            $StatusBarOperation.Text = $A

            $StatusBarProgress.Text  = $B

            $ProgressBar.Minimum          = $C

            $ProgressBar.Maximum          = $D

            $ProgressBar.Value            = $E

            $ProgressBar.Visible          = $F 
    }
}
 
 



function Set-DataGridViewDoubleBuffer {
     
        param (
     
                [Parameter(Mandatory = $true)][System.Windows.Forms.DataGridView]$grid,
     
                [Parameter(Mandatory = $true)][boolean]$Enabled
     
            )
     
        $type = $grid.GetType();
     
        $propInfo = $type.GetProperty('DoubleBuffered',('Instance','NonPublic'))
     
        $propInfo.SetValue($grid, $Enabled, $null)
     
} # DEPRECIATED - background dv filter, and suspend (maybe not needed), work fine
     



function FLoatBalloon {


        #
        #  shows a notification
        #


        Param(
                $Title = ''  ,

                $Text  = ''  ,

                $Icon  = 'Information'
        
        )


        Write-Host -ForeGround Yellow "Floating a balloon."
        Write-Host -ForeGround Yellow $Title
        Write-Host -ForeGround Yellow $Text
        Write-Host -ForeGround Yellow $Icon


        # Add-Type -Assembly System.Windows.Forms


        $balloon = New-Object System.Windows.Forms.NotifyIcon -Property @{
            Icon = [System.Drawing.SystemIcons]::$( $Icon )
            BalloonTipTitle = $Title
            BalloonTipText = $Text
            Visible = $True 
        }

        $balloon.ShowBalloonTip(1)


        $null = Register-ObjectEvent $balloon BalloonTipClicked -SourceIdentifier event_BalloonTipClicked -Action {

                Write-Host  -ForeGround Yellow "event_BalloonTipClicked occured !"   
             
            #    Unregister-Event -SourceIdentifier $event.SourceIdentifier -Force
            #    Remove-Job $event.SourceIdentifier -Force

                # unregister event and remove job object
                Unregister-Event -SourceIdentifier event_BalloonTipClosed -Force
                Remove-Job event_BalloonTipClosed -Force
        
                # unregister other event and remove job object
                Unregister-Event -SourceIdentifier event_BalloonTipClicked -Force
                Remove-Job event_BalloonTipClicked -Force

                $balloon.Visible = $False
                $balloon.Dispose()
        }

        $null = Register-ObjectEvent $balloon BalloonTipClosed -SourceIdentifier event_BalloonTipClosed -Action {

                Write-Host -ForeGround Yellow "event_BalloonTipClosed occured !"

             #   Unregister-Event -SourceIdentifier $event.SourceIdentifier -Force
             #   Remove-Job $event.SourceIdentifier -Force

                # unregister event and remove job object
                Unregister-Event -SourceIdentifier event_BalloonTipClicked -Force
                Remove-Job event_BalloonTipClicked -Force

                # unregister other event and remove job object
                Unregister-Event -SourceIdentifier event_BalloonTipClosed -Force
                Remove-Job event_BalloonTipClosed -Force

                $balloon.Visible = $False
                $balloon.Dispose()
        }
}



#endregion


                ################
                #              #
                #     GUI      #
                #              #
                ################

#region begin  


Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles();


# for right-click and calendar
#[void] [System.Reflection.Assembly]::LoadWithPartialName(“System.Drawing”)
Add-Type -AssemblyName System.Drawing



                ################
                #              #
                #     FORM     #
                #              #
                ################

#region begin  

$form = New-Object System.Windows.Forms.Form

$form.Text = 'Event Log'

# $form.AutoScroll = $true  # dgv has it's own, and dock=fill, so never needed for form

#region begin  prepare for Size, Location

<#
     [System.Windows.Forms.Screen]::AllScreens  # Gets an array of all displays on the system  -or-  use this ::PrimaryScreen
     BitsPerPixel : 32
     Bounds       : {X=0,Y=0,Width=2194,Height=1234}
     DeviceName   : \\.\DISPLAY1
     Primary      : True
     WorkingArea  : {X=0,Y=0,Width=3840,Height=2090}
    
     $screen = [System.Windows.Forms.Screen]::PrimaryScreen
     $screen.Bounds.Width
     $screen.Bounds.Height
     2194
     1234
      
     # hardware resolution
     # -------------------
     $vc = Get-WmiObject -class "Win32_VideoController"
     $vc.CurrentHorizontalResolution
     $vc.CurrentVerticalResolution
     3840
     2160
#>

$screen = [System.Windows.Forms.Screen]::PrimaryScreen

[int]$FormPixelWidth  = ( @( $screen.Bounds.Width , 1800 ) | measure -Minimum ).Minimum  # i.e. whichever is smaller, prefer 1800
[int]$FormPixelHeight = ( @( $screen.Bounds.Height , 600 ) | measure -Minimum ).Minimum  # i.e. whichever is smaller, prefer  600

# $form.Size = New-Object System.Drawing.Size( $FormPixelWidth , $FormPixelHeight )
#                      --- OR ---
$form.MinimumSize = New-Object System.Drawing.Size( $FormPixelWidth , $FormPixelHeight )
# $form.MaximumSize = New-Object System.Drawing.Size( $screen.Bounds.Width , $screen.Bounds.Height )

#  -Obsolete-  $form.AutoScaleMode = 1  # form will automatically scale itself and its controls based on: (0)disabled (1)font (2)dpi (3)classes' parent's scaling mode(if no parent, disabled)
#$form.AutoSize = $true   # automatically resizes to fit its contents, MinimumSize and MaximumSize properties are respected, but the current value of the Size property is ignored

 #endregion

#endregion




                ################
                #              #
                #  Status Bar  #
                #              #
                ################

#region begin

$StatusBar = New-Object System.Windows.Forms.StatusStrip

$StatusBar.Dock = [System.Windows.Forms.DockStyle]::Bottom

# operation name
$StatusBarOperation = New-Object System.Windows.Forms.ToolStripLabel

# which item is being processed
$StatusBarProgress = New-Object System.Windows.Forms.ToolStripLabel

# progress bar
$ProgressBar = New-Object System.Windows.Forms.ToolStripProgressBar
$ProgressBar.Visible = $false

# current event records stats
$StatusBarConsoleStats = New-Object System.Windows.Forms.ToolStripLabel

# current event records dispositions
$StatusBarDispositionStats = New-Object System.Windows.Forms.ToolStripLabel

$StatusBar.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@(
                            $StatusBarOperation,
                            $StatusBarProgress,
                            $ProgressBar
                            $StatusBarConsoleStats
                            $StatusBarDispositionStats
                            ))


#endregion



                ################
                #              #
                #     DGV      #
                #              #
                ################

#region begin



$DGV = New-Object System.Windows.Forms.DataGridView -Property @{


            
           # Size = New-Object System.Drawing.Size( $form.ClientSize.Width , $form.ClientSize.Height )

            Dock = 'Fill'


            
            Font = New-Object System.Drawing.Font("Courier New",10,0,3,0)   # *** monospaced font ***

            ForeColor = [Drawing.Color]::Blue    # only this color property works in this hash, see below



            ColumnHeadersVisible = $true

            RowHeadersVisible = $false  # elim first col with curr row ptr

            AutoSizeColumnsMode = 6 # ( 6 = AllCells ) column widths adjust to fit the contents of all cells in the columns, including header cells.

            AllowUserToAddRows = $false # won't display empty row at bottom

         #   ReadOnly = $true   # $false allows for copy paste, and visual feedback when selecting for right-click



            DataSource = $dv                  #  Only a dataset or datatable object is dynamically updatable as a DataSource

                        
            
            # for right-click
            Name = "DGV"
            Text = "DGV"
             

} # dataGridView



#region begin  Colors

#
# rejects these color property's syntax when in above block
#

#  color for all the cells.
    #$DGV.DefaultCellStyle.ForeColor                           = 'Black'   # ==> specified already in proporties block above
    #$DGV.DefaultCellStyle.BackColor                           = 'White'

# selected cells
    #$DGV.DefaultCellStyle.SelectionForeColor                  = 'Black'
    #$DGV.DefaultCellStyle.SelectionBackColor                  = 'White'
                                                                # ARGB stands for Alpha (Transparency), Red, Green, and Blue.  
            # transparency option                               # For the Alpha channel, 255 is opaque, 0 is transparent, and anything in between
    #$DGV.DefaultCellStyle.SelectionBackColor                  = [System.Drawing.Color]::FromArgb(0, 255, 0, 0)  # transparent red
    #$DGV.DefaultCellStyle.SelectionBackColor                  = [System.Drawing.Color]::FromName("Transparent")

            # make invisible
    $DGV.DefaultCellStyle.SelectionForeColor                  = $DGV.DefaultCellStyle.ForeColor 
    $DGV.DefaultCellStyle.SelectionBackColor                  = $DGV.DefaultCellStyle.BackColor

# default rows ???
    #$DGV.RowsDefaultCellStyle.BackColor                       = 'White'
                                                               
# alternate rows                                               
    #$DGV.AlternatingRowsDefaultCellStyle.ForeColor            = 'Black'
    #$DGV.AlternatingRowsDefaultCellStyle.BackColor            = 'AntiqueWhite'
                                                               
# row selectors                                                  
    #$DGV.RowHeadersDefaultCellStyle.BackColor                 = 'Black'
                                                               
# row selected won't override Selectors color                  
    #$DGV.RowHeadersDefaultCellStyle.SelectionBackColor        = 'Empty'  # does not work
                                                               
# column headers                                               
    #$DGV.ColumnHeadersDefaultCellStyle.ForeColor              = 'White'
    #$DGV.ColumnHeadersDefaultCellStyle.BackColor              = 'Black'

#endregion



#region begin  mouse click event



#Creation of content for right click event actions

$ClickElementMenu=
{
    [System.Windows.Forms.ToolStripItem]$sender = $args[0]
    [System.EventArgs]$e= $args[1]

    $ElementMenuClicked=$sender.Text
    

    [int]$RowIndex = $DGV.CurrentCell.RowIndex        # $DGV.SelectedRows[0].Index    # for multi rows selected, pick first one

    [int]$ColIndex = $DGV.CurrentCell.ColumnIndex

    # NOTE: casting to integer ensures not null for use as index.  sadly, comparing with zero in either results in null
   # if ( $RowIndex -and $ColIndex ) {  # verify not mis-click'd on cell border by accident, will float a balloon

           # $ColName = $DGV.Columns[$ColIndex].Name
            $ColName = $DGV.CurrentCell.OwningColumn.Name
    
            $CellContent=$DGV.Rows[$RowIndex].Cells[$ColIndex].Value
    

            $result="Click on element menu : '{0}' , in rowindex : {1} , column : {2}, name : {3}, cell content : {4}"   -f   $ElementMenuClicked,  $RowIndex, $ColIndex, $columnName , $CellContent
    
           # Write-Host $result


            switch ( $ElementMenuClicked ) {

                "Remove Occurances" { RemoveOccurances $ColName $CellContent }

                "Hide Column"       { HideColumn $ColName } 

                "Show All Columns"  { ShowAllColumns } 

                "View Only These"   { FilterColumn $ColName $CellContent } 

                "View All"          { ClearFilter } 

                "Default Sort"      { DefaultSort } 
        
            } # switch

  #  } else { FLoatBalloon  -Icon 'Error'  -Title 'Cell not found'  -Text "...possible mis-click'd on cell border by accident"  }
}





#create menu to show with right mouse button

$contextMenuStrip1=New-Object System.Windows.Forms.ContextMenuStrip


$ToolStripItems = @( "Remove Occurances" , "Hide Column" , "Show All Columns" , "View Only These" , "View All" , "Default Sort" )

for( $i = 0 ; $i -lt $ToolStripItems.Count ; $i++ ) {


    # New-Variable -Name "var$i" -Value $i
    # Get-Variable -Name "var$i" -ValueOnly


    # creation of elements of menu

    $CreateObject = ' [System.Windows.Forms.ToolStripItem]$toolStripItem' + $i + ' = New-Object System.Windows.Forms.ToolStripMenuItem'

    $AddMenuText = ' $toolStripItem' + $i + '.Text = "' + $ToolStripItems[$i] + '" '

    $AddScriptBlock = ' $toolStripItem' + $i + '.add_Click($ClickElementMenu) '

    $AddToMenu = ' $contextMenuStrip1.Items.Add($toolStripItem' + $i + ') | out-null '

    Invoke-Expression  $CreateObject

    Invoke-Expression  $AddMenuText

    Invoke-Expression  $AddScriptBlock

    Invoke-Expression  $AddToMenu


    <#

    # old way, before using invoke above, need entire block for each menu choice

    #creation element1 of menu

    [System.Windows.Forms.ToolStripItem]$toolStripItem1 = New-Object System.Windows.Forms.ToolStripMenuItem

    $toolStripItem1.Text = "Remove Occurances";

    $toolStripItem1.add_Click($ClickElementMenu)

    $contextMenuStrip1.Items.Add($toolStripItem1) | out-null
    
    #>
       
}


#create event of mouse down on datagrid and show menu when clicked

$DGV.add_MouseDown({

    $sender = $args[0]

    [System.Windows.Forms.MouseEventArgs]$e= $args[1]

    [System.Windows.Forms.DataGridView+HitTestInfo] $hit = $DGV.HitTest($e.X, $e.Y);


    if ($e.Button -eq  [System.Windows.Forms.MouseButtons]::Right)
    {

        if ($hit.Type -eq [System.Windows.Forms.DataGridViewHitTestType]::Cell)
        {
            $DGV.CurrentCell = $DGV[$hit.ColumnIndex, $hit.RowIndex];

            $contextMenuStrip1.Show($DGV, $e.X, $e.Y);
        }


    } else {

        if ($hit.Type -eq [System.Windows.Forms.DataGridViewHitTestType]::ColumnHeader)  #  on column sort
        {
            $DGV.FirstDisplayedScrollingRowIndex = 0   # jump to first row to see the results from the beginning
        }
    } # else ( left button )
})

<#

DataGridViewHitTestType
------------------------------------------------------------------------
Cell                 1   A cell in the DataGridView.
ColumnHeader         2   A column header in the DataGridView.
HorizontalScrollBar  5   The horizontal scroll bar of the DataGridView.
None                 0   An empty part of the DataGridView.
RowHeader            3   A row header in the DataGridView.
TopLeftHeader        4   The top left column header in the DataGridView.
VerticalScrollBar    6   The vertical scroll bar of the DataGridView.

#>

#endregion



 
# attempt to overide auto scroll jumping around, but that's a form feature, which is disabled, and not causing the issue

#$DGV | Add-Member Point -MemberType ScriptMethod -Value { return $this.AutoScrollPosition }


#endregion



                ################
                #              #
                #   Calendar   #
                #              #
                ################

#region begin unused

# $DateDialog = New-Object Windows.Forms.Form 
# $DateDialog.Text = "Select a Date" 
# $DateDialog.Size = New-Object Drawing.Size @( 243,230 ) 
# $DateDialog.StartPosition = "CenterScreen"
# $DateDialog.FormBorderStyle = 'FixedToolWindow'
# $DateDialog.ShowInTaskbar = $False
# $DateDialog.MinimizeBox = $false
# $DateDialog.MaximizeBox = $false
# $DateDialog.ControlBox = $false
# 
# $calendar = New-Object System.Windows.Forms.MonthCalendar 
# $calendar.ShowTodayCircle = $true
# $calendar.MaxSelectionCount = 1
# $calendar.visible = $True
# 
# $OKButton = New-Object System.Windows.Forms.Button
# $OKButton.Location = New-Object System.Drawing.Point( 38,165)
# $OKButton.Size = New-Object System.Drawing.Size(75,23)
# $OKButton.Text = "OK"
# $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
# 
# $CancelButton = New-Object System.Windows.Forms.Button
# $CancelButton.Location = New-Object System.Drawing.Point( 113,165 )
# $CancelButton.Size = New-Object System.Drawing.Size(75,23)
# $CancelButton.Text = "Cancel"
# $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
# 
# $DateDialog.AcceptButton = $OKButton
# $DateDialog.CancelButton = $CancelButton
# 
# $DateDialog.Controls.Add($calendar) 
# $DateDialog.Controls.Add($OKButton)
# $DateDialog.Controls.Add($CancelButton)


#endregion



                ################
                #              #
                #   BUTTONS    #
                #              #
                ################

#region begin unused

# Function DateCheck( $FirstLast , $NewDate ) {
#  
#  
#          $Today = Get-Date
#  
#  
#          $Date = [datetime]::parseexact($NewDate , 'dd-MMM-yyyy', $null)
#  
#  
#          & $BtnDate$FirstLast.Tag = $True
#     
#          & $BtnDate$FirstLast.BackColor = [Drawing.Color]::red
#  
#          & $BtnDate$FirstLast.text = $Date.ToString( "MMM d, yy'" )
#  
#          if ( $Date -eq $Today ) { $NewDate = 'Today' }  # override
#  
#  
#  
#          # Assign dates to variables for comparison in next step
#  
#  
#          switch( $FirstLast ) {
#  
#  
#  
#              'First'     {   $First =  $Date
#  
#                              if ( $Date -eq $Today ) { $BtnDateFirst.text = 'Today' }
#  
#  
#                              if ( $BtnDateLast.text -eq 'Today' ) {
#  
#                                      $Last = $Today
#     
#                              } else {
#      
#                                      $Last = [datetime]::parseexact($BtnDateLast.text, 'dd-MMM-yy', $null) 
#  
#                              } # else
#  
#                          } # First
#  
#  
#  
#              'Last'      {   $Last = $Date 
#  
#                              if ( $Date -eq $Today ) { $BtnDateLast.text = 'Today' }
#  
#  
#                              if ( $BtnDateFirst.text -eq 'Today' ) {
#  
#                                      $First = $Today
#     
#                              } else {
#      
#                                      $First = [datetime]::parseexact($BtnDateFirst.text, 'dd-MMM-yy', $null) 
#  
#                              } # else
#  
#                          } # Last
#  
#          } # Switch
#  
#  
#  
#  
#          # Compare date variables
#  
#          switch( $True ) {
#              
#                  ( $First -gt $Today ) {
#  
#                          $BtnDateFirst.BackColor = [Drawing.Color]::Yellow
#                          $BtnDateFirst.ForeColor = [Drawing.Color]::Black  }
#              
#                  ( $Last -gt $Today ) {
#  
#                          $BtnDateLast.BackColor = [Drawing.Color]::Yellow
#                          $BtnDateLast.ForeColor = [Drawing.Color]::Black   }
#  
#                  ( $First -gt $Last ) {
#  
#                          $BtnDateFirst.BackColor = [Drawing.Color]::Yellow
#                          $BtnDateFirst.ForeColor = [Drawing.Color]::Black
#  
#                          $BtnDateLast.BackColor = [Drawing.Color]::Yellow
#                          $BtnDateLast.ForeColor = [Drawing.Color]::Black   }
#  
#                  ( $True ) {
#  
#                          $BtnDateFirst.Tag = $True
#     
#                          $BtnDateFirst.BackColor = [Drawing.Color]::red
#  
#                          $BtnDateFirst.text = "$( ( Get-Date -Format 'MM:dd:yy' ) )" }
#  
#          } # switch
# 
# 
# } # Function
# 
# 
# 
# $BtnDateFirst_click = { 
# 
# 
#         $DateDialog.Topmost = $True
# 
#         $result = $DateDialog.ShowDialog() 
# 
#         if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
# 
#             $date = $calendar.SelectionStart
# 
#             Write-Host "Date selected: $($date.ToShortDateString())"
# 
#             DateCheck 'First' $date
# 
#         }
# 
# }
# 
# 
# $BtnDateLast_click = { 
# 
# 
#         $DateDialog.Topmost = $True
# 
#         $result = $DateDialog.ShowDialog() 
# 
#         if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
# 
#             $date = $calendar.SelectionStart
# 
#             Write-Host "Date selected: $($date.ToShortDateString())"
# 
#             DateCheck 'Last' $date
# 
#         }
#
# }

#endregion

#region begin 

$BtnUpdates_click = { 

        $BtnUpdates.Tag = $True

        $BtnUpdates.BackColor = [Drawing.Color]::green
}


$BtnAuto_click = { 

        if( $BtnAuto.Tag ) { $BtnAuto.Tag = $False
                               $BtnAuto.BackColor = [Drawing.Color]::red

        } else {               $BtnAuto.Tag = $True 
                               $BtnAuto.BackColor = [Drawing.Color]::green } 


        if( $BtnUpdates.Tag -or $BtnAuto.Tag ) { $BtnUpdates.BackColor = [Drawing.Color]::green

        } else{                                $BtnUpdates.BackColor = [Drawing.Color]::red }

}



# COMMON to ALL buttons

#$bBackColor = [Drawing.Color]::red   # [System.Drawing.Color]::FromName("ButtonFace")
$bForeColor = [Drawing.Color]::white # [System.Drawing.Color]::FromName("ControlText")
#$bFont = New-Object System.Drawing.Font("Microsoft Sans Serif",8,0,3,0)
$bFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
#$bFlatStyle = [System.Windows.Forms.FlatStyle]::System
#$bHeight = [int]( $Form.Height / 20 )
$bHeight = 22
$bwidth = $bHeight
$bAnchorRight = 'Bottom,Right'
$bAnchorLeft = 'Bottom,Left'
$bTop = $Form.ClientSize.Height - $BtnAuto.Height - $bHeight


#endregion

#region begin unused


# # select date range First
# 
# $BtnDateFirst = New-Object System.Windows.Forms.Button
# $BtnDateFirst.Visible = $true
# $BtnDateFirst.Height = $bHeight
# $BtnDateFirst.width = $bwidth * 7
# $BtnDateFirst.Anchor = $bAnchorLeft
# 
# $BtnDateFirst.BackColor = [Drawing.Color]::green
# $BtnDateFirst.ForeColor = $bForeColor
# $BtnDateFirst.Font = $bFont
# #$BtnDateFirst.FlatStyle = $bFlatStyle
# 
# #$BtnDateFirst.add_Click( { ApplyUpdates } )
#     $BtnDateFirst.Add_Click($BtnDateFirst_Click)
# 
# $BtnDateFirst.Top = $bTop
# $BtnDateFirst.left = 10
# $BtnDateFirst.text = "Today"
# $BtnDateFirst.Tag = $False 
# 
# 
# # select date range Last
# 
# $BtnDateLast = New-Object System.Windows.Forms.Button
# $BtnDateLast.Visible = $true
# $BtnDateLast.Height = $bHeight
# $BtnDateLast.width = $bwidth * 7
# $BtnDateLast.Anchor = $bAnchorLeft
# 
# $BtnDateLast.BackColor = [Drawing.Color]::green
# $BtnDateLast.ForeColor = $bForeColor
# $BtnDateLast.Font = $bFont
# #$BtnDateLast.FlatStyle = $bFlatStyle
# 
# #$BtnDateLast.add_Click( { ApplyUpdates } )
#     $BtnDateLast.Add_Click($BtnDateLast_Click)
# 
# $BtnDateLast.Top = $bTop
# $BtnDateLast.left = $BtnDateFirst.Right 
# $BtnDateLast.text = "Today"
# $BtnDateLast.Tag = $False 


#endregion

#region begin 



# Auto Updates

$BtnAuto = New-Object System.Windows.Forms.Button
$BtnAuto.Visible = $true
$BtnAuto.Height = $bHeight
$BtnAuto.width = $bwidth * 4
$BtnAuto.Anchor = $bAnchorRight

#$BtnAuto.BackColor = $bBackColor
$BtnAuto.BackColor = [Drawing.Color]::green
$BtnAuto.ForeColor = $bForeColor
$BtnAuto.Font = $bFont
#$BtnAuto.FlatStyle = $bFlatStyle

#$BtnAuto.add_Click( { ApplyUpdates } )
    $BtnAuto.Add_Click($BtnAuto_Click)

$BtnAuto.Top = $bTop
$BtnAuto.left = $Form.ClientSize.Width - $BtnAuto.width - $bHeight
$BtnAuto.text = "Auto"  
$BtnAuto.Tag = $True 


# Manual single update

$BtnUpdates = New-Object System.Windows.Forms.Button
$BtnUpdates.Visible = $False
$BtnUpdates.Height = $bHeight
$BtnUpdates.width = $bwidth * 7
$BtnUpdates.Anchor = $bAnchorRight

$BtnUpdates.BackColor = [Drawing.Color]::red
$BtnUpdates.ForeColor = $bForeColor
$BtnUpdates.Font = $bFont
#$BtnUpdates.FlatStyle = $bFlatStyle

#$BtnUpdates.add_Click( { ApplyUpdates } )
    $BtnUpdates.Add_Click($BtnUpdates_Click)

$BtnUpdates.Top = $bTop
$BtnUpdates.left = $BtnAuto.left - $BtnUpdates.width
$BtnUpdates.text = "not yet pressed"  
$BtnUpdates.Tag = $False 



#endregion

                ################
                #              #
                #DateTimePicker#
                #              #
                ################
#region begin 


function PickerDateFirst_ValueChanged { 


        $PickerDateLast.MinDate = $PickerDateFirst.value  # dynamic

        # change search critera, based on previous hi/lo recorded

}


function PickerDateLast_ValueChanged { 


        $PickerDateFirst.MaxDate = $PickerDateFirst.value  # dynamic
        
        # change search critera, based on previous hi/lo recorded

}


$PickerDateLast = New-Object System.Windows.Forms.DateTimePicker 

$PickerDateLast.MinDate = ( Get-Date )

$PickerDateLast.MaxDate = ( Get-Date )

$PickerDateLast.CustomFormat = "MMM d"

$PickerDateLast.Format = [windows.forms.datetimepickerFormat]::custom

#$PickerDateLast.Left = $PickerDateFirst.Right
$PickerDateLast.Left = $BtnUpdates.Left - $PickerDateLast.Width

$PickerDateLast.Top = $form.ClientSize.Height - $PickerDateLast.Height

#$PickerDateLast.Anchor = 'Left,Bottom'
$PickerDateLast.Anchor = ' Bottom , Right '

$PickerDateLast.Add_ValueChanged({PickerDateLast_ValueChanged})




$PickerDateFirst = New-Object System.Windows.Forms.DateTimePicker 

#$PickerDateFirst.MinDate = new DateTime(1985, 6, 20);

$PickerDateFirst.MaxDate = ( Get-Date )

$PickerDateFirst.CustomFormat = "MMM d"

$PickerDateFirst.Format = [windows.forms.datetimepickerFormat]::custom

#$PickerDateFirst.Left = 0
$PickerDateFirst.Left = $PickerDateLast.Left - $PickerDateFirst.Width

$PickerDateFirst.Top = $PickerDateLast.Top

#$PickerDateFirst.Anchor = 'Left,Bottom'
$PickerDateFirst.Anchor = ' Bottom , Right '

$PickerDateFirst.Add_ValueChanged({PickerDateFirst_ValueChanged})


#endregion




                ################
                #              #
                #   ASSEMBLE   #
                #   AND SHOW   #
                #              #
                ################

#region begin 


# add controls, and sort DGV

$form.Controls.Add($DGV) ; DefaultSort -NoJump

$Form.Controls.Add($BtnUpdates)

$Form.Controls.Add($BtnAuto)

$Form.Controls.Add($PickerDateFirst)

$Form.Controls.Add($PickerDateLast)

$Form.Controls.Add($StatusBar)







# set up AutoExec functionality
  
# another option for syntax to perform something when form loads     
#$Form_Load = {$form.Text = "Form Load Event Handled!"}    
 
# script block to call with next statement below     
$Form_Load = {
     
        Set-DataGridViewDoubleBuffer -grid $DGV -Enabled $true
     
    }

#$form.Add_Load( $Form_Load )




# show the form

$Form.Add_Shown( { $Form.Activate() } )
$Form.Show()



#$StatusBar.BringToFront()
$PickerDateFirst.BringToFront()
$PickerDateLast.BringToFront()
$BtnAuto.BringToFront()




# place form at intended location

$FormLeft   = [int]( ( $screen.Bounds.Width   -  $form.Width ) / 2 )
$FormTop    = [int](   $screen.Bounds.Height  * .01 )
$form.Location = New-Object System.Drawing.Point( $FormLeft , $FormTop )
     


SetPriority "BelowNormal"  # don't interfere with normal usage



#endregion

#endregion


      #############################          ################         #############################
      #############################          #              #         #############################
      #############################          # Main{} Loop  #         #############################
      #############################          #              #         #############################
      #############################          ################         #############################




while( $form.Visible ) {



                        
        ################
        #              #
        #    GATHER    #
        #              #
        ################

        #region begin  
        [System.Windows.Forms.Application]::DoEvents()


        $EventLog_Objects = @()

       

        while( $EventLog_Objects.count -lt 1 ) {

        
                [System.Windows.Forms.Application]::DoEvents()

                           



                        
                if( $BtnUpdates.Tag -or $BtnAuto.Tag ) { ApplyUpdates             ; $PrevRowCount = 0 ; $PrevHitCount = 0 }
                

                        



                # if we're stuck seeing only repeats, look further ahead, and if needed, move on.  may miss something, but that's how it goes.
                
                if( ( $PrevRecordId -eq $pendingestRecordId ) -and ( $PrevEventCount -ge $BatchSize ) ) {  # we're buried, take action

                        # start by reaching further ahead with a performance hit
                        if( $MaxEvents -eq $BatchSize ) { $MaxEvents = 256 ; $Deadlock = 'yes'   # 256 = system max

                        # last resort; start advancing the clock in case the event log was slammed so hard that even 256 won't dig out
                        } elseif( $CutOffTime.TimeOfDay -lt ( Get-Date ).TimeOfDay ) { $CutOffTime = ( $CutOffTime ).AddSeconds(1) ; sleepfor 3 # don't kill cpu

                        # caught up to (maybe ahead of) current time, give event log a break
                        } else { sleepfor 10 } }   


                
                # did paydirt break the spell?  Reset Maxevents, do above query and stats report

                if( $PrevRecordId -ne $pendingestRecordId ) { $MaxEvents = $BatchSize }  




                # begin output of new stats line, indicates active, not sleeping

                #Write-Host ( Get-Date -Format ' hh:mm:sst') -NoNewline 
                $ConsoleStats = Get-Date -Format ' hh:mm:sst /'

                Write-Host '+' -NoNewline  # visual indicator that get is about to start

                UpdateStatusBar -Op 'Reading Event Log' 



                $EventFilterHash = @{
                                        Logname      = "Security" 
                                    
                                        ProviderName = “Microsoft-Windows-Security-Auditing"

                                        ID           = $EventId

                                        StartTime    = $CutOffTime 

                } # EventFilterHash




              #  try { 

                        $Milliseconds = ( Measure-Command -Expression {
        
                            $EventLog_Objects = Get-WinEvent  -Oldest  -MaxEvents $MaxEvents  -ErrorAction SilentlyContinue  -FilterHashTable $EventFilterHash
        
                        } ).Milliseconds


              #  }
              #
              #  # NOTE: "Try" requires " -ErrorAction Stop "  ===>  non-terminating error won't get caught by try/catch
              #
              #  catch [Exception] {    # might not be any messages in our requested time period before getting first messages returned, then we always get at least the last message already seen
              #
              #          if ($_.Exception -match "No events were found that match the specified selection criteria") {
              #
              #                      Write-Host "$(Get-Date)   Error: No events found for $CutOffTime";
              #          }
              #  }



        
                [System.Windows.Forms.Application]::DoEvents()


              

                # update cache values right away after fetching records so as to match events ( non-PTR )

                # non-PTR ( A , CNAME , etc. )
                foreach( $o in ( Get-DnsClientCache ).Where( { $_.Type -ne 12 } ) ) { $DnsCacheFwd.($o.data) = $o.name }

        
                [System.Windows.Forms.Application]::DoEvents()


                # PTR
                foreach( $o in ( Get-DnsClientCache ).Where( { $_.Type -eq 12 } ) ) { $DnsCacheRev.($o.name) = $o.data }




                # paydirt!         

                if( $EventLog_Objects.count -gt 1 ) {   

                                                
                        # newest record, is now the oldest we'll accept,

                        $CutOffTime = $EventLog_Objects[ -1 ].TimeCreated


                        # record new value for latest timestamp and record id seen as high score
                        
                        $Days[ $( '{0:MM:dd:yy}' -f $CutOffTime ) ].HiStamp = $CutOffTime
                        $Days[ $( '{0:MM:dd:yy}' -f $CutOffTime ) ].HiRecord = $EventLog_Objects[ -1 ].RecordId


 
                        # counter reset from hitting upper bound?

                        if( ( $pendingestRecordId - $EventLog_Objects[ -1 ].RecordId ) -gt 10000 ) { $pendingestRecordId = 0 } }




                # did paydirt break the spell?  Reset 'Deadlock' indicator for this loop's stats report

                if( $PrevRecordId -ne $pendingestRecordId ) { $Deadlock = 'no' }  
                        


                # save for next deadlock check
                $PrevRecordId = $pendingestRecordId                # set up to act on possible deadlock next loop                                                
                $PrevEventCount = $EventLog_Objects.count      # will get zero'd out in outer whle loop before next deadlock check




                
              #  $ConsoleStats = " CutOff:"   , ( $CutOffTime                   ).ToString('hh:mm:sst')              ,
              #                  " Newest:"   , ( $pendingestRecordId           ).ToString().PadLeft( 7  , [char]32 ) ,
              #                  " Millisec:" , ( $Milliseconds                 ).ToString().PadLeft( 4  , [char]32 ) ,
              #                  " Events:"   , ( $EventLog_Objects.count       ).ToString().PadLeft( 3  , [char]32 ) ,
              #                  " Max:"      , ( $MaxEvents                    ).ToString().PadLeft( 3  , [char]32 ) ,
              #                  " Deadlock:" , ( $Deadlock                                ).PadRight( 3  , [char]32 ) , 
              #                  " Rows:"     , ( $DGV.Rows.Count               ).ToString().PadLeft( 3  , [char]32 ) ,
              #                  " Fwd:"      , ( $DnsCacheFwd.Count            ).ToString().PadLeft( 3  , [char]32 ) ,
              #                  " Rev:"      , ( $DnsCacheRev.Count            ).ToString().PadLeft( 3  , [char]32 )
                

                                # timestamp was recorded before doing get
                $ConsoleStats = $ConsoleStats                                                         ,   
                                ( $CutOffTime                   ).ToString('hh:mm:sst')               ,   "CutOff ("   , 
                                ( $Milliseconds                 ).ToString().PadLeft( 4  , [char]32 ) ,   "MilSec )"   , 
                                ( $pendingestRecordId           ).ToString().PadLeft( 7  , [char]32 ) ,   "Newest"   , 
                                ( $EventLog_Objects.count       ).ToString().PadLeft( 3  , [char]32 ) ,   "Events"   , 
                                ( $MaxEvents                    ).ToString().PadLeft( 3  , [char]32 ) ,   "Max"      , 
                                ( $Deadlock                                ).PadLeft( 3  , [char]32 ) ,   "Deadlock" , 
                                ( $DGV.Rows.Count               ).ToString().PadLeft( 3  , [char]32 ) ,   "Rows "     , 
                                ( $DnsCacheFwd.Count            ).ToString().PadLeft( 3  , [char]32 ) ,   "dns"      , 
                                ( $DnsCacheRev.Count            ).ToString().PadLeft( 3  , [char]32 ) ,   "ptr"      

                Write-Host $ConsoleStats 


                # not much going on, give cpu a big break
        
                if( $EventLog_Objects.count -lt $BatchSize ) { SleepFor 30 }



                # totally caught up, give cpu an extra big break

                if( $EventLog_Objects.count -le 1 ) { sleepfor 30 }  

                        






                if( -not $form.Visible ) { break }   # sleepfor helper



        } # while

  
  
        if( -not $form.Visible ) { break }   # 2nd time to jump to end of outer while (avoids err msg on setting CuttoffTime if no records yet)




        #endregion

        ################
        #              #
        #  EACH EVENT  #
        #              #
        ################

        #region begin  
        [System.Windows.Forms.Application]::DoEvents()


        $OutCount = 0  # reporting counter
        $InCount = 0   # reporting counter
        $i = 0         # progress bar pseudo counter, excludes dup record id's

        foreach( $obj in (  $EventLog_Objects ).Where( { $_.RecordId -gt $pendingestRecordId } ) ) { 


                Write-Host '.' -NoNewline   # progress indicator, typically not more than 64
                
                $i++ ; UpdateStatusBar -Op 'Processing Events' -Max $EventLog_Objects.count -Val $i


                $pendingestRecordId = $obj.RecordId


                                      #  '---------- DEBUGGING ----------------'
                                      #  $obj.TimeCreated.ToString()
                                      #  $obj.RecordId.ToString()
                                      #  $obj.Message | Format-Table -AutoSize     # debuging output, dump message portion



                [System.Windows.Forms.Application]::DoEvents()  # allow for form close event
              #  sleepfor .3                                       # give cpu a break, and allow for form close event

                if( -not $form.Visible ) { break }  # exit loop



           #     Write-Host ( $obj | Format-List -Property * | Out-String )
           #
           #     Write-Host ( $obj.Bookmark.ToString() )
           #
           #     Write-Host ( $obj.Properties | Format-List -Property * | Out-String )
           #     
           #     Write-Host $obj.Properties.value[5]


               
                if( $IgnoreDest -contains $obj.Properties.value[5] ) { continue } # skip to next iteration of loop



                #endregion
        
                ################
                #              #
                #    PARSE     #
                #              #
                ################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()


                # clear temporary storage
                $paths.Clear()
                $flags = @()
                       


                $OutputRow.Clear()    # clear temporary buffer
                
                foreach( $k in ( $Fields.Keys ) ) {
                
                                            [System.Windows.Forms.Application]::DoEvents()

                                            $OutputRow.$k = ' '  # can't stay null at db row import

                                    } #)

            <#
           
             NOTE: not preserving values, so complexity, slowdown of this deep copy not needed
                
                # aquire order of elements for output buffer from fields structure, only needed for ordered, otherwise, $OutputRow = $Fields.Clone()
                # create a deep-clone of an object ( like: $OutputRow = $Fields => but don't pointer/reference to same memory structure )
                $ms = New-Object System.IO.MemoryStream
                $bf = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
                $bf.Serialize($ms, $Fields)
                $ms.Position = 0
                $OutputRow = $bf.Deserialize($ms)
                $ms.Close()

            #>




       #         # Message is a big blob, so parse it into rows for processing
       #
       #         $MyArray=@( ($obj.Message).Split( [Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries ) )
       #
       #
       #
       #         # parse value from interesting rows, and store in temporary output buffer
       #
       #         foreach( $k in ( $Fields.Keys ) ) {
       #              
       #                 [System.Windows.Forms.Application]::DoEvents()
       #
       #                 # need something to search on, so skip calculated fields
       #
       #                 if ( "$( $Fields.$k )" -ne ' ' ) {
       #
       #                         $MessageRow = $MyArray -match "$( $Fields.$k )"  # find matching fields in message
       #             
       #                         if( $MessageRow ) {  # if field found in message, parse out part needed                  
       #
       #                                 $OutputRow.$k = ( ( $MessageRow ) -replace "`t", " " ).split( ' ' , [StringSplitOptions]::RemoveEmptyEntries )  | 
       #
       #                                     Select-Object -Skip ( ( $Fields.$k -cSplit ' ' ).Count ) # works with multiple chars too!
       #
       #                         } else { $OutputRow.$k = ' ' }
       #                 } # if
       #         } # foreach

       #         if ( $OutputRow.Direction -eq 'Outbound' ) { $OutCount++ }
       #         if ( $OutputRow.Direction -eq 'Inbound'  ) { $InCount++  }


                $OutputRow.PIDx        = $obj.Properties.value[0]
                $OutputRow.App         = $obj.Properties.value[1]
                $OutputRow.Direction   = $obj.Properties.value[2]
                $OutputRow.Source      = $obj.Properties.value[3]
                $OutputRow.sPort       = $obj.Properties.value[4]
                $OutputRow.Destination = $obj.Properties.value[5]
                $OutputRow.dPort       = $obj.Properties.value[6]
                $OutputRow.Protocol    = $obj.Properties.value[7]
                $OutputRow.Rule        = $obj.Properties.value[8]  # XML ONLY - $OutputRow.FilterRTID = $obj.FilterRTID



                if ( $OutputRow.Direction -like '*14593' ) { $OutputRow.Direction = 'Outbound' ; $OutCount++ }
                if ( $OutputRow.Direction -like '*14592' ) { $OutputRow.Direction = 'Inbound'  ; $InCount++  }



                $OutputRow.LastUpdated = $obj.TimeCreated.ToString('M/d  h:mm p')
                
              #  $OutputRow.RecordId = $obj.RecordId.ToString()              # sequential s/n of event


              #  $OutputRow.FilterOrigin = $obj.ProviderId


                # full path
                $OutputRow.FilePath = $OutputRow.app

                # parse out just fname
                $fname = $OutputRow.app.split('\')[-1]




                #endregion

                ################
                #              #
                #   FILTERS    #
                #              #
                ################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()



                if( $Direction -notcontains $OutputRow.Direction ) { continue }




                # expose actual service hiding behind svchost 
                $OutputRow.svc = ( Get-WmiObject Win32_service -Filter "ProcessId = $($OutputRow.PIDx)" ).Name

                # get full name if found, else put something as placeholder for insert into table
                if( $OutputRow.svc ) { $OutputRow.DisplayName = ( Get-Service -Name $OutputRow.svc -ErrorAction SilentlyContinue ).DisplayName 
                } else { $OutputRow.svc = ' ' }





                ######################################

                # *** ABORT *** if event not intersting

                ######################################

                if( ( $IgnoreApp -contains $fname ) -or ( $IgnoreSvc -contains $OutputRow.svc ) ) { continue }
             #   if( ( $IgnoreApp -contains $fname ) -or ( $IgnoreSvc -contains $OutputRow.svc ) -or ( $IgnoreDest -contains $OutputRow.Destination ) ) { continue }


             #   if( ( $OutputRow.App -eq "System" ) -and ( $OutputRow.dPort -eq "137" ) ) { continue }
                  




                #endregion

                #######################
                #                     #
                #      NEFARIOUS?     #
                #                     #
                #######################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()




                # check for different path to executable

                if ($paths.ContainsKey($fname)) {

                        if( $paths[$fname] -notcontains $OutputRow.app ) {   # $paths[$fname] is a pointer to an array
                        
                                 # alarm 
                                 $flags += 'path'

                                 # record
                               #  $paths[ $fname ] += $OutputRow.app    # NOTE:  need to store paths in the datatable somehow, and as hidden
                        }
                }

                else { $paths[ $fname ] = @($OutputRow.app) }   # record to new array stored in the hash
                
               
               <#


                    If you have a predefined application that should be used to perform the operation that was reported by this event, monitor events with “Application” not equal to your defined application.

                    You can monitor to see if “Application” is not in a standard folder (for example, not in System32 or Program Files) or is in a restricted folder (for example, Temporary Internet Files).

                    If you have a pre-defined list of restricted substrings or words in application names (for example, “mimikatz” or “cain.exe”), check for these substrings in “Application.”

                    Check that “Source Address” is one of the addresses assigned to the computer.

                    If the computer or device should not have access to the Internet, or contains only applications that don’t connect to the Internet, monitor for 5156 events where “Destination Address” is an IP address from the Internet (not from private IP ranges).

                    If you know that the computer should never contact or should never be contacted by certain network IP addresses, monitor for these addresses in “Destination Address.”

                    If you have an allow list of IP addresses that the computer or device is expected to contact or to be contacted by, monitor for IP addresses in “Destination Address” that are not in the allow list.

                    If you need to monitor all inbound connections to a specific local port, monitor for 5156 events with that “Source Port.”

                    Monitor for all connections with a “Protocol Number” that is not typical for this device or computer, for example, anything other than 1, 6, or 17.

                    If the computer’s communication with “Destination Address” should always use a specific “Destination Port,” monitor for any other “Destination Port.”


               #>



                #endregion

                #######          ################          #######
                #######          #              #          #######
                #######          #    OUTPUT    #          #######
                #######          #              #          #######
                #######          ################          #######



 

                ################   
                #              #
                #   BEAUTIFY   #      NOTE:  has to come before tuple check
                #              #
                ################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()



                # use parsed value for display
                $OutputRow.app = $fname




                # use friendly name for protocol
 
                $Temp = $OutputRow.Protocol
                $OutputRow.Protocol = $PrettyProtocols[ ( [string]$OutputRow.Protocol ) ] 
                if( -not $OutputRow.Protocol ) { $OutputRow.Protocol = $Temp }


                
                # use friendly name for EventId

                $OutputRow.Action = $obj.Id.ToString()   # type of event, e.g. 5156

                $Temp = $OutputRow.Action
                $OutputRow.Action = $PrettyEventId[ ( $OutputRow.Action ) ] 
                if( -not $OutputRow.Action ) { $OutputRow.Action = $Temp }



                #endregion

                #######################
                #                     #
                #  DETERMINE IF NEW   #
                #                     #
                #######################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()


                $TupleFields = @( "Action" , "Direction" , "Source" , "Protocol" , "dPort" , "Destination" , "App" , "Svc" )



                $OutputRow.Tuple = ( $OutputRow.Keys.ForEach( {
                        
                        [System.Windows.Forms.Application]::DoEvents()
                        
                        if( $TupleFields -contains $_ ) {
                        
                                ( $OutputRow.$_ ) -join " "    # App can have spaces, so join to become a single array member
                        }  # if
                } ) )  # =



                $existing = $dt.Select("Tuple = '" + $OutputRow.Tuple + "'")   # find matching tuple in db
                                                                               # should be no worries about an array resulting from multiple matches
                [System.Windows.Forms.Application]::DoEvents()
                
                $pending      = $dtw.Select("Tuple = '" + $OutputRow.Tuple + "'")  # find matching tuple in db
                                                                               # should be no worries about an array resulting from multiple matches

                #endregion

                #######################
                #                     #
                #    PREP FOR NEW     #
                #                     #
                #######################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()


                if( -not $existing -and -not $pending ) {  # then resolve and add to $pending, else just update flags and hits further down


                        $OutputRow.HitCount = 1

                        $OutputRow.Flags = ' '
                

                #endregion

                        ################
                        #              #
                        #   DNS/GEO    #
                        #              #
                        ################

                        #region begin  
                        [System.Windows.Forms.Application]::DoEvents()


                        $RFC = IsPrivateNetwork ( $OutputRow.Destination )


                        $OutputRow.HostName = $RFC

                        $OutputRow.Domain  = " "

                        $OutputRow.Country  = "n/a"



                        # Don't waste a lookup on more or less non-public IPs, or endless create loop w/port 53

                        if( ( $RFC -eq 'Public' ) -and   

                            ( $DnsServers -notcontains $OutputRow.Destination  ) -and

                          ( ( $OutputRow.App , $OutputRow.dPort -join ':' ) -ne "System:137" ) ) { 


                                 # find the ip in the dns cache

                                 $OutputRow.HostName = $DnsCacheFwd.( $OutputRow.Destination ) 


                                 # if not found, try a reverse lookup

                                 if( -not $OutputRow.HostName ) { 
                                 


                                        # check the cache

                                        $option = [StringSplitOptions]::RemoveEmptyEntries

                                        $octets = ( $OutputRow.Destination ).Split( '.' , 5 , $option ) # break into 5 max, toss any fifth later

                                        $reversed = $octets[3..0] -join '.'

                                       # $DnsCacheRev.keys | where {$_ -like "$reversed*"} | foreach { $OutputRow.HostName = $DnsCacheRev.$_ }

                                       #            - OR -
                                          
                                        $name = $reversed , '.in-addr.arpa' -join ''

                                        $OutputRow.HostName = $DnsCacheRev.$name

                                     #   write-host '' # LF
                                     #   write-host '-----------'
                                     #   write-host 'OutputRow.Destination   ' , $OutputRow.Destination
                                     #   write-host 'octets                  ' , $octets
                                     #   write-host 'reversed                ' , $reversed
                                     #   write-host 'name                    ' , $name
                                     #   write-host 'OutputRow.HostName      ' , $OutputRow.HostName
                                     #   write-host 'DnsCacheRev.$name       ' , $DnsCacheRev.$name




                                        # else go out for a lookup

                                        if( -not $OutputRow.HostName ) { 
                                                
                                                [System.Windows.Forms.Application]::DoEvents()
                                                
                                                # uses only first record from returned array
                                                $OutputRow.HostName = @(                                  
                                                        
                                                        Resolve-DnsName $OutputRow.Destination -type PTR -ErrorAction SilentlyContinue | 

                                                                % { $_.NameHost } )[0]    

                                     #           write-host 'post lookup             ' , $OutputRow.HostName
                                                                                     
                                                [System.Windows.Forms.Application]::DoEvents()
                                                
                                         } # if




                                        # mark as found through reverse

                                        if( $OutputRow.HostName ) { $OutputRow.HostName = '@' , $OutputRow.HostName -join ' ' } 

                                     #   write-host 'final touch             ' , $OutputRow.HostName


                                 } # if


                                 # last resort use a blank space so db has something to insert into column

                                 if( -not $OutputRow.HostName ) { $OutputRow.HostName = ' ' }

                                 # parse out domain

                                 else{ $OutputRow.Domain = $OutputRow.HostName.split('.')[-2..-1] -join '.' }



                                                                 
                                 # cname? if( $DnsCacheFwd.( $OutputRow.HostName ) ) { $OutputRow.HostName = $DnsCacheFwd.( $OutputRow.HostName ) } # repeat




# whois
                        
# https://rdap.arin.net/registry/ip/205.185.216.0




                                $IPAddress = $OutputRow.Destination   # need this for geolocation call
                                $Octets = $IPAddress.Split(".")   # less server-side processing to convert IPv4 to decimal
                                $DecimalIP = [int]$Octets[0]*16777216 + [int]$Octets[1]*65536 + [int]$Octets[2]*256 + [int]$Octets[3]

                                $Geo = Invoke-RestMethod -Method Get -Uri "http://77.55.235.217/$DecimalIP" # ip2c.org
                                                                                                           
                                [System.Windows.Forms.Application]::DoEvents()
                                                
                                $SomeCode = ($Geo -split ';')[0]         # always '1'
                                $Country2letter = ($Geo -split ';')[1]   # US
                                $Country3letter = ($Geo -split ';')[2]   # USA
                                $CountryFullName = ($Geo -split ';')[3]  # United States
                           
                                # array allows for easy check for color coding later
                                if( ( $OtherCountries -notcontains $CountryFullName ) -and ( $Country2letter -ne 'US' ) ) { $OtherCountries += $CountryFullName }
                           
                                $OutputRow.Country = $CountryFullName


                                
                                # Write-Host '=> looking up, found:  ' , $OutputRow.HostName , $OutputRow.Country



                        } # if




                        #endregion

                        ################
                        #              #
                        #   USERNAME   #
                        #              #
                        ################

                        #region begin  
                        [System.Windows.Forms.Application]::DoEvents()





                        # get the username for this PID  **  requires elevated user rights  **  ( except for my own processes )
                        # ------------------------------
                   

                        # if not admin, skip getting user

                        # NOTE:  with WMI will at least get my username w/o throwing an error

         #               if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) { 
         #         
         #                       $OutputRow.UserName = ( Get-Process -Id $OutputRow.PIDx -ErrorAction SilentlyContinue -IncludeUserName ).UserName }
                                  
                                                      
         #          
         #    WMI method
         #

         $ShowDebug = ''   #  null to not show, anything to show


                        $Filter = "handle='" + $OutputRow.PIDx + "'"
             
                        $WmiObjProcess = Get-WmiObject -Class Win32_Process -Filter $Filter
             

                        if ( $ShowDebug ) {
                                Write-Host
                                Write-Host 'Get-Process        '
                                Get-Process -Id $OutputRow.PIDx -ErrorAction SilentlyContinue | Select-Object -Property * | ft 
                        }
             
             
                        if( -not $WmiObjProcess ) { 
                        
                                $OutputRow.UserName = "*expired"  
                        
                        } else {
             
                                $WmiObjOwner = $WmiObjProcess.getowner()
             
                                $UserName = $WmiObjOwner.user
             
                                $OutputRow.UserName = $UserName
             

                                if ( $ShowDebug ) {
                                        Write-Host '$WmiObjProcess        '
                                        $WmiObjProcess | Select-Object -Property * | ft 
                                        Write-Host '$WmiObjOwner          '
                                        $WmiObjOwner    | Select-Object -Property  * | fl 
                                        Write-Host '$WmiObjOwner.user     ' , $UserName
                                }

             
                        } # else
             

                        if( -not $OutputRow.UserName ) { $OutputRow.UserName = "*denied"  }
             
                        if ( $ShowDebug ) {
                                Write-Host '$OutputRow.UserName' , $OutputRow.UserName
                                Write-Host 'Event:$obj.UserId  ' , $obj.UserId              # direct from event
                        }


                        <#

                        Get-Process

                        Name      Id PriorityClass FileVersion HandleCount WorkingSet PagedMemorySize PrivateMemorySize VirtualMemorySize TotalProcessorTime
                        ----      -- ------------- ----------- ----------- ---------- --------------- ----------------- ----------------- ------------------
                        firefox 1752        Normal 84.0.2             2102  348561408       232337408         232337408        -659017728 00:08:50.6875000


                        $WmiObjProcess

                        PSComputerName  ProcessName Handles            VM        WS Path                                         __GENUS __CLASS       __SUPERCLASS __DYNASTY
                        --------------  ----------- -------            --        -- ----                                         ------- -------       ------------ ---------
                        DESKTOP-LG64QR0 firefox.exe    2102 2206954172416 348561408 C:\Program Files\Mozilla Firefox\firefox.exe       2 Win32_Process CIM_Process  CIM_ManagedSystemElement


                        $WmiObjOwner


                        PSComputerName   :
                        __GENUS          : 2
                        __CLASS          : __PARAMETERS
                        __SUPERCLASS     :
                        __DYNASTY        : __PARAMETERS
                        __RELPATH        :
                        __PROPERTY_COUNT : 3
                        __DERIVATION     : {}
                        __SERVER         :
                        __NAMESPACE      :
                        __PATH           :
                        Domain           : DESKTOP-LG64QR0
                        ReturnValue      : 0
                        User             : r
                        Properties       : {Domain, ReturnValue, User}
                        SystemProperties : {__GENUS, __CLASS, __SUPERCLASS, __DYNASTY...}
                        Qualifiers       : {}
                        ClassPath        : __PARAMETERS
                        Site             :
                        Container        :



                        $WmiObjOwner.user      r
                        $OutputRow.UserName r
                        Event:$obj.UserId


                        ######################################################################################################################################

                        Get-Process

                        Name      Id PriorityClass FileVersion                         HandleCount WorkingSet PagedMemorySize PrivateMemorySize VirtualMemorySize TotalProcessorTime
                        ----      -- ------------- -----------                         ----------- ---------- --------------- ----------------- ----------------- ------------------
                        svchost 2956        Normal 10.0.19041.1 (WinBuild.160101.0800)         277    7471104         3133440           3133440          88506368 00:00:09.2187500


                        $WmiObjProcess

                        PSComputerName  ProcessName Handles            VM      WS Path                            __GENUS __CLASS       __SUPERCLASS __DYNASTY
                        --------------  ----------- -------            --      -- ----                            ------- -------       ------------ ---------
                        DESKTOP-LG64QR0 svchost.exe     277 2203406729216 7471104 C:\WINDOWS\system32\svchost.exe       2 Win32_Process CIM_Process  CIM_ManagedSystemElement


                        $WmiObjOwner


                        PSComputerName   :
                        __GENUS          : 2
                        __CLASS          : __PARAMETERS
                        __SUPERCLASS     :
                        __DYNASTY        : __PARAMETERS
                        __RELPATH        :
                        __PROPERTY_COUNT : 3
                        __DERIVATION     : {}
                        __SERVER         :
                        __NAMESPACE      :
                        __PATH           :
                        Domain           : NT AUTHORITY
                        ReturnValue      : 0
                        User             : NETWORK SERVICE
                        Properties       : {Domain, ReturnValue, User}
                        SystemProperties : {__GENUS, __CLASS, __SUPERCLASS, __DYNASTY...}
                        Qualifiers       : {}
                        ClassPath        : __PARAMETERS
                        Site             :
                        Container        :



                        $WmiObjOwner.user      NETWORK SERVICE
                        $OutputRow.UserName NETWORK SERVICE
                        Event:$obj.UserId

                        #>             




                        #endregion

                        #######################
                        #                     #
                        #      ADD NEW        #
                        #                     #
                        #######################

                        #region begin  
                        [System.Windows.Forms.Application]::DoEvents()


                        # HitCount is numeric, as is Port
                        $array = @(  

                                foreach( $k in $OutputRow.Keys ) { 
                                                                                             
                                        [System.Windows.Forms.Application]::DoEvents()
                                                
                                        if( $Numerics -contains  $k ) { [int]( $OutputRow.$k ) 
                     
                                        } else {                             ( $OutputRow.$k ) -join " " 
                     
                                        } } )
                     
                     

                        [void]$dtw.Rows.Add( $array )
  
          
                } # if


                #endregion

                #######################
                #                     #
                # EXISTING, DO UPDATE #
                #                     #
                #######################

                #region begin  
               # [System.Windows.Forms.Application]::DoEvents()      # can't be above 'else',  breaks connection to 'if' block, catch next one


                else{ 
                    

                    if( $existing ) {   
                                        $FlagsHash[ "$( $OutputRow.Tuple )" ] = ( 
                                                
                                                $( $FlagsHash[ "$( $OutputRow.Tuple )" ] ) , 
                                                
                                                $( $Flags  -join ' ' )  -join ' ' 
                                                
                                                ).trim()

                                        
                                        $HitsHash[ "$( $OutputRow.Tuple )" ]++ 

                                        $TimeHash[ "$( $OutputRow.Tuple )" ] = $OutputRow.LastUpdated

                                    }


                                    # Write-Host              '++++++++++++++ flag ++++++++++++++++++++'
                                    # Write-Host              $FlagsHash["$( $OutputRow.Tuple )" ]
                                    # Write-Host              '++++++++++++++ hits ++++++++++++++++++++'
                                    # Write-Host              $HitsHash["$( $OutputRow.Tuple )" ]
                                    # Write-Host              '+++++++++++++ tuple +++++++++++++++++++++'
                                    # Write-Host              $OutputRow.Tuple
                                    # Write-Host              '************** keys ********************'
                                    # Write-Host              $HitsHash.Keys
                                    # Write-Host              '*****************************************'


                    if( $pending      ) { 
                                        $pending[0]["Flags"] = ( $( $pending[0]["Flags"] ) , $( $Flags -join ' ' ) -join ' ' ).trim()

                                        $pending[0]["HitCount"]++

                                        $pending[0]["LastUpdated"] = $OutputRow.LastUpdated

                                    }
                    

                } # else




                #endregion
                
                #######################
                #                     #
                # UPDATE DISPOSITIONS #
                #                     #
                #######################

                #region begin  
                [System.Windows.Forms.Application]::DoEvents()
        

                $TmpNewRow = $dtw.Rows.Count - $PrevRowCount
                $TmpNewHit = $HitsHash.Count - $PrevHitCount
                                                        
                $PrevRowCount = $dtw.Rows.Count
                $PrevHitCount = $HitsHash.Count
       
                # estimate, does not include dups

                $Discards = $InCount + $OutCount - $TmpNewRow - $TmpNewHit
      
              #  $DispositionStats = 'NewRows'  , $TmpNewRow ,
              #                    'Updates:'  , $TmpNewHit ,
              #                    'Discards:' , $Discards  ,
              #                    'Outbound'  , $OutCount  ,
              #                    'Inbound'   , $InCount

              $DispositionStats =  ' (' ,
                                   ( $TmpNewRow ).ToString().PadLeft( 3  , [char]32 ) ,  'NewRow'  ,
                                   ( $TmpNewHit ).ToString().PadLeft( 3  , [char]32 ) ,  'Update'  ,
                                   ( $Discards  ).ToString().PadLeft( 3  , [char]32 ) ,  'Discard @' ,
                                   ( $InCount   ).ToString().PadLeft( 3  , [char]32 ) ,  'In'       ,
                                   ( $OutCount  ).ToString().PadLeft( 3  , [char]32 ) ,  'Out )'      



        } # pipeline

                

                #endregion


        #######################
        #                     #
        #   CLEANUP / PAUSE   #
        #                     #
        #######################
        #region begin  
        [System.Windows.Forms.Application]::DoEvents()

      
        # final accurate count
             
        $Discards = $EventLog_Objects.count - $TmpNewRow - $TmpNewHit

        for( $i = 1 ; $i -le ( $Discards ) ; $i++ ) { Write-Host ',' -NoNewline }  # discards count pad progress indicator
            
            
        Write-Host ''   # newline for progress indicator

      
                # report stats on this run

        Write-Host $DispositionStats




        # configure update buttons

        if( ( $dtw.Rows.Count -gt 0 ) -or ( $HitsHash.Count -gt 0 ) ) {


                if( $BtnUpdates.Tag -or $BtnAuto.Tag ) { $BtnUpdates.BackColor = [Drawing.Color]::green

                } else{                                $BtnUpdates.BackColor = [Drawing.Color]::red }



                $BtnUpdates.Text = $dtw.Rows.Count , "/" ,  $HitsHash.Count , "updates"

                $BtnUpdates.Visible = $True

                $BtnUpdates.BringToFront()

        } # if



        TrimTable  # crudly limit size of table to pre-determined number of lines
        


 #      if( $EventLog_Objects.count -gt 0 ) {  $EventLog_Objects.Dispose() }  # memory leak?


                #endregion

} #  while 





$form.Dispose()

$dv.Close
$dt.Close
$dtw.Close
	
Remove-Variable -name dv
Remove-Variable -name dt



# do a comparison against recorded at begin, 
# and remove all of the variables added by script
((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).foreach{Remove-Variable -Name $_ 2>$null}

