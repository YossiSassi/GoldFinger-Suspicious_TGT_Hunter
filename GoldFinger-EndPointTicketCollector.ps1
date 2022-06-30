## GOLD FINGER - Suspicious TGT detector --> Ticket Collector Script (To Be Run locally on Remote EndPoints via WinRM/ws-man or PaExec/SMB) ##
# NOTE: DO NOT RUN THIS SCRIPT. Run 'GoldFinger-Main.ps1' instead, with relevant parameters (if applicable), and keep this script available in the same folder.

# Purpose: TGT monitor, research in progress, hunting for indicators of potential Golden Tickets/Pass-The-Hash on EndPoints in the domain.
# Need to have either WinRM or SMB (PaExec method) open and enabled on EndPoints.
# version: 1.0
# License: BSD 3-Clause
# Original functions by Jared Atkinson (@jaredcatkinson) & Matthew Graeber (@mattifestation)
# Modified by Yossi Sassi (@yossi_sassi)
# comments to yossis@protonmail.com #

# Check for elevated rights
if (!([System.Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion().StartsWith("v4"))) {Write-Output "Not Elevated. Quiting"; exit}

# If local PS history is collected, disable it for this script
if (Get-Module PSReadline) {Set-PSReadLineOption -HistorySaveStyle SaveNothing}

# Main function
function Get-KerberosTicketGrantingTicket
{
<#
.NOTES
Author: Jared Atkinson (@jaredcatkinson)
Modified by: Yossi Sassi (@yossi_sassi)
License: BSD 3-Clause
#>
    [CmdletBinding()]
    param
    (
    )

    #region PSReflect
    function New-InMemoryModule
    {
	<#
	.NOTES
	Author: Matthew Graeber (@mattifestation)
	License: BSD 3-Clause
	#>

        Param
        (
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String]
            $ModuleName = [Guid]::NewGuid().ToString()
        )

        $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
        $LoadedAssemblies = $AppDomain.GetAssemblies()

        foreach ($Assembly in $LoadedAssemblies) {
            if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
                return $Assembly
            }
        }

        $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
        $Domain = $AppDomain
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

        return $ModuleBuilder
    }

    function func
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [String]
            $DllName,

            [Parameter(Position = 1, Mandatory = $True)]
            [string]
            $FunctionName,

            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $ReturnType,

            [Parameter(Position = 3)]
            [Type[]]
            $ParameterTypes,

            [Parameter(Position = 4)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention,

            [Parameter(Position = 5)]
            [Runtime.InteropServices.CharSet]
            $Charset,

            [String]
            $EntryPoint,

            [Switch]
            $SetLastError
        )

        $Properties = @{
            DllName = $DllName
            FunctionName = $FunctionName
            ReturnType = $ReturnType
        }

        if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
        if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
        if ($Charset) { $Properties['Charset'] = $Charset }
        if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
        if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

        New-Object PSObject -Property $Properties
    }

    function Add-Win32Type
    {
	<#
	.NOTES
	Author: Matthew Graeber (@mattifestation)
	License: BSD 3-Clause
	#>
        [OutputType([Hashtable])]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $DllName,

            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $FunctionName,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [String]
            $EntryPoint,

            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [Type]
            $ReturnType,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Type[]]
            $ParameterTypes,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CharSet]
            $Charset = [Runtime.InteropServices.CharSet]::Auto,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Switch]
            $SetLastError,

            [Parameter(Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [ValidateNotNull()]
            [String]
            $Namespace = ''
        )

        BEGIN
        {
            $TypeHash = @{}
        }

        PROCESS
        {
            if ($Module -is [Reflection.Assembly])
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
                }
                else
                {
                    $TypeHash[$DllName] = $Module.GetType($DllName)
                }
            }
            else
            {
                # Define one type for each DLL
                if (!$TypeHash.ContainsKey($DllName))
                {
                    if ($Namespace)
                    {
                        $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                    }
                    else
                    {
                        $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                    }
                }

                $Method = $TypeHash[$DllName].DefineMethod(
                    $FunctionName,
                    'Public,Static,PinvokeImpl',
                    $ReturnType,
                    $ParameterTypes)

                # Make each ByRef parameter an Out parameter
                $i = 1
                foreach($Parameter in $ParameterTypes)
                {
                    if ($Parameter.IsByRef)
                    {
                        [void] $Method.DefineParameter($i, 'Out', $null)
                    }

                    $i++
                }

                $DllImport = [Runtime.InteropServices.DllImportAttribute]
                $SetLastErrorField = $DllImport.GetField('SetLastError')
                $CallingConventionField = $DllImport.GetField('CallingConvention')
                $CharsetField = $DllImport.GetField('CharSet')
                $EntryPointField = $DllImport.GetField('EntryPoint')
                if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

                if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

                # Equivalent to C# version of [DllImport(DllName)]
                $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                    $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                    [Reflection.FieldInfo[]] @($SetLastErrorField,
                                               $CallingConventionField,
                                               $CharsetField,
                                               $EntryPointField),
                    [Object[]] @($SLEValue,
                                 ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                                 ([Runtime.InteropServices.CharSet] $Charset),
                                 $ExportedFuncName))

                $Method.SetCustomAttribute($DllImportAttribute)
            }
        }

        END
        {
            if ($Module -is [Reflection.Assembly])
            {
                return $TypeHash
            }

            $ReturnTypes = @{}

            foreach ($Key in $TypeHash.Keys)
            {
                $Type = $TypeHash[$Key].CreateType()
            
                $ReturnTypes[$Key] = $Type
            }

            return $ReturnTypes
        }
    }

    function psenum
    {
        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [Parameter(Position = 1, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,

            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $Type,

            [Parameter(Position = 3, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $EnumElements,

            [Switch]
            $Bitfield
        )

        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }

        $EnumType = $Type -as [Type]

        $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

        if ($Bitfield)
        {
            $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
            $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
            $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        }

        foreach ($Key in $EnumElements.Keys)
        {
            # Apply the specified enum type to each element
            $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
        }

        $EnumBuilder.CreateType()
    }

    function field
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [UInt16]
            $Position,
        
            [Parameter(Position = 1, Mandatory = $True)]
            [Type]
            $Type,
        
            [Parameter(Position = 2)]
            [UInt16]
            $Offset,
        
            [Object[]]
            $MarshalAs
        )

        @{
            Position = $Position
            Type = $Type -as [Type]
            Offset = $Offset
            MarshalAs = $MarshalAs
        }
    }

    function struct
    {
	<#
	.NOTES
	Author: Matthew Graeber (@mattifestation)
	License: BSD 3-Clause
	#>
        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 1, Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [Parameter(Position = 2, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,

            [Parameter(Position = 3, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $StructFields,

            [Reflection.Emit.PackingSize]
            $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

            [Switch]
            $ExplicitLayout
        )

        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }

        [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
            Class,
            Public,
            Sealed,
            BeforeFieldInit'

        if ($ExplicitLayout)
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
        }
        else
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
        }

        $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
        $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

        $Fields = New-Object Hashtable[]($StructFields.Count)

        # Sort each field according to the orders specified
        # Unfortunately, PSv2 doesn't have the luxury of the
        # hashtable [Ordered] accelerator.
        foreach ($Field in $StructFields.Keys)
        {
            $Index = $StructFields[$Field]['Position']
            $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
        }

        foreach ($Field in $Fields)
        {
            $FieldName = $Field['FieldName']
            $FieldProp = $Field['Properties']

            $Offset = $FieldProp['Offset']
            $Type = $FieldProp['Type']
            $MarshalAs = $FieldProp['MarshalAs']

            $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

            if ($MarshalAs)
            {
                $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
                if ($MarshalAs[1])
                {
                    $Size = $MarshalAs[1]
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                        $UnmanagedType, $SizeConst, @($Size))
                }
                else
                {
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
                }
            
                $NewField.SetCustomAttribute($AttribBuilder)
            }

            if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
        }

        # Make the struct aware of its own size.
        # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
        $SizeMethod = $StructBuilder.DefineMethod('GetSize',
            'Public, Static',
            [Int],
            [Type[]] @())
        $ILGenerator = $SizeMethod.GetILGenerator()
        # Thanks for the help, Jason Shirk!
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

        # Allow for explicit casting from an IntPtr
        # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
        $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
            'PrivateScope, Public, Static, HideBySig, SpecialName',
            $StructBuilder,
            [Type[]] @([IntPtr]))
        $ILGenerator2 = $ImplicitConverter.GetILGenerator()
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

        $StructBuilder.CreateType()
    }
    #endregion PSReflect

    $Module = New-InMemoryModule -ModuleName GetKerberosTicket

    #region Enums
    $KERB_PROTOCOL_MESSAGE_TYPE = psenum $Module KERB_PROTOCOL_MESSAGE_TYPE UInt32 @{ 
        KerbDebugRequestMessage                  = 0
        KerbQueryTicketCacheMessage              = 1
        KerbChangeMachinePasswordMessage         = 2
        KerbVerifyPacMessage                     = 3
        KerbRetrieveTicketMessage                = 4
        KerbUpdateAddressesMessage               = 5
        KerbPurgeTicketCacheMessage              = 6
        KerbChangePasswordMessage                = 7
        KerbRetrieveEncodedTicketMessage         = 8
        KerbDecryptDataMessage                   = 9
        KerbAddBindingCacheEntryMessage          = 10
        KerbSetPasswordMessage                   = 11
        KerbSetPasswordExMessage                 = 12
        KerbVerifyCredentialsMessage             = 13
        KerbQueryTicketCacheExMessage            = 14
        KerbPurgeTicketCacheExMessage            = 15
        KerbRefreshSmartcardCredentialsMessage   = 16
        KerbAddExtraCredentialsMessage           = 17
        KerbQuerySupplementalCredentialsMessage  = 18
        KerbTransferCredentialsMessage           = 19
        KerbQueryTicketCacheEx2Message           = 20
        KerbSubmitTicketMessage                  = 21
        KerbAddExtraCredentialsExMessage         = 22
        KerbQueryKdcProxyCacheMessage            = 23
        KerbPurgeKdcProxyCacheMessage            = 24
        KerbQueryTicketCacheEx3Message           = 25
        KerbCleanupMachinePkinitCredsMessage     = 26
        KerbAddBindingCacheEntryExMessage        = 27
        KerbQueryBindingCacheMessage             = 28
        KerbPurgeBindingCacheMessage             = 29
        KerbQueryDomainExtendedPoliciesMessage   = 30
        KerbQueryS4U2ProxyCacheMessage           = 31
    }

    $KERB_CACHE_OPTIONS = psenum $Module KERB_CACHE_OPTIONS UInt64 @{
        KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1
        KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2
        KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4
        KERB_RETRIEVE_TICKET_AS_KERB_CRED   = 0x8
        KERB_RETRIEVE_TICKET_WITH_SEC_CRED  = 0x10 
        KERB_RETRIEVE_TICKET_CACHE_TICKET   = 0x20
        KERB_RETRIEVE_TICKET_MAX_LIFETIME   = 0x40
    } -Bitfield

    $KERB_ENCRYPTION_TYPE = psenum $Module KERB_ENCRYPTION_TYPE UInt32 @{
          reserved0                         = 0
          des_cbc_crc                       = 1
          des_cbc_md4                       = 2
          des_cbc_md5                       = 3
          reserved1                         = 4
          des3_cbc_md5                      = 5
          reserved2                         = 6
          des3_cbc_sha1                     = 7
          dsaWithSHA1_CmsOID                = 9
          md5WithRSAEncryption_CmsOID       = 10
          sha1WithRSAEncryption_CmsOID      = 11
          rc2CBC_EnvOID                     = 12
          rsaEncryption_EnvOID              = 13
          rsaES_OAEP_ENV_OID                = 14
          des_ede3_cbc_Env_OID              = 15
          des3_cbc_sha1_kd                  = 16
          aes128_cts_hmac_sha1_96           = 17
          aes256_cts_hmac_sha1_96           = 18
          aes128_cts_hmac_sha256_128        = 19
          aes256_cts_hmac_sha384_192        = 20
          rc4_hmac                          = 23
          rc4_hmac_exp                      = 24
          camellia128_cts_cmac              = 25
          camellia256_cts_cmac              = 26
          subkey_keymaterial                = 65
    }

    $KERB_TICKET_FLAGS = psenum $Module KERB_TICKET_FLAGS UInt32 @{
        reserved          = 2147483648
        forwardable       = 0x40000000
        forwarded         = 0x20000000
        proxiable         = 0x10000000
        proxy             = 0x08000000
        may_postdate      = 0x04000000
        postdated         = 0x02000000
        invalid           = 0x01000000
        renewable         = 0x00800000
        initial           = 0x00400000
        pre_authent       = 0x00200000
        hw_authent        = 0x00100000
        ok_as_delegate    = 0x00040000
        name_canonicalize = 0x00010000
        cname_in_pa_data  = 0x00040000
        enc_pa_rep        = 0x00010000
        reserved1         = 0x00000001
    } -Bitfield

    $SECURITY_LOGON_TYPE = psenum $Module SECURITY_LOGON_TYPE UInt32 @{
        Interactive = 2
        Network     = 3
        Batch       = 4
        Service     = 5
        Proxy       = 6
        Unlock      = 7
        NetworkCleartext = 8
        NewCredentials = 9
        RemoteInteractive = 10
        CachedInteractive = 11
        CachedRemoteInteractive = 12
        CachedUnlock = 13
    }

    $SECURITY_IMPERSONATION_LEVEL = psenum $Module SECURITY_IMPERSONATION_LEVEL UInt32 @{
        SecurityAnonymous = 0
        SecurityIdentification = 1
        SecurityImpersonation = 2
        SecurityDelegation = 3
    }

    $TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
        TOKEN_DUPLICATE          = 0x00000002
        TOKEN_IMPERSONATE        = 0x00000004
        TOKEN_QUERY              = 0x00000008
        TOKEN_QUERY_SOURCE       = 0x00000010
        TOKEN_ADJUST_PRIVILEGES  = 0x00000020
        TOKEN_ADJUST_GROUPS      = 0x00000040
        TOKEN_ADJUST_DEFAULT     = 0x00000080
        TOKEN_ADJUST_SESSIONID   = 0x00000100
        DELETE                   = 0x00010000
        READ_CONTROL             = 0x00020000
        WRITE_DAC                = 0x00040000
        WRITE_OWNER              = 0x00080000
        SYNCHRONIZE              = 0x00100000
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        TOKEN_ALL_ACCESS         = 0x001f01ff
    } -Bitfield
    #endregion Enums

    #region Structs
    $LSA_STRING = struct $Module LSA_STRING @{
        Length = field 0 UInt16
        MaximumLength = field 1 UInt16
        Buffer = field 2 IntPtr
    }

    $LSA_UNICODE_STRING = struct $Module LSA_UNICODE_STRING @{
        Length = field 0 UInt16
        MaximumLength = field 1 UInt16
        Buffer = field 2 IntPtr
    }

    $LUID = struct $Module LUID @{
        LowPart  = field 0 UInt32
        HighPart = field 1 UInt32
    }

    $LUID_AND_ATTRIBUTES = struct $Module LUID_AND_ATTRIBUTES @{
        Luid       = field 0 $LUID
        Attributes = field 1 UInt32
    }

    $SecHandle = struct $Module SecHandle @{
        dwLower = field 0 IntPtr       
        dwUpper = field 1 IntPtr
    }

    $KERB_CRYPTO_KEY = struct $Module KERB_CRYPTO_KEY @{
        KeyType = field 0 Int32
        Length = field 1 Int32
        Value = field 2 IntPtr
    }

    $KERB_EXTERNAL_NAME = struct $Module KERB_EXTERNAL_NAME @{
        NameType = field 0 Int16
        NameCount = field 1 UInt16
        Names = field 2 $LSA_UNICODE_STRING
    }

    $KERB_EXTERNAL_TICKET = struct $Module KERB_EXTERNAL_TICKET @{
        ServiceName = field 0 IntPtr
        TargetName = field 1 IntPtr
        ClientName = field 2 IntPtr
        DomainName = field 3 $LSA_UNICODE_STRING
        TargetDomainName = field 4 $LSA_UNICODE_STRING
        AltTargetDomainName = field 5 $LSA_UNICODE_STRING
        SessionKey = field 6 $KERB_CRYPTO_KEY
        TicketFlags = field 7 UInt32
        Flags = field 8 UInt32
        KeyExpirationTime = field 9 Int64
        StartTime = field 10 Int64
        EndTime = field 11 Int64
        RenewUntil = field 12 Int64
        TimeSkew = field 13 Int64
        EncodedTicketSize = field 14 Int32
        EncodedTicket = field 15 IntPtr
    }

    $KERB_TICKET_CACHE_INFO = struct $Module KERB_TICKET_CACHE_INFO @{
        ServerName = field 0 $LSA_UNICODE_STRING
        RealmName = field 1 $LSA_UNICODE_STRING
        StartTime = field 2 Int64
        EndTime = field 3 Int64
        RenewTime = field 4 Int64
        EncryptionType = field 5 Int32
        TicketFlags = field 6 UInt32
    }

    $KERB_QUERY_TKT_CACHE_REQUEST = struct $Module KERB_QUERY_TKT_CACHE_REQUEST @{
        MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
        LogonId = field 1 $LUID
    }

    $KERB_QUERY_TKT_CACHE_RESPONSE = struct $Module KERB_QUERY_TKT_CACHE_RESPONSE @{
        MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
        CountOfTickets = field 1 UInt32
        Tickets = field 2 $KERB_TICKET_CACHE_INFO.MakeArrayType() -MarshalAs @('ByValArray', 1)
    }

    $KERB_RETRIEVE_TKT_REQUEST = struct $Module KERB_RETRIEVE_TKT_REQUEST @{
        MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
        LogonId = field 1 $LUID
        TargetName = field 2 $LSA_UNICODE_STRING
        TicketFlags = field 3 UInt64
        CacheOptions = field 4 $KERB_CACHE_OPTIONS
        EncryptionType = field 5 Int64
        CredentialsHandle = field 6 $SecHandle
    }

    $KERB_RETRIEVE_TKT_RESPONSE = struct $Module KERB_RETRIEVE_TKT_RESPONSE @{
        Ticket = field 0 $KERB_EXTERNAL_TICKET
    }

    $LSA_LAST_INTER_LOGON_INFO = struct $Module LSA_LAST_INTER_LOGON_INFO @{
        LastSuccessfulLogon = field 0 Int64
        LastFailedLogon = field 1 Int64
        FailedAttemptCountSinceLastSuccessfulLogon = field 2 UInt64
    }

    $SECURITY_LOGON_SESSION_DATA = struct $Module SECURITY_LOGON_SESSION_DATA @{
        Size = field 0 UInt32
        LogonId = field 1 $LUID
        Username = field 2 $LSA_UNICODE_STRING
        LogonDomain = field 3 $LSA_UNICODE_STRING
        AuthenticationPackage = field 4 $LSA_UNICODE_STRING
        LogonType = field 5 UInt32
        Session = field 6 UInt32
        PSiD = field 7 IntPtr
        LogonTime = field 8 UInt64
        LogonServer = field 9 $LSA_UNICODE_STRING
        DnsDomainName = field 10 $LSA_UNICODE_STRING
        Upn = field 11 $LSA_UNICODE_STRING
        UserFlags = field 12 UInt64
        LastLogonInfo = field 13 $LSA_LAST_INTER_LOGON_INFO
        LogonScript = field 14 $LSA_UNICODE_STRING
        ProfilePath = field 15 $LSA_UNICODE_STRING
        HomeDirectory = field 16 $LSA_UNICODE_STRING
        HomeDirectoryDrive = field 17 $LSA_UNICODE_STRING
        LogoffTime = field 18 Int64
        KickOffTime = field 19 Int64
        PasswordLastSet = field 20 Int64
        PasswordCanChange = field 21 Int64
        PasswordMustChange = field 22 Int64
    }

    $SID_AND_ATTRIBUTES = struct $Module SID_AND_ATTRIBUTES @{
        Sid        = field 0 IntPtr
        Attributes = field 1 UInt32
    }
    #endregion Structs

    #region Function Definitions
    $FunctionDefinitions = @(
        (func kernel32 CloseHandle ([bool]) @(
            [IntPtr]                                  #_In_ HANDLE hObject
        ) -EntryPoint CloseHandle -SetLastError),
    
        (func advapi32 DuplicateToken ([bool]) @(
            [IntPtr],                                 #_In_  HANDLE                       ExistingTokenHandle,
            [UInt32],                                 #_In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            [IntPtr].MakeByRefType()                  #_Out_ PHANDLE                      DuplicateTokenHandle
        ) -EntryPoint DuplicateToken -SetLastError),
    
        (func advapi32 ImpersonateLoggedOnUser ([bool]) @(
            [IntPtr]                                  #_In_ HANDLE hToken
        ) -EntryPoint ImpersonateLoggedOnUser -SetLastError),
    
        (func secur32 LsaCallAuthenticationPackage_KERB_QUERY_TKT_CACHE ([UInt32]) @(
            [IntPtr],                                      #_In_  HANDLE    LsaHandle
            [UInt64],                                      #_In_  ULONG     AuthenticationPackage
            $KERB_QUERY_TKT_CACHE_REQUEST.MakeByRefType(), #_In_  PVOID     ProtocolSubmitBuffer
            [UInt64],                                      #_In_  ULONG     SubmitBufferLength
            [IntPtr].MakeByRefType(),#_Out_ PVOID     *ProtocolReturnBuffer
            [UInt64].MakeByRefType(),                      #_Out_ PULONG    *ReturnBufferLength
            [UInt32].MakeByRefType()                       #_Out_ PNTSTATUS ProtocolStatus
        ) -EntryPoint LsaCallAuthenticationPackage),
    
        (func secur32 LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT ([UInt32]) @(
            [IntPtr],                                   #_In_  HANDLE    LsaHandle
            [UInt64],                                   #_In_  ULONG     AuthenticationPackage
            $KERB_RETRIEVE_TKT_REQUEST.MakeByRefType(), #_In_  PVOID     ProtocolSubmitBuffer
            [UInt64],                                   #_In_  ULONG     SubmitBufferLength
            [IntPtr].MakeByRefType(),#_Out_ PVOID     *ProtocolReturnBuffer
            [UInt64].MakeByRefType(),                   #_Out_ PULONG    *ReturnBufferLength
            [UInt32].MakeByRefType()                    #_Out_ PNTSTATUS ProtocolStatus
        ) -EntryPoint LsaCallAuthenticationPackage),
    
        (func secur32 LsaConnectUntrusted ([UInt32]) @(
            [IntPtr].MakeByRefType()                #_Out_ PHANDLE LsaHandle
        ) -EntryPoint LsaConnectUntrusted),
    
        (func secur32 LsaDeregisterLogonProcess ([UInt32]) @(
            [IntPtr]                                #_In_ HANDLE LsaHandle
        ) -EntryPoint LsaDeregisterLogonProcess),
    
        (func secur32 LsaEnumerateLogonSessions ([UInt32]) @(
            [UInt64].MakeByRefType(),               #_Out_ PULONG LogonSessionCount,
            [IntPtr].MakeByRefType()                #_Out_ PLUID  *LogonSessionList
        ) -EntryPoint LsaEnumerateLogonSessions),
    
        (func secur32 LsaFreeReturnBuffer ([UInt32]) @(
            [IntPtr].MakeByRefType()                #_In_ PVOID Buffer
        ) -EntryPoint LsaFreeReturnBuffer),
    
        (func secur32 LsaGetLogonSessionData ([UInt32]) @(
            [IntPtr],                                    #_In_  PLUID                        LogonId,
            [IntPtr].MakeByRefType()                     #_Out_ PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData
        ) -EntryPoint LsaGetLogonSessionData),
    
        (func secur32 LsaLookupAuthenticationPackage ([UInt32]) @(
            [IntPtr],                               #_In_  HANDLE      LsaHandle,
            $LSA_STRING.MakeByRefType()             #_In_  PLSA_STRING PackageName,
            [UInt64].MakeByRefType()                #_Out_ PULONG      AuthenticationPackage
        ) -EntryPoint LsaLookupAuthenticationPackage),
    
        (func advapi32 LsaNtStatusToWinError ([UInt64]) @(
            [UInt32]                                #_In_ NTSTATUS Status
        ) -EntryPoint LsaNtStatusToWinError),
    
        (func secur32 LsaRegisterLogonProcess ([UInt32]) @(
            $LSA_STRING.MakeByRefType()             #_In_  PLSA_STRING           LogonProcessName,
            [IntPtr].MakeByRefType()                #_Out_ PHANDLE               LsaHandle,
            [UInt64].MakeByRefType()                #_Out_ PLSA_OPERATIONAL_MODE SecurityMode
        ) -EntryPoint LsaRegisterLogonProcess),
    
        (func advapi32 OpenProcessToken ([bool]) @(
            [IntPtr],                                   #_In_  HANDLE  ProcessHandle
            [UInt32],                                   #_In_  DWORD   DesiredAccess
            [IntPtr].MakeByRefType()                    #_Out_ PHANDLE TokenHandle
        ) -EntryPoint OpenProcessToken -SetLastError),
    
        (func advapi32 RevertToSelf ([bool]) @() -EntryPoint RevertToSelf -SetLastError)
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Kerberos'
    
    $Advapi32 = $Types['advapi32']
    $Kernel32 = $Types['kernel32']
    $Secur32 = $Types['secur32']
    #endregion Function Definitions

    #region Win32 function abstractions
    function CloseHandle
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $Handle    
        )
    
        $SUCCESS = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if(-not $SUCCESS) 
        {
            Write-Debug "CloseHandle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    function DuplicateToken
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        [OutputType([IntPtr])]
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $TokenHandle,

            [Parameter()]
            [ValidateSet('None','SecurityAnonymous','SecurityIdentification','SecurityImpersonation','SecurityDelegation')]
            [string]
            $ImpersonationLevel = 'SecurityImpersonation'
        )

        $DuplicateTokenHandle = [IntPtr]::Zero

        $success = $Advapi32::DuplicateToken($TokenHandle, $SECURITY_IMPERSONATION_LEVEL::$ImpersonationLevel, [ref]$DuplicateTokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        if(-not $success)
        {
            Write-Debug "DuplicateToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }

        Write-Output $DuplicateTokenHandle
    }

    function ImpersonateLoggedOnUser
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $TokenHandle
        )

        $SUCCESS = $Advapi32::ImpersonateLoggedOnUser($TokenHandle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        if(-not $SUCCESS)
        {
            throw "ImpersonateLoggedOnUser Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    function LsaCallAuthenticationPackage
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $LsaHandle,

            [Parameter()]
            [ValidateSet('MICROSOFT_KERBEROS_NAME_A')]
            [string]
            $AuthenticationPackageName = 'MICROSOFT_KERBEROS_NAME_A',

            [Parameter(Mandatory = $true)]
            [UInt32]
            $LogonId
        )

        <#
        (func secur32 LsaCallAuthenticationPackage ([UInt32]) @(
            [IntPtr],                                  #_In_  HANDLE    LsaHandle
            [UInt64],                                  #_In_  ULONG     AuthenticationPackage
            $KERB_RETRIEVE_TKT_REQUEST.MakeByRefType(),#_In_  PVOID     ProtocolSubmitBuffer
            [UInt64],                                  #_In_  ULONG     SubmitBufferLength
            [IntPtr],                                  #_Out_ PVOID     *ProtocolReturnBuffer
            [UInt64].MakeByRefType(),                  #_Out_ PULONG    *ReturnBufferLength
            [UInt32].MakeByRefType()                   #_Out_ PNTSTATUS ProtocolStatus
        ))
        #>

        $AuthenticationPackage = LsaLookupAuthenticationPackage -LsaHandle $LsaHandle -PackageName $AuthenticationPackageName

        switch($AuthenticationPackageName)
        {
            MICROSOFT_KERBEROS_NAME_A
            {
                $LogonIdLuid = [Activator]::CreateInstance($LUID)
                $LogonIdLuid.LowPart = $LogonId
                $LogonIdLuid.HighPart = 0


                # Check Ticket Granting Ticket
                <#
                $KERB_RETRIEVE_TKT_REQUEST = struct $Mod Kerberos.KERB_RETRIEVE_TKT_REQUEST @{
                    MessageType = field 0 $KERB_PROTOCOL_MESSAGE_TYPE
                    LogonId = field 1 $LUID
                    TargetName = field 2 $LSA_UNICODE_STRING
                    TicketFlags = field 3 UInt64
                    CacheOptions = field 4 $KERB_CACHE_OPTIONS
                    EncryptionType = field 5 Int64
                    CredentialsHandle = field 6 IntPtr
                }
                #>

                $ProtocolSubmitBuffer = [Activator]::CreateInstance($KERB_RETRIEVE_TKT_REQUEST)
                $ProtocolSubmitBuffer.MessageType = $KERB_PROTOCOL_MESSAGE_TYPE::KerbRetrieveTicketMessage
                $ProtocolSubmitBuffer.LogonId = $LogonIdLuid

                $ProtocolReturnBuffer = [IntPtr]::Zero
                $ReturnBufferLength = [UInt64]0
                $ProtocolStatus = [UInt32]0

                $SUCCESS = $Secur32::LsaCallAuthenticationPackage_KERB_RETRIEVE_TKT($LsaHandle, $AuthenticationPackage, [ref]$ProtocolSubmitBuffer, $KERB_RETRIEVE_TKT_REQUEST::GetSize(), [ref]$ProtocolReturnBuffer, [ref]$ReturnBufferLength, [ref]$ProtocolStatus)

                if($SUCCESS -eq 0)
                {
                    if($ProtocolStatus -eq 0)
                    {
                        $data = $ProtocolReturnBuffer -as $KERB_RETRIEVE_TKT_RESPONSE
                    
                        #LsaFreeReturnBuffer -Buffer $ProtocolReturnBuffer

                        $ServiceName_STRING = $data.Ticket.ServiceName -as $KERB_EXTERNAL_NAME
                        $ServiceName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ServiceName_STRING.Names.Buffer, $ServiceName_STRING.Names.Length / 2)
                        #$TargetName_STRING = $data.Ticket.TargetName -as $KERB_EXTERNAL_NAME
                        #$TargetName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($TargetName_STRING.Names.Buffer, $TargetName_STRING.Names.Length / 2)
                        $ClientName_STRING = $data.Ticket.ClientName -as $KERB_EXTERNAL_NAME
                        $ClientName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ClientName_STRING.Names.Buffer, $ClientName_STRING.Names.Length / 2)
                        $DomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.Ticket.DomainName.Buffer, $data.Ticket.DomainName.Length / 2)

                        $TargetDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.Ticket.TargetDomainName.Buffer, $data.Ticket.TargetDomainName.Length / 2)
                        $AltTargetDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($data.Ticket.AltTargetDomainName.Buffer, $data.Ticket.AltTargetDomainName.Length / 2)
                        
                        # Session Key
                        $SessionKeyType = [string]($data.Ticket.SessionKey.KeyType -as $KERB_ENCRYPTION_TYPE)
                        $SessionKey = New-Object -TypeName byte[]($data.Ticket.SessionKey.Length)
                        [System.Runtime.InteropServices.Marshal]::Copy($data.Ticket.SessionKey.Value, $SessionKey, 0, $data.Ticket.SessionKey.Length)

                        # EncodedTicket Property
                        $EncodedTicket = New-Object -TypeName byte[]($data.Ticket.EncodedTicketSize)
                        [System.Runtime.InteropServices.Marshal]::Copy($data.Ticket.EncodedTicket, $EncodedTicket, 0, $data.Ticket.EncodedTicketSize)

                        $obj = New-Object -TypeName psobject
                    
                        $obj | Add-Member -MemberType NoteProperty -Name ServiceName -Value $ServiceName
                        #$obj | Add-Member -MemberType NoteProperty -Name TargetName -Value $TargetName
                        $obj | Add-Member -MemberType NoteProperty -Name ClientName -Value $ClientName
                        $obj | Add-Member -MemberType NoteProperty -Name DomainName -Value $DomainName
                        $obj | Add-Member -MemberType NoteProperty -Name TargetDomainName -Value $TargetDomainName
                        $obj | Add-Member -MemberType NoteProperty -Name AltTargetDomainName -Value $AltTargetDomainName
                        $obj | Add-Member -MemberType NoteProperty -Name SessionKeyType -Value $SessionKeyType
                        $obj | Add-Member -MemberType NoteProperty -Name SessionKey -Value $SessionKey
                        $obj | Add-Member -MemberType NoteProperty -Name TicketFlags -Value ($data.Ticket.TicketFlags -as $KERB_TICKET_FLAGS).ToString()
                        $obj | Add-Member -MemberType NoteProperty -Name KeyExpirationTime -Value ([datetime]::FromFileTime($data.Ticket.KeyExpirationTime))
                        $obj | Add-Member -MemberType NoteProperty -Name StartTime -Value ([datetime]::FromFileTime($data.Ticket.StartTime))
                        $obj | Add-Member -MemberType NoteProperty -Name EndTime -Value ([datetime]::FromFileTime($data.Ticket.EndTime))
                        $obj | Add-Member -MemberType NoteProperty -Name RenewUntil -Value ([datetime]::FromFileTime($data.Ticket.RenewUntil))
                        $obj | Add-Member -MemberType NoteProperty -Name TimeSkew -Value $data.Ticket.TimeSkew
                        $obj | Add-Member -MemberType NoteProperty -Name EncodedTicketSize -Value $data.Ticket.EncodedTicketSize
                        $obj | Add-Member -MemberType NoteProperty -Name EncodedTicket -Value $EncodedTicket
                        $obj | Add-Member -MemberType NoteProperty -Name TimeDiffInHours -Value $([math]::Round(([datetime]::FromFileTime($data.Ticket.EndTime) - [datetime]::FromFileTime($data.Ticket.StartTime)).TotalHours,2))
                    
                        Write-Output $obj
                    }
                    else
                    {
                    
                    }                    
                }
                else
                {
                    $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
                    $LastError = [ComponentModel.Win32Exception]$WinErrorCode
                    throw "LsaCallAuthenticationPackage Error: $($LastError.Message)"
                }        
            }
        }
    }

    function LsaConnectUntrusted
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
        )
    
        $LsaHandle = [IntPtr]::Zero

        $SUCCESS = $Secur32::LsaConnectUntrusted([ref]$LsaHandle)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaConnectUntrusted Error: $($LastError.Message)"
        }

        Write-Output $LsaHandle
    }

    function LsaDeregisterLogonProcess
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $LsaHandle
        )

        $SUCCESS = $Secur32::LsaDeregisterLogonProcess($LsaHandle)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaDeregisterLogonProcess Error: $($LastError.Message)"
        }
    }

    function LsaEnumerateLogonSessions
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        $LogonSessionCount = [UInt64]0
        $LogonSessionList = [IntPtr]::Zero

        $SUCCESS = $Secur32::LsaEnumerateLogonSessions([ref]$LogonSessionCount, [ref]$LogonSessionList)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaEnumerateLogonSessions Error: $($LastError.Message)"
        }

        $obj = New-Object -TypeName psobject

        $obj | Add-Member -MemberType NoteProperty -Name SessionCount -Value $LogonSessionCount
        $obj | Add-Member -MemberType NoteProperty -Name SessionListPointer -Value $LogonSessionList
    
        Write-Output $obj
    }

    function LsaFreeReturnBuffer
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $Buffer
        )

        $SUCCESS = $Secur32::LsaFreeReturnBuffer($Buffer)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaFreeReturnBuffer Error: $($LastError.Message)"
        }
    }

    function LsaGetLogonSessionData
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $LuidPointer
        )

        $sessionDataPtr = [IntPtr]::Zero
        $SUCCESS = $Secur32::LsaGetLogonSessionData($LuidPointer, [ref]$sessionDataPtr)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $SUCCESS
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "[LsaGetLogonSessionData] Error: $($LastError.Message)"
        }

        try
        {
            $sessionData = $sessionDataPtr -as $SECURITY_LOGON_SESSION_DATA

            if($sessionData.LogonId.LowPart -eq 996)
            {
                $Upn = [System.Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]::Add($sessionData.Upn.Buffer, 2), $sessionData.Upn.Length / 2)
            }
            else
            {
                $Upn = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Upn.Buffer, $sessionData.Upn.Length / 2)
            }
                            
            New-Object -TypeName psobject -Property @{
                LogonId = $sessionData.LogonId.LowPart
                UserName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Username.Buffer, $sessionData.Username.Length / 2)
                LogonDomain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonDomain.Buffer, $sessionData.LognDomain.Length / 2)
                AuthenticationPackage = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.AuthenticationPackage.Buffer, $sessionData.AuthenticationPackage.Length / 2)
                LogonType = $sessionData.LogonType -as $SECURITY_LOGON_TYPE
                Session = $sessionData.Session
                Sid = New-Object -TypeName System.Security.Principal.SecurityIdentifier($sessionData.PSiD)
                LogonTime = [datetime]::FromFileTime($sessionData.LogonTime)
                LogonServer = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonServer.Buffer, $sessionData.LogonServer.Length / 2)
                DnsDomainName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.DnsDomainName.Buffer, $sessionData.DnsDomainName.Length / 2)
                Upn =  [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.Upn.Buffer, $sessionData.Upn.Length / 2)
                UserFlags = $sessionData.UserFlags
                LastSuccessfulLogon = $sessionData.LastLogonInfo.LastSuccessfulLogon
                LastFailedLogon = $sessionData.LastLogonInfo.LastFailedLogon
                FailedAttemptCountSinceLastSuccessfulLogon = $sessionData.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon
                LogonScript = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.LogonScript.Buffer, $sessionData.LogonScript.Length / 2)
                ProfilePath = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.ProfilePath.Buffer, $sessionData.ProfilePath.Length / 2)
                HomeDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.HomeDirectory.Buffer, $sessionData.HomeDirectory.Length / 2)
                HomeDirectoryDrive = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sessionData.HomeDirectoryDrive.Buffer, $sessionData.HomeDirectoryDrive.Length / 2)
                LogoffTime = $sessionData.LogoffTime
                KickOffTime = $sessionData.KickOffTime
                PasswordLastSet = [datetime]::FromFileTime($sessionData.PasswordLastSet)
                PasswordCanChange = [datetime]::FromFileTime($sessionData.PasswordCanChange)
                PasswordMustChange = $sessionData.PasswordMustChange
            }
        }
        catch
        {

        }

        LsaFreeReturnBuffer -Buffer $sessionDataPtr
    }

    function LsaLookupAuthenticationPackage
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $LsaHandle,

            [Parameter(Mandatory = $true)]
            [ValidateSet('MSV1_0_PACKAGE_NAME', 'MICROSOFT_KERBEROS_NAME_A', 'NEGOSSP_NAME_A', 'NTLMSP_NAME_A')]
            [string]
            $PackageName
        )

        switch($PackageName)
        {
            MSV1_0_PACKAGE_NAME {$authPackageName = 'NTLM'; break}
            MICROSOFT_KERBEROS_NAME_A {$authPackageName = 'Kerberos'; break}
            NEGOSSP_NAME_A {$authPackageName = 'Negotiate'; break}
            NTLMSP_NAME_A {$authPackageName = 'NTLM'; break}
        }

        $authPackageArray = [System.Text.Encoding]::ASCII.GetBytes($authPackageName)
        [int]$size = $authPackageArray.Length
        [IntPtr]$pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size) 
        [System.Runtime.InteropServices.Marshal]::Copy($authPackageArray, 0, $pnt, $authPackageArray.Length)
    
        $lsaString = [Activator]::CreateInstance($LSA_STRING)
        $lsaString.Length = [UInt16]$authPackageArray.Length
        $lsaString.MaximumLength = [UInt16]$authPackageArray.Length
        $lsaString.Buffer = $pnt
    
        $AuthenticationPackage = [UInt64]0

        $SUCCESS = $Secur32::LsaLookupAuthenticationPackage($LsaHandle, [ref]$lsaString, [ref]$AuthenticationPackage)
    
        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaLookupAuthenticationPackage Error: $($LastError.Message)"
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pnt)

        Write-Output $AuthenticationPackage
    }

    function LsaNtStatusToWinError
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory = $true)]
            [UInt32]
            $NtStatus
        )

        $STATUS = $Advapi32::LsaNtStatusToWinError($NtStatus)

        Write-Output $STATUS
    }

    function LsaRegisterLogonProcess
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        $lsaStringArray = [System.Text.Encoding]::ASCII.GetBytes("INVOKE-IR")
        [int]$size = $lsaStringArray.Length
        [IntPtr]$pnt = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size) 
        [System.Runtime.InteropServices.Marshal]::Copy($lsaStringArray, 0, $pnt, $lsaStringArray.Length)
    
        $lsaString = [Activator]::CreateInstance($LSA_STRING)
        $lsaString.Length = [UInt16]$lsaStringArray.Length
        $lsaString.MaximumLength = [UInt16]$lsaStringArray.Length
        $lsaString.Buffer = $pnt

        $LsaHandle = [IntPtr]::Zero
        $SecurityMode = [UInt64]0

        $SUCCESS = $Secur32::LsaRegisterLogonProcess([ref]$lsaString, [ref]$LsaHandle, [ref]$SecurityMode)

        if($SUCCESS -ne 0)
        {
            $WinErrorCode = LsaNtStatusToWinError -NtStatus $success
            $LastError = [ComponentModel.Win32Exception]$WinErrorCode
            throw "LsaRegisterLogonProcess Error: $($LastError.Message)"
        }

        Write-Output $LsaHandle
    }

    function OpenProcessToken
    { 
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        [OutputType([IntPtr])]
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory = $true)]
            [IntPtr]
            $ProcessHandle,
        
            [Parameter(Mandatory = $true)]
            [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
            [string[]]
            $DesiredAccess  
        )
    
        # Calculate Desired Access Value
        $dwDesiredAccess = 0

        foreach($val in $DesiredAccess)
        {
            $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
        }

        $hToken = [IntPtr]::Zero
        $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if(-not $Success) 
        {
            throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    
        Write-Output $hToken
    }

    function RevertToSelf
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        [CmdletBinding()]
        param
        (

        )

        $SUCCESS = $Advapi32::RevertToSelf(); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        if(-not $SUCCESS)
        {
            throw "RevertToSelf Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }
   
    function Get-LogonSession
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	License: BSD 3-Clause
	#>
        [CmdletBinding()]
        param
        (

        )

        $LogonSessions = LsaEnumerateLogonSessions
    
        $CurrentPtr = $LogonSessions.SessionListPointer

        for($i = 0; $i -lt $LogonSessions.SessionCount; $i++)
        {
            try
            {
                # Retreive details about the current logon session
                LsaGetLogonSessionData -LuidPointer $CurrentPtr
            }
            catch
            {

            }

            # Increment to the next LUID
            $CurrentPtr = [IntPtr]::Add($CurrentPtr, $LUID::GetSize())
        }
    }

    function Get-System
    {
	<#
	.NOTES
	Author: Jared Atkinson (@jaredcatkinson)
	Modified: Yossi Sassi (@yossi_sassi)
	License: BSD 3-Clause
	#>
        $proc = Get-Process -Name winlogon

        if($proc.Length -gt 1)
        {
            $proc = $proc[0]
        }

        if($proc.Handle)
        {
            # Open winlogon's Token with TOKEN_DUPLICATE Acess
            # This allows us to make a copy of the token with DuplicateToken
            $hToken = OpenProcessToken -ProcessHandle $proc.Handle -DesiredAccess TOKEN_DUPLICATE -Debug
    
            # Make a copy of the NT AUTHORITY\SYSTEM Token
            $hDupToken = DuplicateToken -TokenHandle $hToken
    
            # Apply our Duplicated Token to our Thread
            ImpersonateLoggedOnUser -TokenHandle $hDupToken
    
            # Clean up the handles we created
            CloseHandle -Handle $hToken
            CloseHandle -Handle $hDupToken

            if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'NT AUTHORITY\SYSTEM')
            {
                throw "Unable to Impersonate System Token"
            }
        }
        else
        {
            throw "Unable to Impersonate System Token"
        }
    }
    
    try
    {
        $hLsa = LsaRegisterLogonProcess
    }
    catch
    {
        Get-System
        $hLsa = LsaRegisterLogonProcess

        RevertToSelf
    }

    if($hLsa)
    {
        # Enumerate all Logon Sessions
        $Sessions = Get-LogonSession

        foreach($Session in $Sessions)
        {
            # Get the tickets from the LSA provider
            $ticket = LsaCallAuthenticationPackage -LsaHandle $hLsa -AuthenticationPackageName MICROSOFT_KERBEROS_NAME_A -LogonId $Session.LogonId 

            if($ticket -ne $null)
            {
                # Add properties from the Logon Session to the ticket
                $ticket | Add-Member -MemberType NoteProperty -Name SessionLogonId -Value $Session.LogonId
		# added conversion to string LUID (YossiS)
                $ticket | Add-Member -MemberType NoteProperty -Name SessionLogonIdString -Value "0x$([convert]::ToString($Session.LogonId,16))"
                $ticket | Add-Member -MemberType NoteProperty -Name SessionUserName -Value $Session.UserName
                $ticket | Add-Member -MemberType NoteProperty -Name SessionUserPrincipalName -Value $Session.Upn
                $ticket | Add-Member -MemberType NoteProperty -Name SessionLogonType -Value ([string]$Session.LogonType)
                $ticket | Add-Member -MemberType NoteProperty -Name SessionAuthenticationPackage -Value $Session.AuthenticationPackage
                $ticket | Add-Member -MemberType NoteProperty -Name SessionLogonServer -Value $Session.LogonServer
                $ticket | Add-Member -MemberType NoteProperty -Name SessionSid -Value $Session.Sid
                $ticket | Add-Member -MemberType NoteProperty -Name SessionID -Value $Session.Session

                # Output the ticket
                Write-Output $ticket
            }
        }

        # Cleanup our LSA Handle
        LsaDeregisterLogonProcess -LsaHandle $hLsa
    }
}

Get-KerberosTicketGrantingTicket