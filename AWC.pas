unit AWC;

{ AmirWeb
  { Amir Fadaeian
  { Version 1.2.0
  { Date : 98/10/28
  { Last Update : 98/11/13
  { Copyright (c) 2020 AmirWeb.me
  { ALL RIGHTS RESERVED
  {
  { Author: Amir Fadaeian
  { Contaqh : AmirWeb.me
  {
  AWC_RestartApp                 ریست برنامه
  AWC_DownloadFile               دانلود فایل
  AWC_GetMACAddress              IP یافتن مک آدرس از روی
  AWC_GetAppVersionStr            ّ  نسخه برنامه
  AWC_PortIsOpen                 بررسی باز بودن پورت
  AWC_LoadFileToStr              بارگزاری فایل متنی در متغیر رشته ای
  AWC_GetTreeSize                بدست اوردن حجم پوشه
  AWC_KeyboardFA                 کیبورد فارسی
  AWC_KeyboardEN                 کیورد انگلیسی
  AWC_StrToMD5                   MD5 بدست آوردن هش
  AWC_CheckCodeMeli              بررسی صحت کد ملی
  AWC_RunAdmin                   اجرای با دسترسی مدیر
  AWC_RunAsAdminWaitCompletion   اجرا با دسترسی مدیر و انتظار برای پایان
  AWC_GetSysDir                  System32 مسیر
  AWC_WindowsPath                مسیر ویندوز
  AWC_GetTempDir                 Temp مسیر
  AWC_ConvertBytes               مبدل واحد حجم
  AWC_ServiceRunning             وضعیت سرویس
  AWC_IsWindows64                تشخیص معماری ویندوز
  AWC_OpenWebLink                باز کردن آدرس در مرورگر
  AWC_SecsToTimeStr              مبدل ثانیه به ذقیقه
  AWC_HostIPAddress              سیستم IP بدست آوردن
  AWC_GetWANAddress              اینترنت IP بدست آوردن
  AWC_PingBool                   ping با True/False
  AWC_PingString                 Ping نتیجه
  AWC_ActiveCaption              نمایش عنوان پنجره  فعال در ویندوز
  AWC_SecondsIdle                زمان بیکار بودن سیسم به ثانیه
  AWC_SecToTime                  تبدیل ساعت به فرمت زمان
  AWC_String2Bin                 متن به باینری
  AWC_String2Hex                 متن به هگزادسیمال
  AWC_Hex2String                 هگزا دسیمال به متن
  AWC_Bin2Hex                    باینری به هگزادسیمال
  AWC_Base64Encode               Base64  اینکدینگ
  AWC_Base64Decode               Base64  دیکدینگ
  AWC_HashSearch                 جستجوی هش در دیتابیس آنلاین
  AWC_CreateShortcut             ساخت میانبر

  36 تابع
}
interface

uses
  Winapi.Windows, Vcl.Controls, Vcl.StdCtrls, Winapi.Messages, System.SysUtils,
  System.Variants, IdHashMessageDigest, System.Math, Winapi.WinSvc, IdHTTP,
  ActiveX, ComObj, System.NetEncoding, ShlObj, Registry,
  System.Classes, Winsock, Vcl.Forms, Winapi.WinInet, UrlMon, ShellAPI;

function AWC_RestartApp(Handle: DWord): boolean;
function AWC_DownloadFile(SourceFile, DestFile: string): boolean;
function AWC_GetMACAddress(const IPAddress: String): String;
function AWC_GetAppVersionStr: string;
function AWC_PortIsOpen(dwPort: Word; ipAddressStr: AnsiString): boolean;
function AWC_LoadFileToStr(const FileName: TFileName): AnsiString;
function AWC_GetTreeSize(path: string): Integer;
function AWC_KeyboardFA: boolean;
function AWC_KeyboardEN: boolean;
function AWC_StrToMD5(STR: string): string;
function AWC_CheckCodeMeli(MelliCode: string): boolean;
function AWC_RunAdmin(Handle: DWord; FileName, Para: String;
  Hide: boolean): boolean;
function AWC_RunAsAdminWaitCompletion(hWnd: hWnd; FileName: string;
  Parameters: string): boolean;
function AWC_GetSysDir: string;
function AWC_ConvertBytes(Bytes: Int64): string;
function AWC_GetTempDir: string;
function AWC_ServiceRunning(sMachine, sService: PChar): boolean;
function AWC_IsWindows64: boolean;
function AWC_OpenWebLink(URL: string): boolean;
function AWC_WindowsPath: string;
function AWC_SecsToTimeStr(const Secs: Integer;
  const LeadingZero: boolean = False): String;
function AWC_HostIPAddress: string;
function AWC_GetWANAddress: String;
function AWC_PingBool(const Address: string): boolean;
function AWC_PingString(const Address: string): string;
function AWC_ActiveCaption: string;
function AWC_SecondsIdle: DWord;
function AWC_SecToTime(Sec: Integer): string;
function AWC_String2Bin(const s: AnsiString): String;
function AWC_String2Hex(const Buffer: AnsiString): string;
function AWC_Hex2String(const Buffer: string): AnsiString;
function AWC_Bin2Hex(BinStr: string): string;
function AWC_Base64Encode(const s: String): String;
function AWC_Base64Decode(const Base64String: String): String;
function AWC_HashSearch(hash, hash_type: String): String;

type
  ShortcutType = (ـStartup, _DESKTOP, _QUICKLAUNCH, _SENDTO, _STARTMENU,
    _OTHERFOLDER);

function AWC_CreateShortcut(SourceFileName: string; Location: ShortcutType;
  SubFolder, WorkingDir, Parameters, Description: string): string;

function SendARP(DestIp: DWord; srcIP: DWord; pMacAddr: pointer;
  PhyAddrLen: pointer): DWord; stdcall; external 'iphlpapi.dll';

type
  TProcessorArchitecture = (paUnknown, // unknown processor
    pax8632, // x86 32 bit processors (some P4, Celeron, Athlon and older)
    pax8664, // x86 64 bit processors (latest P4, Celeron and Athlon64)
    paIA64); // Itanium processors

const
  BufferSize: Word = 32;

var
  CachedGetProcessorArchitecture: DWord = DWord(-1);

implementation

// ****************************************************************************//
function AWC_Base64Decode(const Base64String: String): String;
{ Base64 رمز گشایی }
begin
  try
    Result := TNetEncoding.base64.Decode(Base64String);
  except
    Result := '';
  end;
end;

// ****************************************************************************//
function AWC_Base64Encode(const s: String): String; { Base64 رمز کردن }
begin
  try
    Result := TNetEncoding.base64.Encode(s);
  except
    Result := '';
  end;
end;

// ****************************************************************************//
function AWC_String2Bin(const s: AnsiString): String; { Text to binary }
const
  SBits: array [0 .. 1] of string = ('0', '1');
var
  i, k, t: Integer;
  schar: string;
begin
  Result := '';
  for i := 1 to Length(s) do
  begin
    t := Ord(s[i]);
    schar := '';
    for k := 1 to 8 * SizeOf(AnsiChar) do
    begin
      schar := SBits[t mod 2] + schar;
      t := t div 2
    end;
    Result := Result + schar;
  end;
end;

// ****************************************************************************//
function AWC_String2Hex(const Buffer: AnsiString): string;
{ Text to hexadecimal }
begin
  SetLength(Result, Length(Buffer) * 2);
  BinToHex(PAnsiChar(Buffer), PChar(Result), Length(Buffer));
end;

// ****************************************************************************//
function AWC_Hex2String(const Buffer: string): AnsiString;
{ hexadecimal to binary }
begin
  SetLength(Result, Length(Buffer) div 2);
  HexToBin(PChar(Buffer), PAnsiChar(Result), Length(Result));
end;

// ****************************************************************************//
function AWC_Bin2Hex(BinStr: string): string; { binary to hexadecimal }
const
  BinArray: array [0 .. 15, 0 .. 1] of string = (('0000', '0'), ('0001', '1'),
    ('0010', '2'), ('0011', '3'), ('0100', '4'), ('0101', '5'), ('0110', '6'),
    ('0111', '7'), ('1000', '8'), ('1001', '9'), ('1010', 'A'), ('1011', 'B'),
    ('1100', 'C'), ('1101', 'D'), ('1110', 'E'), ('1111', 'F'));
var
  Error: boolean;
  j: Integer;
  BinPart: string;
begin
  Result := '';
  Error := False;
  for j := 1 to Length(BinStr) do
    if not(BinStr[j] in ['0', '1']) then
    begin
      Error := True;
      // ShowMessage('This is not binary number');
      Break;
    end;
  if not Error then
  begin
    case Length(BinStr) mod 4 of
      1:
        BinStr := '000' + BinStr;
      2:
        BinStr := '00' + BinStr;
      3:
        BinStr := '0' + BinStr;
    end;

    while Length(BinStr) > 0 do
    begin
      BinPart := Copy(BinStr, Length(BinStr) - 3, 4);
      Delete(BinStr, Length(BinStr) - 3, 4);
      for j := 1 to 16 do
        if BinPart = BinArray[j - 1, 0] then
          Result := BinArray[j - 1, 1] + Result;
    end;
  end;
end;

// ****************************************************************************//
function AWC_ActiveCaption: string; { نمایش عنوان پنجره  فعال در ویندوز }
var
  Handle: THandle;
  Len: Longint;
  Title: string;
begin
  Result := '';
  Handle := GetForegroundWindow;
  if Handle <> 0 then
  begin
    Len := GetWindowTextLength(Handle) + 1;
    SetLength(Title, Len);
    GetWindowText(Handle, PChar(Title), Len);
    AWC_ActiveCaption := TrimRight(Title);
  end;
end;

// ****************************************************************************//
function GetStatusCodeStr(statusCode: Integer): string;
begin
  case statusCode of
    0:
      Result := 'Success';
    11001:
      Result := 'Buffer Too Small';
    11002:
      Result := 'Destination Net Unreachable';
    11003:
      Result := 'Destination Host Unreachable';
    11004:
      Result := 'Destination Protocol Unreachable';
    11005:
      Result := 'Destination Port Unreachable';
    11006:
      Result := 'No Resources';
    11007:
      Result := 'Bad Option';
    11008:
      Result := 'Hardware Error';
    11009:
      Result := 'Packet Too Big';
    11010:
      Result := 'Request Timed Out';
    11011:
      Result := 'Bad Request';
    11012:
      Result := 'Bad Route';
    11013:
      Result := 'TimeToLive Expired Transit';
    11014:
      Result := 'TimeToLive Expired Reassembly';
    11015:
      Result := 'Parameter Problem';
    11016:
      Result := 'Source Quench';
    11017:
      Result := 'Option Too Big';
    11018:
      Result := 'Bad Destination';
    11032:
      Result := 'Negotiating IPSEC';
    11050:
      Result := 'General Failure'
  else
    Result := 'Unknow';
  end;
end;

// ****************************************************************************//
function AWC_PingBool(const Address: string): boolean; { Ping Boolean }
var
  FSWbemLocator: OLEVariant;
  FWMIService: OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject: OLEVariant;
  oEnum: IEnumvariant;
  iValue: LongWord;
  i: Integer;
  PacketsReceived: Integer;
begin;
  Result := False;
  PacketsReceived := 0;
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService := FSWbemLocator.ConnectServer('localhost', 'root\CIMV2', '', '');
  FWbemObjectSet := FWMIService.ExecQuery
    (Format('SELECT * FROM Win32_PingStatus where Address=%s AND BufferSize=%d',
    [QuotedStr(Address), BufferSize]), 'WQL', 0);
  oEnum := IUnknown(FWbemObjectSet._NewEnum) as IEnumvariant;
  if oEnum.Next(1, FWbemObject, iValue) = 0 then
  begin
    if FWbemObject.statusCode = 0 then
    begin
        Result := True
    end
  end;
  FWbemObject := Unassigned;
  FWbemObjectSet := Unassigned;
end;

// ****************************************************************************//
function AWC_PingString(const Address: string): string; { Ping String Result }
var
  FSWbemLocator: OLEVariant;
  FWMIService: OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject: OLEVariant;
  oEnum: IEnumvariant;
  iValue: LongWord;
  i: Integer;
  PacketsReceived: Integer;
  Minimum: Integer;
  Maximum: Integer;
  Average: Integer;
begin;
  // Result := 'پاسخ نمی دهد';
  PacketsReceived := 0;
  Minimum := 0;
  Maximum := 0;
  Average := 0;
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService := FSWbemLocator.ConnectServer('localhost', 'root\CIMV2', '', '');
  begin
    FWbemObjectSet := FWMIService.ExecQuery
      (Format('SELECT * FROM Win32_PingStatus where Address=%s AND BufferSize=%d',
      [QuotedStr(Address), BufferSize]), 'WQL', 0);
    oEnum := IUnknown(FWbemObjectSet._NewEnum) as IEnumvariant;
    if oEnum.Next(1, FWbemObject, iValue) = 0 then
    begin
      if FWbemObject.statusCode = 0 then
      begin
        if FWbemObject.ResponseTime > 0 then
          Result := Format('Reply from %s: bytes=%s time=%sms TTL=%s',
            [FWbemObject.ProtocolAddress, FWbemObject.ReplySize,
            FWbemObject.ResponseTime, FWbemObject.TimeToLive])
        else
          Result := Format('Reply from %s: bytes=%s time=<1ms TTL=%s',
            [FWbemObject.ProtocolAddress, FWbemObject.ReplySize,
            FWbemObject.TimeToLive]);
      end
      else if not VarIsNull(FWbemObject.statusCode) then
        Result := Format('Reply from %s: %s', [FWbemObject.ProtocolAddress,
          GetStatusCodeStr(FWbemObject.statusCode)])
      else
        Result := Format('Reply from %s: %s',
          [Address, 'Error processing request']);
    end;
    FWbemObject := Unassigned;
    FWbemObjectSet := Unassigned;
  end;
end;

// ****************************************************************************//
function AWC_GetAppVersionStr: string; { Get current Version }
var
  Exe: string;
  Size, Handle: DWord;
  Buffer: TBytes;
  FixedPtr: PVSFixedFileInfo;
begin
  Exe := ParamStr(0);
  Size := GetFileVersionInfoSize(PChar(Exe), Handle);
  if Size = 0 then
    RaiseLastOSError;
  SetLength(Buffer, Size);
  if not GetFileVersionInfo(PChar(Exe), Handle, Size, Buffer) then
    RaiseLastOSError;
  if not VerQueryValue(Buffer, '\', pointer(FixedPtr), Size) then
    RaiseLastOSError;
  Result := Format('%d.%d', [LongRec(FixedPtr.dwFileVersionMS).Hi,
    LongRec(FixedPtr.dwFileVersionMS).Lo])
end;

// ****************************************************************************//
function AWC_PortIsOpen(dwPort: Word; ipAddressStr: AnsiString): boolean;
{ Portcheck }
var
  Client: sockaddr_in;
  sock: Integer;

  ret: Integer;
  wsdata: WSAData;
begin
  Result := False;
  ret := WSAStartup($0002, wsdata); // initiates use of the Winsock DLL
  if ret <> 0 then
    exit;
  try
    Client.sin_family := AF_INET;
    // Set the protocol to use , in this case (IPv4)
    Client.sin_port := htons(dwPort);
    // convert to TCP/IP network byte order (big-endian)
    Client.sin_addr.s_addr := inet_addr(PAnsiChar(ipAddressStr));
    // convert to IN_ADDR  structure
    sock := socket(AF_INET, SOCK_STREAM, 0); // creates a socket
    Result := connect(sock, Client, SizeOf(Client)) = 0;
    // establishes a connection to a specified socket
  finally
    WSACleanup;
  end;
end;

// ****************************************************************************//
function AWC_GetMACAddress(const IPAddress: String): String; { GetMACAddress }
var
  DestIp: ULONG;
  MacAddr: Array [0 .. 5] of Byte;
  MacAddrLen: ULONG;
  SendArpResult: Cardinal;
begin
  DestIp := inet_addr(PAnsiChar(AnsiString(IPAddress)));
  MacAddrLen := Length(MacAddr);
  SendArpResult := SendARP(DestIp, 0, @MacAddr, @MacAddrLen);

  if SendArpResult = NO_ERROR then
    Result := Format('%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',
      [MacAddr[0], MacAddr[1], MacAddr[2], MacAddr[3], MacAddr[4], MacAddr[5]])
  else
    Result := '';
end;

// ****************************************************************************//
function AWC_DownloadFile(SourceFile, DestFile: string): boolean;
{ دانلود فایل }
begin
  try
    DeleteUrlCacheEntry(PChar(SourceFile));
    Result := UrlDownloadToFile(nil, PChar(SourceFile), PChar(DestFile),
      0, nil) = 0;
  except
    Result := False;
  end;
end;

// ****************************************************************************//
function AWC_LoadFileToStr(const FileName: TFileName): AnsiString;
{ فایل به استرنگ }
var
  FileStream: TFileStream;
begin
  FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    if FileStream.Size > 0 then
    begin
      SetLength(Result, FileStream.Size);
      FileStream.Read(pointer(Result)^, FileStream.Size);
    end;
  finally
    FileStream.Free;
  end;
end;

// ****************************************************************************//
function AWC_RestartApp(Handle: DWord): boolean; { ریست برنامه }
begin
  ShellExecute(Handle, nil, PChar(Application.ExeName), nil, nil,
    SW_SHOWNORMAL);
  Application.Terminate;
end;

// ****************************************************************************//
function AWC_RunAdmin(Handle: DWord; FileName, Para: String;
  { اجرا با دسترسی مدیر }
  Hide: boolean): boolean;
begin
  if Hide then
  begin
    ShellExecute(Handle, 'RunAs', PChar(FileName), PChar(Para), nil, SW_HIDE);
  end
  else
  begin
    ShellExecute(Handle, 'RunAs', PChar(FileName), PChar(Para), nil, SW_SHOW);
  end;
end;

// ****************************************************************************//
function AWC_GetTreeSize(path: string): Integer; { بدست آوردن حجم پوشه }
var
  tsr: TSearchRec;
begin
  Result := 0;
  path := IncludeTrailingBackSlash(path);
  if FindFirst(path + '*', faAnyFile, tsr) = 0 then
  begin
    repeat
      if (tsr.attr and faDirectory) > 0 then
      begin
        if (tsr.name <> '.') and (tsr.name <> '..') then
          Inc(Result, AWC_GetTreeSize(path + tsr.name));
      end
      else
        Inc(Result, tsr.Size);
    until FindNext(tsr) <> 0;
    FindClose(tsr);
  end;
end;

// ****************************************************************************//
function AWC_KeyboardFA: boolean; { کیبورد فارسی }
begin
  LoadKeyboardLayout('00000429', KLF_ACTIVATE);
end;

// ****************************************************************************//
function AWC_KeyboardEN: boolean; { کیبورد انگلیسی }
begin
  LoadKeyboardLayout('00000409', KLF_ACTIVATE);
end;

// ****************************************************************************//
function AWC_StrToMD5(STR: string): string; { String To MD5 }
var
  pMD5: TIdHashMessageDigest5;
begin
  Result := '';
  pMD5 := TIdHashMessageDigest5.Create;
  try
    Result := pMD5.HashStringAsHex(STR);
  finally
    pMD5.Free;
  end;
end;

// ****************************************************************************//
function GetNumber(STR: String): String; { بررسی کد ملی }
var
  i: Integer;
begin
  Result := '';
  for i := 1 to Length(STR) do
    if (STR[i] in ['0' .. '9']) then
      Result := Result + STR[i];
end;

// ****************************************************************************//
function AWC_CheckCodeMeli(MelliCode: string): boolean;
var
  i, Sum, Mon, Chk: Integer;
begin
  Result := False;
  MelliCode := GetNumber(MelliCode);
  while Length(Trim(MelliCode)) < 10 do
    MelliCode := '0' + MelliCode;

  If (MelliCode = '0000000000') or (MelliCode = '1111111111') Or
    (MelliCode = '2222222222') or (MelliCode = '3333333333') Or
    (MelliCode = '4444444444') or (MelliCode = '5555555555') Or
    (MelliCode = '6666666666') or (MelliCode = '7777777777') Or
    (MelliCode = '8888888888') or (MelliCode = '9999999999') Then
    exit;
  Chk := StrToInt(Copy(MelliCode, 10, 1));
  Sum := 0;
  for i := 1 to 9 do
    Sum := Sum + StrToInt(Copy(MelliCode, i, 1)) * (11 - i);
  Mon := Sum mod 11;
  if ((Mon < 2) and (Chk = Mon)) or ((Mon >= 2) and (Chk = (11 - Mon))) then
    Result := True;
end;

// ****************************************************************************//
function AWC_RunAsAdminWaitCompletion(hWnd: hWnd; FileName: string;
  { اجرا با دسترسی مدیر و انتظار برای پایان }
  Parameters: string): boolean;
var
  sei: TShellExecuteInfo;
  ExitCode: DWord;
begin
  ZeroMemory(@sei, SizeOf(sei));
  sei.cbSize := SizeOf(TShellExecuteInfo);
  sei.Wnd := hWnd;
  sei.fMask := SEE_MASK_FLAG_DDEWAIT or SEE_MASK_FLAG_NO_UI or
    SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb := PChar('runas');
  sei.lpFile := PChar(FileName); // PAnsiChar;
  if Parameters <> '' then
    sei.lpParameters := PChar(Parameters); // PAnsiChar;
  sei.nShow := SW_HIDE; // Integer;
  if ShellExecuteEx(@sei) then
  begin
    repeat
      Application.ProcessMessages;
      GetExitCodeProcess(sei.hProcess, ExitCode);
    until (ExitCode <> STILL_ACTIVE) or Application.Terminated;
  end;
  Result := True;
end;

// ****************************************************************************//
function AWC_GetSysDir: string; { بدست آوردن درایو ویندوز }
var
  Buffer: array [0 .. MAX_PATH] of Char;
begin
  GetSystemDirectory(Buffer, MAX_PATH - 1);
  SetLength(Result, StrLen(Buffer));
  Result := Buffer;
end;

// ****************************************************************************//
function AWC_ConvertBytes(Bytes: Int64): string; { مبدل واحد حجم }
const
  Description: Array [0 .. 8] of string = ('Bytes', 'KB', 'MB', 'GB', 'TB',
    'PB', 'EB', 'ZB', 'YB');
var
  i: Integer;
begin
  i := 0;

  while Bytes > Power(1024, i + 1) do
    Inc(i);

  Result := FormatFloat('###0.##', Bytes / IntPower(1024, i)) + ' ' +
    Description[i];
end;

// ****************************************************************************//
function AWC_GetTempDir: string; { بدست آوردن مسیر پوشه Temp }
begin
  Result := GetEnvironmentVariable('TEMP');
end;

// ****************************************************************************//
function ServiceGetStatus(sMachine, sService: PChar): DWord; { وضعیت سرویس }
var
  SCManHandle, SvcHandle: SC_Handle;
  SS: TServiceStatus;
  dwStat: DWord;
begin
  dwStat := 0;
  // Open service manager handle.
  SCManHandle := OpenSCManager(sMachine, nil, SC_MANAGER_CONNECT);
  if (SCManHandle > 0) then
  begin
    SvcHandle := OpenService(SCManHandle, sService, SERVICE_QUERY_STATUS);
    // if Service installed
    if (SvcHandle > 0) then
    begin
      // SS structure holds the service status (TServiceStatus);
      if (QueryServiceStatus(SvcHandle, SS)) then
        dwStat := SS.dwCurrentState;
      CloseServiceHandle(SvcHandle);
    end;
    CloseServiceHandle(SCManHandle);
  end;
  Result := dwStat;
end;

// ****************************************************************************//
function AWC_ServiceRunning(sMachine, sService: PChar): boolean; { اجرای سرویس }
begin
  Result := SERVICE_RUNNING = ServiceGetStatus(sMachine, sService);
end;

// ****************************************************************************//
function GetProcessorArchitecture: TProcessorArchitecture;
var
  ASystemInfo: TSystemInfo;
begin
  if CachedGetProcessorArchitecture = DWord(-1) then
  begin
    ASystemInfo.dwOemId := 0;
    GetNativeSystemInfo(ASystemInfo);
    CachedGetProcessorArchitecture := ASystemInfo.wProcessorArchitecture;
  end;
  case CachedGetProcessorArchitecture of
    PROCESSOR_ARCHITECTURE_INTEL:
      Result := pax8632;
    PROCESSOR_ARCHITECTURE_IA64:
      Result := paIA64;
    PROCESSOR_ARCHITECTURE_AMD64:
      Result := pax8664;
  else
    Result := paUnknown;
  end;
end;

// ****************************************************************************//
function AWC_IsWindows64: boolean; { تشخیص معماری ویندوز }
begin
  Result := GetProcessorArchitecture in [paIA64, pax8664];
end;

function AWC_OpenWebLink(URL: string): boolean;
begin
  URL := StringReplace(URL, '"', '%22', [rfReplaceAll]);
  ShellExecute(0, 'open', PChar(URL), nil, nil, SW_SHOWNORMAL);
end;

// ****************************************************************************//
function AWC_WindowsPath: string; { دایرکتوری ویندوز }
begin
  SetLength(Result, MAX_PATH);
  SetLength(Result, GetWindowsDirectory(@Result[1], MAX_PATH));
end;

// ****************************************************************************//
function AWC_SecsToTimeStr(const Secs: Integer; { تبدیل دقیقه به ساعت }
  const LeadingZero: boolean = False): String;
begin
  if Secs >= SecsPerHour then
  begin
    if LeadingZero then
      Result := FormatDateTime('hh:nn:ss', Secs / SecsPerDay)
    else
      Result := FormatDateTime('h:n:ss', Secs / SecsPerDay)
  end
  else
  begin
    if LeadingZero then
      Result := FormatDateTime('nnss', Secs / SecsPerDay)
    else
      Result := FormatDateTime('nss', Secs / SecsPerDay)
  end;
end;

// ****************************************************************************//
function AWC_HostIPAddress: string; { Host Name IP }
var
  wsdata: Winsock.TWSAData; // details of WinSock implementation
  HostName: array [0 .. 14] of AnsiChar; // standard host name of local machine
  HostEnt: Winsock.PHostEnt; // info about host
  Addr: PAnsiChar; // pointer to list of addresses
begin
  Result := '0.0.0.0';
  if Winsock.WSAStartup(MakeWord(1, 1), wsdata) <> 0 then
    exit;
  try
    Winsock.GetHostName(HostName, SizeOf(HostName));
    HostEnt := Winsock.GetHostByName(HostName);
    if Assigned(HostEnt) and Assigned(HostEnt^.h_addr_list) then
    begin
      Addr := HostEnt^.h_addr_list^;
      if Assigned(Addr) and (HostEnt^.h_length >= 4) then
      begin
        Result := Format('%d.%d.%d.%d', [Ord(Addr[0]), Ord(Addr[1]),
          Ord(Addr[2]), Ord(Addr[3])]);
      end;
    end;
  finally
    WSACleanup;
  end;
end;

// ****************************************************************************//
function AWC_GetWANAddress: String; { IP WAN }
var
  Req: TIdHTTP; // Indy
  BOF, EOF: Integer;
begin
  Result := 'Not available';
  Req := TIdHTTP.Create(nil);
  try
    Result := Req.Get('http://checkip.dyndns.org/');
    BOF := Pos(':', Result);
    Delete(Result, 1, BOF + 1);
    EOF := Pos('</', Result);
    Delete(Result, EOF, Length(Result));
  finally
    Req.Free;
  end;
end;

// ****************************************************************************//
function AWC_SecondsIdle: DWord; { زمان بیکاری سیستم }
var
  liInfo: TLastInputInfo;
begin
  liInfo.cbSize := SizeOf(TLastInputInfo);
  GetLastInputInfo(liInfo);
  Result := (GetTickCount - liInfo.dwTime) DIV 1000;
end;

// ****************************************************************************//
function AWC_SecToTime(Sec: Integer): string; { ثانیه به زمان }
var
  H, M, s: string;
  ZH, ZM, ZS: Integer;
begin
  ZH := Sec div 3600;
  ZM := Sec div 60 - ZH * 60;
  ZS := Sec - (ZH * 3600 + ZM * 60);
  H := IntToStr(ZH);
  M := IntToStr(ZM);
  s := IntToStr(ZS);
  Result := H + ':' + M + ':' + s;
end;

// ****************************************************************************//
function AWC_HashSearch(hash, hash_type: String): String;
{ جستجوی هش در دیتابیس آنلاین }
var
  URL: string;
  H: TIdHTTP;
  SS: TStringStream;
begin
  URL := 'https://md5decrypt.net/en/Api/api.php?hash=' + hash + '&hash_type=' +
    hash_type + '&email=akmfad1@yahoo.com&code=248e83c7514d2dfc';
  try
    try
      H := TIdHTTP.Create(nil);
      H.Request.UserAgent :=
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0';
      SS := TStringStream.Create(nil);
      try
        H.Get(URL, SS);
        Result := SS.DataString;
        if Result = 'ERROR CODE : 001' then
        begin
          Result := 'محدودیت روزانه با پایان رسیده است'
        end
        else if Result = 'ERROR CODE : 002' then
        begin
          Result := 'اشکال در مشخصات کاربری'
        end
        else if Result = 'ERROR CODE : 003' then
        begin
          Result := 'درخواست بیش از حد مجاز'
        end
        else if Result = 'ERROR CODE : 004' then
        begin
          Result := 'نوع هش معتبر نمی‌باشد'
        end
        else if Result = 'ERROR CODE : 005' then
        begin
          Result := 'هش با نوع هش تشخیص داده نشد'
        end
        else if Result = 'ERROR CODE : 006' then
        begin
          Result := 'اشکال در درخواست'
        end
        else if Result = '' then
        begin
          Result := 'پاسخ در دیتابیس یافت نشد'
        end
      Except
        Result := 'سرور پاسخ نمی‌دهد'
      end;

    finally
      SS.Free;
    end;
  finally
    H.Free
  end;
end;

// ****************************************************************************//
function AWC_CreateShortcut(SourceFileName: string; Location: ShortcutType;
  SubFolder, WorkingDir, Parameters, Description: string): string;
{ ایجاد میانبر }
const
  SHELL_FOLDERS_ROOT = 'Software\MicroSoft\Windows\CurrentVersion\Explorer';
  QUICK_LAUNCH_ROOT = 'Software\MicroSoft\Windows\CurrentVersion\GrpConv';
var
  MyObject: IUnknown;
  MySLink: IShellLink;
  MyPFile: IPersistFile;
  Directory, LinkName: string;
  WFileName: WideString;
  Reg: TRegIniFile;
begin

  MyObject := CreateComObject(CLSID_ShellLink);
  MySLink := MyObject as IShellLink;
  MyPFile := MyObject as IPersistFile;

  MySLink.SetPath(PChar(SourceFileName));
  MySLink.SetArguments(PChar(Parameters));
  MySLink.SetDescription(PChar(Description));

  LinkName := ChangeFileExt(SourceFileName, '.lnk');
  LinkName := ExtractFileName(LinkName);

  // Quicklauch
  if Location = _QUICKLAUNCH then
  begin
    Reg := TRegIniFile.Create(QUICK_LAUNCH_ROOT);
    try
      Directory := Reg.ReadString('MapGroups', 'Quick Launch', '');
    finally
      Reg.Free;
    end;
  end
  else
  // Other locations
  begin
    Reg := TRegIniFile.Create(SHELL_FOLDERS_ROOT);
    try
      case Location of
        _OTHERFOLDER:
          Directory := SubFolder;
        _DESKTOP:
          Directory := Reg.ReadString('Shell Folders', 'Desktop', '');
        _STARTMENU:
          Directory := Reg.ReadString('Shell Folders', 'Start Menu', '');
        _SENDTO:
          Directory := Reg.ReadString('Shell Folders', 'SendTo', '');
        ـStartup:
          Directory := Reg.ReadString('Shell Folders', 'Startup', '');
      end;
    finally
      Reg.Free;
    end;
  end;

  if Directory <> '' then
  begin
    if (SubFolder <> '') and (Location <> _OTHERFOLDER) then
      WFileName := Directory + '\' + SubFolder + '\' + LinkName
    else
      WFileName := Directory + '\' + LinkName;

    if WorkingDir = '' then
      MySLink.SetWorkingDirectory(PChar(ExtractFilePath(SourceFileName)))
    else
      MySLink.SetWorkingDirectory(PChar(WorkingDir));

    MyPFile.Save(PWChar(WFileName), False);
    Result := WFileName;
  end;
end;
// ****************************************************************************//

end.
