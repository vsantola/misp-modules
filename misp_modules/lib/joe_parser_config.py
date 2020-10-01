#
# This file holds threat mappings and ignore lists for misp-modules joe_parser
# 

# threat name mapping between malpedia and joe sandbox
# dict("MALPEDIA_THREATNAME": ['JOE_THREATNAME', 'JOE_TRHEATNAME'])

threatname_mapping = {'Agent Tesla': ['AgentTesla'],
                      'Dridex': ['Dridex Dropper'],
                      'MASS Logger': ['MassLogger RAT'],
                      'Ave Maria': ['AveMaria']
                     }

# the following filenames will be ignored to prevent dummy correlations in misp
ignore_filenames_exact = [
        "%APPDATA%\\Adobe\\Acrobat\\DC",
        "%APPDATA%\\Adobe\\Acrobat\\DC\\Security\\ES_session_storek",
        "%APPDATA%\\Adobe\\Headlights",
        "%APPDATA%\\Adobe\\Linguistics",
        "%APPDATA%\\Adobe\\LogTransport2"
        "%APPDATA%\\Microsoft\\Forms",
        "%APPDATA%\\Microsoft\\Forms\\WINWORD.box",
        "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\desktop.ini",
        "%APPDATA%\\Microsoft\\Office\\Recent\\index.dat",
        "%APPDATA%\\Microsoft\\Speech",
        "%APPDATA%\\Microsoft\\Templates\\~$Normal.dotm",
        "%APPDATA%\\Microsoft\\Templates\\Normal.dotm",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\desktop.ini",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\desktop.ini",
        "%LOCALAPPDATA%\\Adobe\\Color",
        "%LOCALAPPDATA%\\CEF",
        "%LOCALAPPDATA%\\Microsoft\\Internet Explorer\\Recovery",
        "%LOCALAPPDATA%\\Microsoft\\Office\\15.0",
        "%LOCALAPPDATA%\\microsoft\\office\\OTeleData_2236_1.etl",
        "%LOCALAPPDATA%\\microsoft\\office\\OTeleData_2236_2.etl",
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Caches",
        "%PROGRAMFILES%\\(x86)\\Common Files\\microsoft shared\\OFFICE15\\MSO.DLL",
        "%PROGRAMFILES%\\(x86)\\Common Files\\microsoft shared\\VBA\\VBA6\\VBE6EXT.OLB",
        "%PROGRAMFILES%\\(x86)\\Common Files\\microsoft shared\\VBA\\VBA7.1\\VBE7.DLL",
        "%PROGRAMFILES%\\(x86)\\Internet Explorer\\iexplore.exe",
        "%PROGRAMFILES%\\(x86)\\Microsoft Office\\Office15\\MSWORD.OLB",
        "%PROGRAMFILES%\\(x86)\\Microsoft Office\\Office15\\WINWORD.EXE",
        "%TEMP%\\~$imgs.htm",
        "%TEMP%\\acrocef_low",
        "%TEMP%\\acrord32_sbx",
        "%TEMP%\\CVR8743.tmp.cvr",
        "%TEMP%\\VBE",
        "%TEMP%\\VBE\\MSForms.exd",
        "%USERPROFILE%\\AppData\\Local",
        "%USERPROFILE%\\AppData\\Roaming",
        "%WINDIR%\\Fonts\\StaticCache.dat",
        "%WINDIR%\\System32\\spool\\drivers\\color\\sRGB Color Space Profile.icm",
        "%WINDIR%\\SysWOW64\\FM20.DLL",
        "%WINDIR%\\SysWOW64\\ieframe.dll",
        "%WINDIR%\\SysWOW64\\scrrun.dll",
        "%WINDIR%\\SysWOW64\\stdole2.tlb",
        "%WINDIR%\\SysWOW64\\wbem\\wbemdisp.tlb",
        "C:\\WINDOWS\\win.ini",
        "C:\\ProgramData",
        "C:\\Users",
        "C:\\Users\\user",
        "c:\\users\\user\\appdata\\roaming\\microsoft\\windows\\cookies",
        "c:\\users\\user\\appdata\\roaming",
        "c:\\users\\user\\appdata\\local",

        ]

# All files with those substrings will be ignored
ignore_filenames_substr = [
        "desktop.ini",
        "\\Adobe\\Acrobat\\DC",
        "\\Adobe\\Headlights",
        "\\Adobe\\Linguistics",
        "\\Adobe\\LogTransport2"
        "\\Microsoft\\Forms",
        "\\Microsoft\\Office\\Recent\\index.dat",
        "\\Microsoft\\Speech",
        "\\Microsoft\\Templates\\~$Normal.dotm",
        "\\Microsoft\\Templates\\Normal.dotm",
        "\\Microsoft\\Windows\\Cookies"
        "\\Adobe\\Color",
        "\\CEF",
        "\\Microsoft\\Internet Explorer\\Recovery",
        "\\Microsoft\\Office\\15.0",
        "\\microsoft\\office\\OTeleData_2236_1.etl",
        "\\microsoft\\office\\OTeleData_2236_2.etl",
        "\\Microsoft\\Windows\\Caches",
        "\\Microsoft\\Windows\\History",
        "\\Adobe\\Acrobat Reader DC\\Reader",
        "\\Common Files\\microsoft shared\\OFFICE15\\MSO.DLL",
        "\\(x86)\\Common Files\\microsoft shared\\VBA\\VBA6\\VBE6EXT.OLB",
        "\\(x86)\\Common Files\\microsoft shared\\VBA\\VBA7.1\\VBE7.DLL",
        "\\(x86)\\Internet Explorer\\iexplore.exe",
        "\\(x86)\\Microsoft Office\\Office15\\MSWORD.OLB",
        "\\(x86)\\Microsoft Office\\Office15\\WINWORD.EXE",
        "\\~$imgs.htm",
        "\\acrocef_low",
        "\\acrord32_sbx",
        "\\CVR8743.tmp.cvr",
        "\\VBE\\MSForms.exd",
        "\\System32\\WindowsPowerShell\\v1.0\\",
        "\\Microsoft.NET\\Framework64\\v2.0.50727",
        "\\Microsoft\\Windows\\Recent\\CustomDestinations",
        "\\SysWOW64\\",
        "\\Common Files\\microsoft shared\\",
        "\\drivers\\etc\\hosts",
        "\\srvsvc",
        "\\microsoft\\office\\OTeleData",
        "\\Microsoft Office\\Office15\\",
        "\\Fonts\\StaticCache.dat",
        "\\Microsoft\\Forms",
        "\\assembly\\GAC_MSIL\\",
        "\\Microsoft\\Office\\Recent\\",
        "\\VBE",
        "\\Microsoft\\Crypto",
        "\\assembly\\NativeImages",
        "\\Microsoft.NET\\Framework"
        "unknown"
]

# the following regkeys will be ignored to prevent dummy correlations in misp
ignore_regkeys = [

        ]

# ignore IPs
ignore_ipaddr = [
        '192.168.2.0/24',
        '8.8.8.8',
        '1.1.1.1',
        '8.8.4.4'
]

# ignore URLs
ignore_url = [
        "http://www.%s.comPA",
        "https://www.cloudflare.com/5xx-error-landing",        
]

# disable correlations in references with the following names
disable_correlations = [
        "powershell.exe",
        "WINWORD.EXE",
]