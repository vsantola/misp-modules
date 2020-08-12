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
        "%WINDIR%\\win.ini",
        "C:\\ProgramData",
        "C:\\Users",
        "C:\\Users\\user",
        ]

# All files with those substrings will be ignored
ignore_filenames_substr = [
        "desktop.ini",
        "%LOCALAPPDATA%\\ow\\Adobe\\Acrobat\\DC",
        "%PROGRAMFILES%\\(x86)\\Adobe\\Acrobat Reader DC\\Reader",
        "%WINDIR%\\assembly\\NativeImages_v4.0.30319_32",
        "%WINDIR%\\assembly\\NativeImages_v4.0.30319"
]

# the following regkeys will be ignored to prevent dummy correlations in misp
ignore_regkeys = [

        ]
