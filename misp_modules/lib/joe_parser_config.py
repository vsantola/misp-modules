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
            r"%USERPROFILE%\Desktop\desktop.ini",
            r"%USERPROFILE%\Favorites\desktop.ini",
            r"%PROGRAMFILES%\(x86)\Internet Explorer\iexplore.exe",
            r"%LOCALAPPDATA%\Microsoft\Internet Explorer\Recovery",
            r"%WINDIR%\SysWOW64\ieframe.dll",
            r"%LOCALAPPDATA%\CEF",
            r"C:\ProgramData",
            r"%LOCALAPPDATA%\Microsoft\Windows\Caches",
            r"%USERPROFILE%\AppData\Roaming",
            r"%USERPROFILE%\AppData\Local",
            r"%TEMP%\acrocef_low",
            r"%APPDATA%\Microsoft\Speech",
            r"%APPDATA%\Adobe\Headlights",
            r"%APPDATA%\Adobe\LogTransport2"
            r"%APPDATA%\Adobe\Linguistics",
            r"%WINDIR%\Fonts\StaticCache.dat",
            r"%APPDATA%\Adobe\Acrobat\DC\Security\ES_session_storek",
            r"%WINDIR%\System32\spool\drivers\color\sRGB Color Space Profile.icm",
            r"C:\Users\desktop.ini",
            r"%PROGRAMFILES%\(x86)\desktop.ini",
            r"%WINDIR%\win.ini",
            r"%TEMP%\acrord32_sbx",
            r"C:\Users\user",
            r"%APPDATA%\Adobe\Acrobat\DC",
            r"%LOCALAPPDATA%\Adobe\Color"
        ]

# All files with those prefixes will be ignored
ignore_filenames_prefix = [
            r"%LOCALAPPDATA%\ow\Adobe\Acrobat\DC",
            r"%PROGRAMFILES%\(x86)\Adobe\Acrobat Reader DC\Reader"
]

# the following regkeys will be ignored to prevent dummy correlations in misp
ignore_regkeys = [

        ]
