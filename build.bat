msbuild nextdns-windows.sln /t:Rebuild /p:Configuration=Release /p:Platform="any cpu" || goto :error

cd service

set GOARCH=amd64
go build -o .\bin\amd64\service.exe . || goto :error

set GOARCH=386
go build -o .\bin\i386\service.exe . || goto :error

cd ..

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool" sign /q /n "NextDNS" /tr http://timestamp.digicert.com /td sha256 /fd sha256 gui\bin\gui.exe dnsunleak\bin\dnsunleak.exe service\bin\amd64\service.exe service\bin\i386\service.exe || goto error

"C:\Program Files (x86)\NSIS\makensis.exe" nsis\NextDNSSetup.nsi || goto :error

"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool" sign /q /n "NextDNS" /tr http://timestamp.digicert.com /td sha256 /fd sha256 NextDNSSetup-*.exe || goto error

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
