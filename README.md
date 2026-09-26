# MikroTik Helper

Нативное Windows-приложение на WPF для настройки двух MikroTik.

Соберите приложение через `build.bat`. Готовый `MikrotikHelper.exe` появится в
`bin\Release\net10.0-windows\win-x64\publish`.

Для генерации WireGuard-ключей используется установленный WireGuard for Windows.
Connect выполняет авторизацию через официальный RouterOS API на TCP-порту 8728.
На MikroTik должен быть включён сервис `api`, а пользователь должен иметь права
`api`, `read` и `write`. Сертификат не требуется, пароль на диск не сохраняется.
Порт 8728 следует разрешать только из доверенной локальной сети.
