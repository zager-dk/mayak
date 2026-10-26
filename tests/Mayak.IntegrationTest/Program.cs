using System.Text.Json.Nodes;
using Mayak.Core.Awg;
using Mayak.Core.Export;
using Mayak.Core.Models;
using Mayak.Core.Server;

// Сквозной тест MayakServer через настоящий SSH на локальном стенде.
// Стенд: тестовый SSH/SFTP-сервер на 127.0.0.1:2222 (root/test) и заглушки docker/awg/tc в PATH,
// где «контейнер» — файловая система этой же машины (тест читает /opt/amnezia/awg напрямую).
// Запуск: dotnet run --project tests/Mayak.IntegrationTest -- 127.0.0.1 2222 root test
// Не запускайте против боевого сервера: тест переустанавливает VPN.
var host = args.ElementAtOrDefault(0) ?? "127.0.0.1";
var port = int.Parse(args.ElementAtOrDefault(1) ?? "2222");
var user = args.ElementAtOrDefault(2) ?? "root";
var password = args.ElementAtOrDefault(3) ?? "test";

int failed = 0, passed = 0;
void Check(string name, bool ok, string? details = null)
{
    if (ok) { passed++; Console.WriteLine($"  OK    {name}"); }
    else { failed++; Console.WriteLine($"  FAIL  {name} {details}"); }
}

var creds = new SshCredentials { Host = host, Port = port, User = user, Password = password };
using var server = new MayakServer(creds);
server.Log += m => Console.WriteLine("    · " + m);

Console.WriteLine("Подключение и установка:");
server.Connect();
Check("отпечаток сервера получен", server.Fingerprint?.StartsWith("SHA256:") == true, server.Fingerprint);
var state = server.GetState();
Console.WriteLine($"    состояние до установки: {state}");
server.Install(new InstallOptions { Port = 41234, Version = AwgProtocolVersion.V2 }, reinstall: state is ServerState.Running or ServerState.Stopped);
Check("после установки контейнер работает", server.GetState() == ServerState.Running);

var snap = server.Load();
Check("порт и ключ сервера прочитаны", snap.Endpoint.Port == 41234 && snap.Endpoint.ServerPublicKey.Length == 44);
Check("параметры AWG 2.0 прочитаны", snap.Endpoint.Parameters.ProtocolVersionString == "2" && snap.Endpoint.Parameters.I1.Length > 0);
Check("база пустая, лимит по умолчанию 35", snap.Db.Users.Count == 0 && snap.Db.DefaultDownMbps == 35);

Console.WriteLine("Пользователи и устройства:");
var ivan = new VpnUser { Name = "Иван", Note = "оплачено до 01.12" };
snap.Db.Users.Add(ivan);
server.Save(snap);
var phone = server.AddDevice(snap, ivan, "iPhone", DeviceKind.IPhone, 35, 35);
var laptop = server.AddDevice(snap, ivan, "Ноутбук", DeviceKind.Windows, 50, 0);
var maria = new VpnUser { Name = "Мария" };
snap.Db.Users.Add(maria);
var android = server.AddDevice(snap, maria, "Android", DeviceKind.Android, 0, 0);

snap = server.Load();
var ivanR = snap.Db.Users.Single(u => u.Name == "Иван");
Check("база пережила перечитывание", snap.Db.Users.Count == 2 && ivanR.Devices.Count == 2 && ivanR.Note == "оплачено до 01.12");
Check("IP выданы по порядку", ivanR.Devices[0].Ip == "10.8.1.1" && ivanR.Devices[1].Ip == "10.8.1.2" && snap.Db.Users[1].Devices[0].Ip == "10.8.1.3",
    string.Join(",", snap.Db.AllDevices.Select(d => d.Ip)));
Check("все три пира в awg0.conf", snap.PeersOnServer.Count == 3);
Check("чужих подключений нет", snap.Foreign.Count == 0);
Check("статистика прочитана", snap.Stats.Count == 3 && snap.StatsFor(ivanR.Devices[0])?.IsOnline == true);

var limits = File.ReadAllText(MayakServer.LimitsPath);
Check("лимиты: iPhone 35/35, ноутбук 50/∞, Android без строки",
    limits.Contains("10.8.1.1 35000 35000 11") && limits.Contains("10.8.1.2 50000 0 12") && !limits.Contains("10.8.1.3"), "\n" + limits);

var table = JsonNode.Parse(File.ReadAllText(MayakServer.ClientsTablePath))!.AsArray();
Check("clientsTable для AmneziaVPN заполнен", table.Count == 3 && table.Any(n => n!["userData"]!["clientName"]!.GetValue<string>() == "Иван (iPhone)"));

Console.WriteLine("Приостановка и удаление:");
server.SetDeviceEnabled(snap, ivanR, ivanR.Devices[1], false);
snap = server.Load();
Check("приостановленное устройство убрано с сервера", snap.PeersOnServer.Count == 2 && snap.Db.AllDevices.Count() == 3);
Check("и из лимитов", !File.ReadAllText(MayakServer.LimitsPath).Contains("10.8.1.2"));
ivanR = snap.Db.Users.Single(u => u.Name == "Иван");
server.SetDeviceEnabled(snap, ivanR, ivanR.Devices[1], true);
snap = server.Load();
Check("включённое снова на сервере с тем же IP", snap.PeersOnServer.Count == 3 && snap.Db.AllDevices.Any(d => d.Ip == "10.8.1.2" && d.Enabled));

var mariaR = snap.Db.Users.Single(u => u.Name == "Мария");
server.SetUserEnabled(snap, mariaR, false);
snap = server.Load();
Check("приостановка пользователя убирает его устройства", snap.PeersOnServer.Count == 2);
mariaR = snap.Db.Users.Single(u => u.Name == "Мария");
server.RemoveUser(snap, mariaR);
snap = server.Load();
Check("пользователь удалён", snap.Db.Users.Count == 1 && snap.PeersOnServer.Count == 2);

Console.WriteLine("Подключение, созданное в AmneziaVPN:");
File.AppendAllText(MayakServer.ConfPath, "[Peer]\nPublicKey = FOREIGNKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\nPresharedKey = x\nAllowedIPs = 10.8.1.9/32\n\n");
File.WriteAllText(MayakServer.ClientsTablePath, File.ReadAllText(MayakServer.ClientsTablePath).TrimEnd().TrimEnd(']') +
    ",{\"clientId\":\"FOREIGNKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\",\"userData\":{\"clientName\":\"Пётр\"}}]");
snap = server.Load();
Check("чужое подключение найдено с именем", snap.Foreign.Count == 1 && snap.Foreign[0].Name == "Пётр" && snap.Foreign[0].Ip == "10.8.1.9");
ivanR = snap.Db.Users.Single();
var newDev = server.AddDevice(snap, ivanR, "Mac", DeviceKind.Mac, 35, 35);
Check("новый IP после чужого (как у Amnezia): 10.8.1.10", newDev.Ip == "10.8.1.10", newDev.Ip);
server.RevokeForeign(snap, snap.Foreign[0]);
snap = server.Load();
Check("чужое подключение отозвано", snap.Foreign.Count == 0 && !File.ReadAllText(MayakServer.ClientsTablePath).Contains("Пётр"));

Console.WriteLine("Выдача файлов:");
var dev = snap.Db.Users.Single().Devices.First();
var key = ClientConfigFactory.BuildVpnKey(snap.Endpoint, dev, snap.Db.Dns1, snap.Db.Dns2, "Маяк VPN · Иван");
var json = JsonNode.Parse(VpnKeyCodec.Decode(key))!;
var last = JsonNode.Parse(json["containers"]![0]!["awg"]!["last_config"]!.GetValue<string>())!;
Check("vpn:// содержит ключ сервера и порт", last["server_pub_key"]!.GetValue<string>() == snap.Endpoint.ServerPublicKey && last["port"]!.GetValue<int>() == 41234);
var conf = AwgConfigFile.Parse(ClientConfigFactory.BuildConfFile(snap.Endpoint, dev, snap.Db.Dns1, snap.Db.Dns2));
var serverConf = AwgConfigFile.Parse(File.ReadAllText(MayakServer.ConfPath));
Check(".conf совпадает с сервером по H1–H4 и S1–S4",
    new[] { "H1", "H2", "H3", "H4", "S1", "S2", "S3", "S4", "Jc" }.All(k => conf.GetInterfaceValue(k) == serverConf.GetInterfaceValue(k)));
Check("PSK клиента совпадает с пиром на сервере",
    serverConf.Peers.Single(p => p.PublicKey == dev.PublicKey).PresharedKey == conf.Sections[1].Get("PresharedKey"));

Console.WriteLine("Протокол 3.1:");
server.Install(new InstallOptions { Port = 41235, Version = AwgProtocolVersion.V3 }, reinstall: true);
snap = server.Load();
Check("переустановка на AWG 3.1", snap.Endpoint.Parameters.ProtocolVersionString == "3.1" && snap.Db.Users.Count == 0 && snap.PeersOnServer.Count == 0);
var v3user = new VpnUser { Name = "Тест" };
snap.Db.Users.Add(v3user);
var v3dev = server.AddDevice(snap, v3user, "iPhone", DeviceKind.IPhone, 35, 35);
var v3conf = ClientConfigFactory.BuildConfFile(snap.Endpoint, v3dev, snap.Db.Dns1, snap.Db.Dns2);
Check(".conf 3.1 с HeaderProtectionKey", v3conf.Contains("HeaderProtectionKey = " + snap.Endpoint.Parameters.HeaderProtectionKey) && v3conf.Contains("PersistentKeepalive = 25-35"));

Console.WriteLine();
Console.WriteLine($"Итого: {passed} OK, {failed} ошибок");
return failed == 0 ? 0 : 1;
