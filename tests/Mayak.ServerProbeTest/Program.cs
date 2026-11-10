using System.Net.Sockets;
using Mayak.Api.Data;
using Mayak.Api.Services;

// Изолированный тест (без БД и сети): сводка проверок доступности и коды ошибок.
var failed = 0; var passed = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}"); if (ok) passed++; else failed++; }

var now = new DateTime(2026, 11, 10, 12, 0, 0, DateTimeKind.Utc);
var id = Guid.NewGuid();
ServerProbe P(string kind, int minutesAgo, bool ok, int? ms = null, string? err = null) =>
    new() { ServerId = id, Kind = kind, At = now.AddMinutes(-minutesAgo), Ok = ok, LatencyMs = ms, Error = err };

var probes = new List<ServerProbe>();
for (var m = 0; m < 24 * 60; m += 1) probes.Add(P("tcp", m, m >= 60, m >= 60 ? 40 : null, m >= 60 ? null : "timeout")); // последний час — сбой
for (var m = 0; m < 24 * 60; m += 1) probes.Add(P("icmp", m, false, null, "unavailable"));
probes.Add(P("tls", 5, true, 90)); probes.Add(P("tls", 2000, true, 90)); // вторая — вне окна 24 ч

var s = ServerProbeStats.Summarize(probes, now, TimeSpan.FromHours(24), 48);
var tcp = s.Single(k => k.Kind == "tcp"); var icmp = s.Single(k => k.Kind == "icmp"); var tls = s.Single(k => k.Kind == "tls");
Check("порядок видов: icmp, tcp, tls", string.Join(",", s.Select(k => k.Kind)) == "icmp,tcp,tls");
Check("последний результат tcp — сбой timeout", tcp.LastOk == false && tcp.LastError == "timeout" && tcp.LastMs == null);
Check("доля успешных tcp ≈ 95.8%", tcp.UptimePercent is > 95.7 and < 95.9);
Check("средняя задержка только по успешным", tcp.AvgMs == 40);
Check("48 корзин; последние 2 (час) — 0%, первые — 100%", tcp.Buckets.Count == 48 && tcp.Buckets[^1].OkRatio == 0 && tcp.Buckets[^2].OkRatio == 0 && tcp.Buckets[0].OkRatio == 1);
Check("ICMP «unavailable» не считается недоступностью", icmp.UptimePercent == null && icmp.Buckets.All(b => b.OkRatio == null) && icmp.LastError == "unavailable");
Check("проверка вне окна не учитывается", tls.Count == 1 && tls.UptimePercent == 100);
Check("пустой набор — пустая сводка", ServerProbeStats.Summarize([], now, TimeSpan.FromHours(24), 48).Count == 0);

Check("код ошибки: отказ соединения", ServerProbeService.ErrorCode(new SocketException((int)SocketError.ConnectionRefused)) == "refused");
Check("код ошибки: тайм-аут отмены", ServerProbeService.ErrorCode(new OperationCanceledException()) == "timeout");
Check("код ошибки: сброс внутри IOException", ServerProbeService.ErrorCode(new IOException("x", new SocketException((int)SocketError.ConnectionReset))) == "reset");
Check("код ошибки: TLS", ServerProbeService.ErrorCode(new System.Security.Authentication.AuthenticationException()) == "tls");
Check("код ошибки: прочее без текста исключения", ServerProbeService.ErrorCode(new InvalidOperationException("secret 10.0.0.1")) == "error");

Console.WriteLine($"passed={passed} failed={failed}");
return failed == 0 ? 0 : 1;
