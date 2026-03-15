Markdown
# 🔍 Splunk Detection Queries (SPL) - SOC Portfolio

Este documento demonstra competências de nível **Splunk Power User**, com foco em monitorização e deteção de incidentes em ambientes críticos.

## 1. Deteção de Brute Force (Windows Event Logs)
Identifica tentativas de login falhas seguidas de um sucesso, sugerindo comprometimento de conta.

```splunk
index=wineventlog EventCode=4625 OR EventCode=4624
| stats count(eval(EventCode=4625)) as Failure, count(eval(EventCode=4624)) as Success by src_ip, user
| where Failure > 5 AND Success > 0
| table src_ip, user, Failure, Success

## 2. Monitorização de PowerShell Suspeito (Base64)
Deteta o uso de comandos codificados para ocultar atividades maliciosas no sistema.

index=os_logs process_name=powershell.exe
| search command="*-encodedcommand*" OR command="* -enc *"
| stats count by host, user, command

## 3. Visualização de Tráfego de Rede (Firewall)
Query utilizada para mapear a origem geográfica de conexões permitidas.

index=firewall action=allowed
| iplocation src_ip
| stats count by Country
| geomfilter Country

Documentação técnica desenvolvida por Lindolfo Júnior.
