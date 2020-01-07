# DattoLogs
A powershell script to gather Datto agent logs. It supports both Datto Windows Agent and Shadowsnap. The script will put all of the logs into a zip archive and place it on the desktop. More information on Datto logs and the files collected can be found [here](https://kb.datto.com/hc/en-us/articles/206267443-SIRIS-ALTO-and-NAS-Gathering-Datto-Diagnostic-Logs).

# Usage
Run the script from an elevated Powershell console. 

# Gathered logs
The logs gathered by the script are dependent on the agent software installed, but they both export the System and Application logs from Windows.
## Datto Windows Agent
* %systemdrive%\Windows\System32\config\systemprofile\AppData\Local\Datto\Datto Windows Agent\logs\
* %systemdrive%\Windows\System32\config\systemprofile\AppData\Local\Datto\Datto Windows Agent\agent.sqlite
* Installation logs

## Shadowsnap
* \Program Files\StorageCraft\ShadowProtect\ShadowSnap\log\raw_agent.log
* \Program Files\StorageCraft\ShadowProtect\ShadowSnap\log\log.txt
* \Program Files\StorageCraft\ShadowProtect\ShadowSnap\endptconfig.sqlite3
* Installation logs
