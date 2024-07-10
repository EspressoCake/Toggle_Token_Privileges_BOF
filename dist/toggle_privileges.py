from havoc import Demon, RegisterCommand

def PrintList(demon):
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Toggle privileges")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Usage: TogglePrivsBof enable/disable PRIV_NUMBER")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Example: TogglePrivsBof enable 20")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "Please select a number, to provide as an argument.")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "1:\tSeCreateTokenPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "2:\tSeAssignPrimaryTokenPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "3:\tSeLockMemoryPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "4:\tSeIncreaseQuotaPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "5:\tSeUnsolicitedInputPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "6:\tSeMachineAccountPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "7:\tSeTcbPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "8:\tSeSecurityPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "9:\tSeTakeOwnershipPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "10:\tSeLoadDriverPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "11:\tSeSystemProfilePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "12:\tSeSystemtimePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "13:\tSeProfileSingleProcessPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "14:\tSeIncreaseBasePriorityPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "15:\tSeCreatePagefilePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "16:\tSeCreatePermanentPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "17:\tSeBackupPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "18:\tSeRestorePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "19:\tSeShutdownPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "20:\tSeDebugPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "21:\tSeAuditPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "22:\tSeSystemEnvironmentPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "23:\tSeChangeNotifyPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "24:\tSeRemoteShutdownPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "25:\tSeUndockPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "26:\tSeSyncAgentPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "27:\tSeEnableDelegationPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "28:\tSeManageVolumePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "29:\tSeImpersonatePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "30:\tSeCreateGlobalPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "31:\tSeTrustedCredManAccessPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "32:\tSeRelabelPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "33:\tSeIncreaseWorkingSetPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "34:\tSeTimeZonePrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "35:\tSeCreateSymbolicLinkPrivilege")
	demon.ConsoleWrite(demon.CONSOLE_INFO, "36:\tSeDelegateSessionUserImpersonatePrivilege")

def TogglePrivs(demonID, *param):
    TaskID: str = None
    demon: Demon = None
    demon = Demon(demonID)
    packer : Packer = Packer()

    if len(param) < 2:
        PrintList(demon)
        return False

    if len(param) > 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Too many arguments")
        return False

    packer.addint(int(param[1]))

    action = "enable"
    if param[0] == "disable":
    	action = "disable"

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to toggle privs.")
    demon.InlineExecute(TaskID, action, "toggle_privileges_bof.x64.o", packer.getbuffer(), False)

    return TaskID

RegisterCommand(TogglePrivs, "", "toggle_privs_bof", "Toggle privileges. Launch with no parameters to see the list of PRIV_NUMBER", 0, "[ACTION] [PRIV_NUMBER]", "enable/disable 20" )
