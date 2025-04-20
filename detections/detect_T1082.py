import win32evtlog

def detect_systeminfo_events():
    query = "*[System/EventID=4104]"
    log_type = "Microsoft-Windows-PowerShell/Operational"

    try:
        handle = win32evtlog.EvtQuery(log_type, win32evtlog.EvtQueryReverseDirection, query)
        count = 0
        while True:
            events = win32evtlog.EvtNext(handle, 10)
            if not events:
                break
            for event in events:
                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                if "Get-ComputerInfo" in xml:
                    print("[MATCH] Found Get-ComputerInfo execution (T1082)")
                    print(xml)
                    return
                count += 1
                if count >= 50:
                    break
    except Exception as e:
        print(f"[ERROR] Failed to query event log: {e}")

    print("[X] No T1082 behavior detected.")

if __name__ == "__main__":
    detect_systeminfo_events()
