import win32evtlog

def detect_scriptblock_events():
    query = "*[System/EventID=4104]"
    log_type = "Microsoft-Windows-PowerShell/Operational"

    try:
        handle = win32evtlog.EvtQuery(
            log_type,
            win32evtlog.EvtQueryReverseDirection,
            query
        )

        count = 0
        while True:
            events = win32evtlog.EvtNext(handle, 10)
            if not events:
                break

            for event in events:
                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                print(f"[MATCH] Found Event ID 4104:\n{xml}\n")
                count += 1

                if count >= 1:
                    print("[OK] Script Block Execution Detected.")
                    return

    except Exception as e:
        print(f"[ERROR] Failed to query event log: {e}")

    print("[X] No Event ID 4104 detected.")

if __name__ == "__main__":
    detect_scriptblock_events()
