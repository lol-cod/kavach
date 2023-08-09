import csv
import win32evtlog

evtx_file_path = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx"
output_file_path = "C:\workarea\Malware analysis tool\Malware analysis_files\system_output_7045.csv"# Change this to the desired output file path
target_event_id = 7045  # Event ID to filter

# Connect to the System event log
hand = win32evtlog.OpenEventLog(None, "System")

# Retrieve events from the last 1 hour
one_hour_ago = win32evtlog.GetNumberOfEventLogRecords(hand) - 3600
events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, one_hour_ago)

# Write the event data with Event ID 7045 to a CSV file
with open(output_file_path, mode="w", newline="", encoding="utf-8") as output_file:
    csv_writer = csv.writer(output_file)
    csv_writer.writerow(["Event ID", "Time", "Message"])

    for event in events:
        event_id = event.EventID
        if event_id == target_event_id:
            time_created = event.TimeGenerated.Format()
            message = event.StringInserts

            csv_writer.writerow([event_id, time_created, message])

print(f"System event log data with Event ID {target_event_id} from the last 1 hour dumped to: {output_file_path}")
