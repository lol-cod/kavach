import csv
import win32evtlog

evtx_file_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
output_file_path = "D:\Kavach\Behavior Analysis\output.csv"  # Change this to the desired output file path

# Connect to the Security event log
hand = win32evtlog.OpenEventLog(None, "Security")

# Retrieve events from the last 1 hour
one_hour_ago = win32evtlog.GetNumberOfEventLogRecords(hand) - 3600
events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, one_hour_ago)

# Write the event data to a CSV file
with open(output_file_path, mode="w", newline="", encoding="utf-8") as output_file:
    csv_writer = csv.writer(output_file)
    csv_writer.writerow(["Event ID", "Time", "Message"])

    for event in events:
        event_id = event.EventID
        time_created = event.TimeGenerated.Format()
        message = event.StringInserts

        csv_writer.writerow([event_id, time_created, message])

print(f"Event log data from the last 1 hour dumped to: {output_file_path}")
