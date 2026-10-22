with open('event_mapper.py', 'r') as f:
    content = f.read()

content = content.replace(
    '''    for i, raw in enumerate(wazuh_records):
        status, event, attached_info = map_wazuh_alert(raw, osquery_records)
        if status == "invalid":
            invalid.append({"index": i, "reason": attached_info}) # attached_info is reason for invalid
        elif status == "noise":
            noise_dropped += 1
        elif status == "mapped":
            events.append(event)
            if attached_info:
                attached.append(attached_info)''',
    '''    for i, raw in enumerate(wazuh_records):
        try:
            status, event, attached_info = map_wazuh_alert(raw, osquery_records)
            if status == "invalid":
                invalid.append({"index": i, "reason": attached_info}) # attached_info is reason for invalid
            elif status == "noise":
                noise_dropped += 1
            elif status == "mapped":
                events.append(event)
                if attached_info:
                    attached.append(attached_info)
        except Exception as e:
            invalid.append({"index": i, "reason": f"Unexpected error: {type(e).__name__}"})'''
)

with open('event_mapper.py', 'w') as f:
    f.write(content)
