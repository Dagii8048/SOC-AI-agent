import re

with open('event_mapper.py', 'r') as f:
    content = f.read()

content = content.replace(
    '''            if status == "invalid":
                invalid.append({"index": i, "reason": attached_info}) # attached_info is reason for invalid
            elif status == "noise":
                noise_dropped += 1
            elif status == "mapped":
                events.append(event)
                if attached_info:
                    attached.append(attached_info)
        except Exception as e:
            invalid.append({"index": i, "reason": f"Unexpected error: {e.__class__.__name__}"})''',
    '''            if status == "invalid":
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
