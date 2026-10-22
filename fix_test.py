import re

with open('tests/test_event_mapper.py', 'r') as f:
    content = f.read()

test_to_add = '''
    def test_unexpected_exception_reason(self):
        class BadRecord(dict):
            def get(self, key, default=None):
                if key == "rule":
                    raise ValueError("Boom")
                return super().get(key, default)

        bad_record = BadRecord({"timestamp": "2026-10-02T08:15:30.120+0000"})
        res = map_events([bad_record], [])

        self.assertEqual(len(res["invalid"]), 1)
        reason = res["invalid"][0]["reason"]
        self.assertEqual(reason, "Unexpected error: ValueError")

'''

content = content.replace("if __name__ == '__main__':", test_to_add + "if __name__ == '__main__':")

with open('tests/test_event_mapper.py', 'w') as f:
    f.write(content)
