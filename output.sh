git checkout fix/event-mapper-validation

git branch --show-current
git log --oneline -3
git status --short
git diff --stat origin/feat/etl-pipeline HEAD
cat event_mapper.py
cat tests/test_event_mapper.py
echo "== TZ=UTC"
TZ=UTC python -m unittest discover -s tests -v
echo "== TZ=Africa/Addis_Ababa"
TZ=Africa/Addis_Ababa python -m unittest discover -s tests -v
echo "== TZ=America/New_York"
TZ=America/New_York python -m unittest discover -s tests -v

git ls-remote --heads origin fix/event-mapper-validation
