# Contributing

1. `python -m venv .venv && .venv/bin/pip install -r gateway/requirements-dev.txt`
2. `make test` must pass. New security behaviour needs a test that fails without it.
3. New attacks: add an entry to `gateway/attacks/library.json` (`id`, `category`, `severity`, `name`,
   `prompt`, optional `success_indicators`) and re-run the suite; keep benign prompts at 0% false positives.
4. Never commit secrets. `.env` is git-ignored; use `scripts/gen_env.sh`.
