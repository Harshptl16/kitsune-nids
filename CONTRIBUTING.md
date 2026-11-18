# Contributing (owner: Bhavya)

## Who owns what

Each file has one owner who writes it, commits it and explains it in the demo. Owners are listed in `.github/CODEOWNERS` and in the plan doc's "Team & GitHub" tab. Anyone can review anything.

## Workflow

1. Pick or open an issue; assign yourself.
2. Branch from an up-to-date `main`:
   ```bash
   git switch main && git pull
   git switch -c <yourname>/<short-topic>      # e.g. krish/extractor
   ```
3. Commit small, working steps. Message format: `<area>: <what changed>`, e.g. `features: add jitter stream`.
4. Run `pytest` and `ruff check .` before pushing.
5. Push and open a pull request using the template. Request a review from one teammate (CODEOWNERS adds the owner automatically).
6. Merge with **Squash and merge** once CI is green and one approval is in. Delete the branch.

## Rules

- Never commit or push directly to `main`, and never `git push -f` to it. `main` has no branch protection, so this rule is on us.
- Merge only when CI is green and one teammate has approved.
- Never commit captures (`*.pcap`), models, alert databases or credentials. Captures go in the shared drive.
- Settings go in `configs/default.yaml`, not in code.
- New code comes with tests. Feature code is tested against a brute-force version.
- Write the code yourself; no code copied from the original Kitsune repository or other projects.

## Local setup

```bash
git clone git@github.com:<org-or-owner>/kitsune-nids.git && cd kitsune-nids
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
