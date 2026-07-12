# Files changed by the patch

- `backend/main.py`
- `backend/routers/ip.py`
- `backend/routers/domain.py`
- `backend/routers/url.py`
- `frontend/app/page.tsx`
- `backend/core/validators.py` — new
- `backend/tests/test_validators.py` — new
- `frontend/app/results/bulk/page.tsx` — new

The patch is idempotent: running it again after a successful application makes no further changes.

## Version 2 correction

- Fixes `Could not locate expected source block: duplicate fast health route`.
- Normalises zero, one or multiple health handlers into one canonical route.
- Supports the current validation messages and multiline frontend provider cards.
- Safely reruns without applying duplicate changes.
