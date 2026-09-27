# FastAPI JWT CRUD API

A small SQLite-backed API with user registration, bearer-token authentication, and owner-scoped item CRUD.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-random-secret"
python -m uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs` to try the API. For the OAuth2 login form, enter the account email in the `username` field. The SQLite database defaults to `app.db`; set the `DB` environment variable to use another path.

The fallback signing key is for local development only. Set a strong, private `SECRET_KEY` before deploying, and do not commit it.

## Endpoints

- `POST /register` creates an account.
- `POST /login` returns a JWT access token.
- `GET /me` returns the authenticated user's public profile.
- `POST /items` creates an item for the authenticated user.
- `GET /items` lists that user's items.
- `GET /items/{item_id}` retrieves one of that user's items.
- `PUT /items/{item_id}` replaces an item title and description.
- `DELETE /items/{item_id}` deletes an item.

Run tests with `python -m pytest`.