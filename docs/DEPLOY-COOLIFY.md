# Deploy on Coolify

The repo ships a single multi-stage `Dockerfile`: React build → Go build → small Alpine runtime on port 8080
serving both the API and the UI.

## Steps

1. In Coolify, open your project and choose **New Resource → Public Repository**.
   (Use **Private Repository (GitHub App)** if you make the repo private.)
2. Repository URL: `https://github.com/iamyassin08/iam-projects`, branch `main`.
3. **Build Pack:** `Dockerfile`. Leave the base directory as `/` and the Dockerfile location as `/Dockerfile`.
4. **Ports Exposes:** `8080`.
5. **Storage → Add persistent volume**
   - Name: `iam-data`
   - Destination path: `/data`

   Without the volume, all demo changes are lost on every redeploy.
6. **Domains:** set your domain, for example `https://iam.assafwahinc.com`. Coolify issues the TLS certificate.
7. **Environment variables** (optional, these are the defaults):

   | Variable | Default |
   |---|---|
   | `PORT` | `8080` |
   | `DATA_PATH` | `/data/iam.json` |
   | `STATIC_DIR` | `/app/web` |
   | `PUBLIC_URL` | `https://iam.assafwahinc.com` (recommended: pins the OIDC issuer) |
   | `SESSION_SECRET` | `openssl rand -base64 32` (recommended: sign-ins survive redeploys) |
   | `VAULT_KEY` | `openssl rand -base64 32` (optional; otherwise a key file is created in `/data`) |
   | `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | optional, Keycloak (see `docs/KEYCLOAK.md`) |

8. **Health check:** path `/api/health`, port `8080`. The image also has a Docker `HEALTHCHECK`.
9. Click **Deploy**. The first build takes 1–2 minutes.

## Verify

```bash
curl https://iam.assafwahinc.com/api/health      # {"status":"ok"}
curl https://iam.assafwahinc.com/api/lab/checks  # 20 control results
```

Open the site and you should see the home screen with the four project cards.

## Auto-deploy (GitHub Actions → Coolify)

`.github/workflows/deploy.yml` runs on every push or merged pull request to `main` that touches `backend/`, `frontend/`,
the `Dockerfile` or `docker-compose.yml`. It runs `gofmt`, `go vet`, `go test`, the frontend build and a Docker build, and
only if all pass it calls Coolify's deploy API. Pull requests run the same checks without deploying. Doc-only changes don't redeploy.

One-time setup:

1. **Coolify → Keys & Tokens → API tokens → Create.** Give it the *deploy* permission and copy it.
2. **Find the app UUID:** open IAM Projects in Coolify; the UUID is the last part of the URL
   (`…/project/…/environment/…/application/<uuid>`).
3. **GitHub → repo Settings → Secrets and variables → Actions → New repository secret**, three times:

   | Name | Value |
   |---|---|
   | `COOLIFY_URL` | your Coolify dashboard address, e.g. `https://cloud.example.com` |
   | `COOLIFY_TOKEN` | the token from step 1 |
   | `COOLIFY_APP_UUID` | the UUID from step 2 |

4. **Coolify → IAM Projects → General:** leave Build Pack `Dockerfile` at `/Dockerfile` (unchanged by the
   backend/frontend layout). Turn **off** any other auto-deploy (GitHub App auto deploy or a webhook) so each push deploys once.
5. Push a change, or **Actions → Test and deploy → Run workflow**. The run's *deploy* step prints Coolify's response.

The secrets live only in GitHub's encrypted store; nothing about your Coolify server is committed to this public repo.

Alternative without Actions: connect the repo through Coolify's GitHub App, turn on **Auto Deploy**, and set
**Watch Paths** to `backend/**`, `frontend/**`, `Dockerfile` so only app changes trigger a build.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails at `npm ci` | `frontend/package-lock.json` must be committed and match `package.json`. |
| Build fails at `go build` | `backend/go.mod` must exist; the server uses only the Go standard library. |
| `permission denied` writing `/data/iam.json` | The container runs as UID 10001. Make sure the volume is writable, or recreate it so the image's `chown` applies. |
| 502 from the proxy | The exposed port must be `8080`. |
| Data resets on redeploy | The persistent volume at `/data` is missing. |
| Want a clean demo | Click **Reset demo data** on the home screen, or `POST /api/reset`. |
