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

8. **Health check:** path `/api/health`, port `8080`. The image also has a Docker `HEALTHCHECK`.
9. Click **Deploy**. The first build takes 1–2 minutes.

## Verify

```bash
curl https://iam.assafwahinc.com/api/health      # {"status":"ok"}
curl https://iam.assafwahinc.com/api/lab/checks  # 14 control results
```

Open the site and you should see the home screen with the four project cards.

## Auto-deploy

Turn on **Automatic deployment** under the resource's settings (GitHub App), or copy the Coolify webhook URL
into the repo's **Settings → Webhooks** so every push to `main` redeploys.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails at `npm ci` | `web/package-lock.json` must be committed and match `package.json`. |
| Build fails at `go build` | `server/go.mod` must exist; the server uses only the Go standard library. |
| `permission denied` writing `/data/iam.json` | The container runs as UID 10001. Make sure the volume is writable, or recreate it so the image's `chown` applies. |
| 502 from the proxy | The exposed port must be `8080`. |
| Data resets on redeploy | The persistent volume at `/data` is missing. |
| Want a clean demo | Click **Reset demo data** on the home screen, or `POST /api/reset`. |
