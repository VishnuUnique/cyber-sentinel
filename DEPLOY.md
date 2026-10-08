# 🚀 Deploy Cyber Sentinel as a Public Website

## Option 1 — Streamlit Community Cloud (Dashboard) ✅ FREE & EASIEST

**Your dashboard will be live at a public URL in under 5 minutes.**

### Steps:
1. Push this repo to GitHub (must be public)
2. Go to **[share.streamlit.io](https://share.streamlit.io)** and sign in with GitHub
3. Click **"New app"**
4. Fill in:
   - Repository: `VishnuUnique/cyber-sentinel`
   - Branch: `main`
   - Main file path: `streamlit_app.py`
5. Click **"Deploy!"**

The app auto-generates demo data and trains models on first boot (~30 seconds).

**Live URL format:** `https://vishnuunique-cyber-sentinel-streamlit-app-xxxx.streamlit.app`

---

## Option 2 — Render.com (API + Dashboard) ✅ FREE

1. Push repo to GitHub
2. Go to **[render.com](https://render.com)** → New → **Blueprint**
3. Connect your GitHub repo — Render reads `render.yaml` automatically
4. Click **Apply**

**API URL:** `https://cyber-sentinel-api.onrender.com`  
**Dashboard URL:** `https://cyber-sentinel-dashboard.onrender.com`  
**API Docs:** `https://cyber-sentinel-api.onrender.com/docs`

> ⚠️ Free tier spins down after 15min inactivity — first request takes ~30s to wake up.

---

## Option 3 — Railway.app ✅ FREE $5 credit

1. Go to **[railway.app](https://railway.app)**
2. Click **"New Project"** → **"Deploy from GitHub repo"**
3. Select `VishnuUnique/cyber-sentinel`
4. Railway reads `railway.json` and deploys automatically

**Live URL:** `https://cyber-sentinel-production.up.railway.app`

---

## Option 4 — Instant Public URL with ngrok (No deployment needed)

```bash
# 1. Install ngrok from https://ngrok.com/download

# 2. Run the dashboard locally
pip install -e .
python scripts/generate_demo_data.py
python scripts/train_models.py
streamlit run streamlit_app.py &

# 3. Expose it publicly
ngrok http 8501
# → Forwarding: https://abc123.ngrok.io → http://localhost:8501
```

Share the `https://abc123.ngrok.io` link — works immediately, no signup needed.

---

## Push to GitHub First

```powershell
cd "c:\Users\afsha\PROJECT\New folder\cyber-sentinel"
git init
git remote add origin https://github.com/VishnuUnique/cyber-sentinel.git
git add .
git commit -m "Initial commit: Cyber Sentinel - Intelligent Threat Detection"
git branch -M main
git push -u origin main
```

After pushing, use **Option 1 (Streamlit Cloud)** for the fastest public demo URL.
