# WatsonX-CyberThreat-Detection

# Project Setup Guide

Follow these steps to get the project up and running:

---
## ⚙️ Setup Environment Variables

Create a `.env` file in the root directory and fill in the following details:

```env
# .env.example
WATSONX_API_KEY=your_api_key_here
WATSONX_PROJECT_ID=your_project_id_here
WATSONX_URL=your_watsonx_url_here
```

---
## ✅ Create Virtual Environment

```bash
python -m venv venv
```

Activate the virtual environment:

- On **Windows**:
  ```bash
  venv\Scripts\activate
  ```

- On **macOS/Linux**:
  ```bash
  source venv/bin/activate
  ```

---

## 📦 Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Run the Backend

```bash
uvicorn enhanced_backend:app --reload --port 8000
```

---

## 🌐 Start the Frontend (Website)

```bash
npm run dev
```
