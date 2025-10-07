🕌 MabrurX — Django + Firebase App

MabrurX is a Django web platform for managing pilgrims, agencies, and haj/umrah logs.
It uses Firebase Firestore for data storage and JWT authentication for API security.

🧩 Features

🔐 JWT Authentication with Django REST Framework

☁️ Firebase Firestore database integration

🧭 Admin, Agency & Pilgrim dashboards

🕋 Real-time haj/umrah logs

📦 Modular Django app structure

⚙️ Requirements

Python 3.10+

pip (Python package manager)

Git

A Firebase Project (with a valid serviceAccountKey.json file)

🧱 Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/<your-username>/mabrurx.git
cd mabrurx

2️⃣ Create and Activate a Virtual Environment
python -m venv venv
venv\Scripts\activate     # On Windows
# source venv/bin/activate  # On macOS/Linux

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Create a .env File

In the project root, create a file named .env and add:

SECRET_KEY=your-django-secret-key
DEBUG=True
FIREBASE_KEY=serviceAccountKey.json


⚠️ Do not commit this file to GitHub.

🔥 Firebase Setup

Go to Firebase Console
.

Create a new project (if not already done).

In Project Settings → Service Accounts, click “Generate new private key”.

Save the downloaded JSON file as:

serviceAccountKey.json


and place it inside your project root folder.

🗃️ Apply Database Migrations
python manage.py migrate

▶️ Run the Development Server
python manage.py runserver


Then open your browser and visit:
👉 http://127.0.0.1:8000

🧪 Testing the App

You can test the main features by:

Registering a new user or agency at /register/

Logging in at /login/

Viewing dashboards:

Agency Dashboard → /agency_dashboard

Government Dashboard → /government_dashboard

Checking API endpoints (JWT-protected)

You can use Postman
 or cURL
 to test API calls.

Example API call (replace <token> with your JWT):

curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/pilgrims/
