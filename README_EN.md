# 🎵 SongWish - AI Assistant for Music Gift Management

## 📋 Overview

**SongWish** is an intelligent web application built with Flask and powered by OpenAI GPT-4. It helps users discover and manage personalized music gift lists using a conversational AI assistant.

The application integrates modern technologies including:
- **LangChain** for managing complex conversational states
- **ChromaDB** for vector storage and semantic search (RAG)
- **FastSpring API** for order management
- **LicenseSpring** for license management
- **Auth0** for secure authentication

---

## ✨ Key Features

### 🤖 Conversational AI Assistant
- Real-time assistance for discovering music gifts
- Intelligent recommendations based on user preferences
- Context-aware conversation management with history

### 🎁 Gift Management
- Create and organize gift lists
- Share lists with other users
- Track gift status (available, claimed, purchased)

### 💳 E-commerce Integration
- Complete FastSpring integration for payments
- Order management
- Multi-currency support

### 🔐 Security & Authentication
- Auth0 authentication
- JWT tokens for API requests
- Rate limiting to prevent abuse

### 📚 RAG Architecture (Retrieval Augmented Generation)
- ChromaDB for vector storage
- Contextual semantic search
- Reduction of AI hallucinations

---

## 🛠️ Tech Stack

### Backend
- **Flask** 3.1.0 - Python web framework
- **Gunicorn** 23.0.0 - WSGI production server
- **Flask-CORS** 5.0.1 - CORS support

### AI & NLP
- **OpenAI** 1.78.1 - GPT-4 API
- **LangChain** 0.3.25 - AI orchestration
- **ChromaDB** 1.0.9 - Vector database
- **LangChain Text Splitters** 0.3.8 - Text processing

### Integrations
- **FastSpring API** - Payment management
- **LicenseSpring API** - License management
- **Auth0** - SSO authentication

### Others
- **python-dotenv** 1.0.1 - Environment variable management
- **PyJWT** 2.8.0 - JWT authentication
- **cryptography** 41.0.7 - Encryption
- **requests** 2.32.3 - HTTP requests
- **Flask-Limiter** 3.11.0 - Rate limiting

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip or conda
- Environment variables configured (.env)

### Installation Steps

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/songwish.git
cd songwish
```

2. **Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**

Create a `.env` file in the project root:

```env
# Production
IS_PRODUCTION=false

# OpenAI
OPENAI_API_KEY=your_openai_api_key

# FastSpring
FASTSPRING_API_USER=your_fastspring_user
FASTSPRING_API_PASSWORD=your_fastspring_password
FS_ACCOUNT_ENDPOINT_URL=https://api.fastspring.com/...
FS_ORDER_ENDPOINT_URL=https://api.fastspring.com/...

# LicenseSpring
LS_API_URL=https://api.licensespring.com
LS_API_KEY=your_licensespring_api_key

# Auth0
AUTH0_DOMAIN=your_domain.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
```

5. **Start the application**
```bash
python app.py
```

The application will be accessible at `http://localhost:5000`

---

## 🚀 Deployment

### Heroku

1. **Set up Heroku CLI**
```bash
heroku login
```

2. **Create Heroku application**
```bash
heroku create songwish-app
```

3. **Add environment variables**
```bash
heroku config:set OPENAI_API_KEY=your_key
heroku config:set IS_PRODUCTION=true
# ... add other variables
```

4. **Deploy**
```bash
git push heroku main
```

### Docker

1. **Build image**
```bash
docker build -t songwish .
```

2. **Run container**
```bash
docker run -e OPENAI_API_KEY=your_key \
           -e IS_PRODUCTION=true \
           -p 5000:5000 \
           songwish
```

---

## 📚 Project Structure

```
songwish/
├── app.py                 # Main application file
├── config.py              # Configuration and environment variables
├── requirements.txt       # Python dependencies
├── Procfile              # Heroku configuration
├── .env                  # Environment variables (git ignored)
├── .gitignore            # Files to ignore
├── README.md             # This documentation
│
├── routes/               # API endpoints
│   ├── __init__.py
│   ├── assistant.py      # AI assistant routes
│   ├── gifts.py          # Gift management routes
│   ├── orders.py         # Order routes
│   └── auth.py           # Authentication routes
│
├── services/             # Business logic
│   ├── __init__.py
│   ├── openai_service.py # OpenAI integration
│   ├── chroma_service.py # ChromaDB management
│   ├── fastspring_service.py
│   ├── licensespring_service.py
│   └── auth_service.py
│
├── models/               # Data models
│   ├── __init__.py
│   ├── gift.py
│   ├── conversation.py
│   └── user.py
│
├── utils/                # Utilities
│   ├── __init__.py
│   ├── validators.py
│   ├── decorators.py
│   └── helpers.py
│
└── tests/                # Unit tests
    ├── __init__.py
    ├── test_assistant.py
    ├── test_gifts.py
    └── test_auth.py
```

---

## 🔌 API Endpoints

### AI Assistant

**POST** `/api/assistant/chat`
- Send a message to the AI assistant
- Body: `{ "message": "string", "session_id": "string" }`
- Response: `{ "response": "string", "recommendations": [] }`

**GET** `/api/assistant/history/{session_id}`
- Retrieve conversation history

### Gifts

**GET** `/api/gifts`
- Get user's gift list

**POST** `/api/gifts`
- Create a new gift

**PUT** `/api/gifts/{id}`
- Update a gift

**DELETE** `/api/gifts/{id}`
- Delete a gift

### Orders

**GET** `/api/orders`
- Get user's orders

**POST** `/api/orders`
- Create a new order

**GET** `/api/orders/{id}`
- Get order details

### Authentication

**POST** `/api/auth/login`
- Login with Auth0

**POST** `/api/auth/logout`
- Logout

**GET** `/api/auth/me`
- Get current user information

---

## 🧪 Testing

Run tests:

```bash
# All tests
pytest

# Specific tests
pytest tests/test_assistant.py

# With coverage
pytest --cov=.

# Verbose
pytest -v
```

---

## 🔐 Security

### Implemented Security Practices

1. **Environment Variables** - No hardcoded secrets
2. **CORS** - Cross-origin access control
3. **Rate Limiting** - Abuse prevention
4. **JWT Tokens** - Secure authentication
5. **Input Validation** - All inputs validated
6. **Error Handling** - Safe error handling

### Security Checklist Before Production

- [ ] Enable `IS_PRODUCTION=true`
- [ ] Configure authorized CORS domains
- [ ] Update API tokens
- [ ] Enable HTTPS
- [ ] Configure security headers
- [ ] Set up monitoring
- [ ] Configure logging

---

## 📈 Performance & Scalability

### Implemented Optimizations

- **Caching** with Redis (optional)
- **Rate Limiting** to prevent abuse
- **Async Operations** for long-running tasks
- **Database Indexing** for fast queries
- **Vector Search** optimized with ChromaDB

### Recommended Metrics to Monitor

- Average response time
- Requests per second
- Error rate
- Memory usage
- CPU usage

---

## 🐛 Troubleshooting

### Issue: `ModuleNotFoundError`
**Solution**: Make sure you've installed dependencies
```bash
pip install -r requirements.txt
```

### Issue: `OpenAI API Error`
**Solution**: Verify your API key is valid and check your quota

### Issue: `Connection Error with ChromaDB`
**Solution**: Make sure ChromaDB is correctly initialized
```bash
python -c "import chromadb; chromadb.Client()"
```

### Issue: `Auth0 Authentication Failed`
**Solution**: Verify your Auth0 configuration in .env

---

## 📞 Support & Contact

- **Issues**: Create a GitHub issue
- **Email**: support@songwish.com
- **Documentation**: https://docs.songwish.com

---

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for more details.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 Changelog

### v1.0.0 (2024-01-XX)
- ✅ Initial release
- ✅ Conversational AI assistant
- ✅ Gift management
- ✅ FastSpring integration
- ✅ Auth0 authentication

---

## 🙏 Acknowledgments

- OpenAI for the GPT-4 API
- LangChain for AI orchestration
- FastSpring for payment solution
- All contributors

---

**Built with ❤️ for music lovers**
