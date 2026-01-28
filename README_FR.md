# 🎵 SongWish - Assistant IA pour la Gestion de Cadeaux Musicaux

## 📋 Vue d'ensemble

**SongWish** est une application web intelligente construite avec Flask et alimentée par OpenAI GPT-4. Elle aide les utilisateurs à découvrir et gérer des listes de cadeaux musicaux personnalisées en utilisant un assistant IA conversationnel.

L'application intègre des technologies modernes incluant:
- **LangChain** pour la gestion d'états conversationnels complexes
- **ChromaDB** pour le stockage vectoriel et la recherche sémantique (RAG)
- **FastSpring API** pour la gestion des commandes
- **LicenseSpring** pour la gestion des licences
- **Auth0** pour l'authentification sécurisée

---

## ✨ Caractéristiques principales

### 🤖 Assistant IA Conversationnel
- Assistance en temps réel pour découvrir des cadeaux musicaux
- Recommandations intelligentes basées sur les préférences utilisateur
- Gestion contextuelle des conversations avec historique

### 🎁 Gestion de Cadeaux
- Création et organisation de listes de cadeaux
- Partage de listes avec d'autres utilisateurs
- Suivi du statut des cadeaux (disponible, réclamé, acheté)

### 💳 Intégration E-commerce
- Intégration complète FastSpring pour les paiements
- Gestion des commandes
- Support multi-devises

### 🔐 Sécurité & Authentification
- Authentification Auth0
- Jetons JWT pour les requêtes API
- Limite de taux pour prévenir les abus

### 📚 Architecture RAG (Retrieval Augmented Generation)
- ChromaDB pour le stockage vectoriel
- Recherche sémantique contextuelle
- Réduction des hallucinations de l'IA

---

## 🛠️ Stack Technologique

### Backend
- **Flask** 3.1.0 - Framework web Python
- **Gunicorn** 23.0.0 - Serveur WSGI production
- **Flask-CORS** 5.0.1 - Support CORS

### IA & NLP
- **OpenAI** 1.78.1 - API GPT-4
- **LangChain** 0.3.25 - Orchestration IA
- **ChromaDB** 1.0.9 - Base de données vectorielle
- **LangChain Text Splitters** 0.3.8 - Traitement de texte

### Intégrations
- **FastSpring API** - Gestion des paiements
- **LicenseSpring API** - Gestion des licences
- **Auth0** - Authentification SSO

### Autres
- **python-dotenv** 1.0.1 - Gestion des variables d'environnement
- **PyJWT** 2.8.0 - Authentification JWT
- **cryptography** 41.0.7 - Chiffrement
- **requests** 2.32.3 - Requêtes HTTP
- **Flask-Limiter** 3.11.0 - Limitation de taux

---

## 📦 Installation

### Prérequis
- Python 3.8+
- pip ou conda
- Variables d'environnement configurées (.env)

### Étapes d'installation

1. **Cloner le repository**
```bash
git clone https://github.com/yourusername/songwish.git
cd songwish
```

2. **Créer un environnement virtuel**
```bash
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate
```

3. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

4. **Configurer les variables d'environnement**

Créer un fichier `.env` à la racine du projet:

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

5. **Démarrer l'application**
```bash
python app.py
```

L'application sera accessible à `http://localhost:5000`

---

## 🚀 Déploiement

### Heroku

1. **Configurer Heroku CLI**
```bash
heroku login
```

2. **Créer l'application Heroku**
```bash
heroku create songwish-app
```

3. **Ajouter les variables d'environnement**
```bash
heroku config:set OPENAI_API_KEY=your_key
heroku config:set IS_PRODUCTION=true
# ... ajouter les autres variables
```

4. **Déployer**
```bash
git push heroku main
```

### Docker

1. **Build l'image**
```bash
docker build -t songwish .
```

2. **Exécuter le conteneur**
```bash
docker run -e OPENAI_API_KEY=your_key \
           -e IS_PRODUCTION=true \
           -p 5000:5000 \
           songwish
```

---

## 📚 Structure du Projet

```
songwish/
├── app.py                 # Fichier principal de l'application
├── config.py              # Configuration et variables d'environnement
├── requirements.txt       # Dépendances Python
├── Procfile              # Configuration Heroku
├── .env                  # Variables d'environnement (git ignored)
├── .gitignore            # Fichiers à ignorer
├── README.md             # Cette documentation
│
├── routes/               # Endpoints API
│   ├── __init__.py
│   ├── assistant.py      # Routes pour l'assistant IA
│   ├── gifts.py          # Routes pour les cadeaux
│   ├── orders.py         # Routes pour les commandes
│   └── auth.py           # Routes pour l'authentification
│
├── services/             # Logique métier
│   ├── __init__.py
│   ├── openai_service.py # Intégration OpenAI
│   ├── chroma_service.py # Gestion ChromaDB
│   ├── fastspring_service.py
│   ├── licensespring_service.py
│   └── auth_service.py
│
├── models/               # Modèles de données
│   ├── __init__.py
│   ├── gift.py
│   ├── conversation.py
│   └── user.py
│
├── utils/                # Utilitaires
│   ├── __init__.py
│   ├── validators.py
│   ├── decorators.py
│   └── helpers.py
│
└── tests/                # Tests unitaires
    ├── __init__.py
    ├── test_assistant.py
    ├── test_gifts.py
    └── test_auth.py
```

---

## 🔌 API Endpoints

### Assistant IA

**POST** `/api/assistant/chat`
- Envoyer un message à l'assistant IA
- Body: `{ "message": "string", "session_id": "string" }`
- Response: `{ "response": "string", "recommendations": [] }`

**GET** `/api/assistant/history/{session_id}`
- Récupérer l'historique de conversation

### Cadeaux

**GET** `/api/gifts`
- Récupérer la liste des cadeaux de l'utilisateur

**POST** `/api/gifts`
- Créer un nouveau cadeau

**PUT** `/api/gifts/{id}`
- Mettre à jour un cadeau

**DELETE** `/api/gifts/{id}`
- Supprimer un cadeau

### Commandes

**GET** `/api/orders`
- Récupérer les commandes de l'utilisateur

**POST** `/api/orders`
- Créer une nouvelle commande

**GET** `/api/orders/{id}`
- Récupérer les détails d'une commande

### Authentification

**POST** `/api/auth/login`
- Login avec Auth0

**POST** `/api/auth/logout`
- Logout

**GET** `/api/auth/me`
- Récupérer les informations de l'utilisateur connecté

---

## 🧪 Tests

Exécuter les tests:

```bash
# Tous les tests
pytest

# Tests spécifiques
pytest tests/test_assistant.py

# Avec couverture
pytest --cov=.

# Verbose
pytest -v
```

---

## 🔐 Sécurité

### Bonnes pratiques implémentées

1. **Variables d'environnement** - Pas de secrets en dur
2. **CORS** - Contrôle d'accès cross-origin
3. **Rate Limiting** - Protection contre les abus
4. **JWT Tokens** - Authentification sécurisée
5. **Input Validation** - Validation de toutes les entrées
6. **Error Handling** - Gestion sécurisée des erreurs

### Checklist de sécurité avant production

- [ ] Activer `IS_PRODUCTION=true`
- [ ] Configurer les domaines CORS autorisés
- [ ] Mettre à jour les tokens d'API
- [ ] Activer HTTPS
- [ ] Configurer les headers de sécurité
- [ ] Mettre en place le monitoring
- [ ] Configurer les logs

---

## 📈 Performance & Scalabilité

### Optimisations implémentées

- **Caching** avec Redis (optionnel)
- **Rate Limiting** pour prévenir les abus
- **Async Operations** pour les tâches longues
- **Database Indexing** pour les requêtes rapides
- **Vector Search** optimisé avec ChromaDB

### Métriques recommandées à monitorer

- Temps de réponse moyen
- Nombre de requêtes/seconde
- Taux d'erreur
- Utilisation de la mémoire
- Utilisation du CPU

---

## 🐛 Dépannage

### Problème: `ModuleNotFoundError`
**Solution**: Assurez-vous d'avoir installé les dépendances
```bash
pip install -r requirements.txt
```

### Problème: `OpenAI API Error`
**Solution**: Vérifiez que votre clé API est valide et vérifiez votre quota

### Problème: `Connection Error with ChromaDB`
**Solution**: Assurez-vous que ChromaDB est correctement initialisé
```bash
python -c "import chromadb; chromadb.Client()"
```

### Problème: `Auth0 Authentication Failed`
**Solution**: Vérifiez que vos paramètres Auth0 sont corrects dans .env

---

## 📞 Support & Contact

- **Issues**: Créer une issue GitHub
- **Email**: support@songwish.com
- **Documentation**: https://docs.songwish.com

---

## 📄 Licence

Ce projet est licencié sous la licence MIT. Voir le fichier LICENSE pour plus de détails.

---

## 🤝 Contribution

Les contributions sont bienvenues! Veuillez:

1. Fork le repository
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Committer vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

---

## 📝 Changelog

### v1.0.0 (2024-01-XX)
- ✅ Lancement initial
- ✅ Assistant IA conversationnel
- ✅ Gestion des cadeaux
- ✅ Intégration FastSpring
- ✅ Authentification Auth0

---

## 🙏 Remerciements

- OpenAI pour l'API GPT-4
- LangChain pour l'orchestration IA
- FastSpring pour la solution de paiement
- Tous les contributeurs

---

**Créé avec ❤️ pour les amateurs de musique**
