# 🏠 Tydom Delta Dore — Intégration Home Assistant

Intégration Home Assistant pour la box **Tydom** de Delta Dore, compatible HACS.

Supporte les **volets roulants**, portails, lumières, interrupteurs, thermostats, détecteurs de fumée et capteurs.

---

## ✅ Équipements supportés

| Type Tydom | Entité HA | Fonctionnalités |
|---|---|---|
| Volets roulants | `cover` | Ouvrir / Fermer / Stop / Position (0–100%) |
| Portails / Garages | `cover` | Ouvrir / Fermer / Stop |
| Lumières ON/OFF | `light` | Allumer / Éteindre |
| Variateurs | `light` | Allumer / Éteindre / Luminosité |
| Interrupteurs | `switch` | ON / OFF |
| Thermostats / Chaudières | `climate` | Consigne température / Mode |
| Détecteurs (fumée, mouvement) | `binary_sensor` | État alarme |
| Capteurs (température, batterie) | `sensor` | Valeur numérique |

---

## 📋 Prérequis

- Home Assistant OS ou Supervised (version **2023.1.0+**)
- HACS installé
- Box **Tydom 1.0** ou **Tydom 2.0** connectée à votre réseau local
- Adresse MAC de la box (étiquette sous la box)
- Code PIN / mot de passe Tydom (étiquette sous la box)

---

## 🚀 Installation via HACS (recommandé)

### Étape 1 — Ajouter le dépôt dans HACS

1. Dans Home Assistant, allez dans **HACS** → **Intégrations**
2. Cliquez sur les **3 points** (menu) en haut à droite
3. Sélectionnez **Dépôts personnalisés**
4. Remplissez le formulaire :
   - **URL** : `https://github.com/H0ros/HA_TYDOM`
   - **Catégorie** : `Intégration`
5. Cliquez sur **Ajouter**

### Étape 2 — Installer l'intégration

1. Retournez dans **HACS** → **Intégrations**
2. Cherchez **"Tydom Delta Dore"**
3. Cliquez sur l'intégration puis sur **Télécharger**
4. Confirmez le téléchargement
5. **Redémarrez Home Assistant** (Paramètres → Système → Redémarrer)

### Étape 3 — Configurer l'intégration

1. Allez dans **Paramètres** → **Appareils et services**
2. Cliquez sur **+ Ajouter une intégration**
3. Cherchez **"Tydom"**
4. Remplissez le formulaire :

| Champ | Exemple | Obligatoire |
|---|---|---|
| Adresse MAC | `AA:BB:CC:DD:EE:FF` | ✅ Oui |
| Code PIN | `123456` | ✅ Oui |
| Adresse IP | `192.168.1.50` | ❌ Non (auto) |

> 💡 L'adresse IP est optionnelle. Si votre réseau supporte **mDNS/Bonjour**, la box est découverte automatiquement via `{MAC}-tydom.local`. Sinon, entrez l'IP fixe de votre box.

---

## 🔧 Installation manuelle (sans HACS)

1. Téléchargez le dépôt :
   ```bash
   git clone https://github.com/H0ros/HA_TYDOM.git
   ```

2. Copiez le dossier dans Home Assistant :
   ```bash
   cp -r ha-tydom/custom_components/tydom /config/custom_components/
   ```
   Ou via le module **SSH & Web Terminal** de HA :
   ```bash
   cd /config/custom_components
   git clone https://github.com/H0ros/HA_TYDOM.git temp_tydom
   mv temp_tydom/custom_components/tydom .
   rm -rf temp_tydom
   ```

3. Redémarrez Home Assistant

4. Configurez l'intégration (voir Étape 3 ci-dessus)

---

## 🌐 Publier votre fork sur GitHub

### Prérequis
- Un compte GitHub
- Git installé sur votre machine

### Étapes

```bash
# 1. Cloner / initialiser le dépôt
git init ha-tydom
cd ha-tydom

# 2. Copier les fichiers du plugin (déposés par Claude)
# Copier le dossier custom_components/ et hacs.json ici

# 3. Créer le dépôt sur GitHub
# → github.com → New repository → nom : ha-tydom → Public

# 4. Pousser le code
git add .
git commit -m "feat: initial release Tydom integration"
git branch -M main
git remote add origin https://github.com/H0ros/HA_TYDOM.git
git push -u origin main

# 5. Créer un tag de release (requis par HACS)
git tag v1.0.0
git push origin v1.0.0
```

> ⚠️ **Important** : remplacez `VOTRE_USERNAME` dans `manifest.json` et `hacs.json` avant de publier.

---

## 🔍 Dépannage

### La box n'est pas trouvée automatiquement
→ Entrez l'IP manuellement dans le champ "Adresse IP" lors de la configuration.
→ Vérifiez que la box est sur le même sous-réseau que HA.

### Erreur d'authentification
→ Vérifiez le code PIN (celui imprimé sur l'étiquette, pas un éventuel mot de passe app Delta Dore).
→ La Tydom 1.0 utilise le code à 6 chiffres, la Tydom 2.0 peut utiliser un mot de passe plus long.

### Les équipements n'apparaissent pas
→ Attendez ~30 secondes après la configuration (la box envoie les données en push).
→ Consultez les logs : **Paramètres** → **Système** → **Journaux**, filtrez sur `tydom`.

### Activer les logs détaillés
Ajoutez dans `configuration.yaml` :
```yaml
logger:
  default: warning
  logs:
    custom_components.tydom: debug
```

---

## 🏗️ Architecture technique

```
custom_components/tydom/
├── __init__.py          # Point d'entrée, setup/unload
├── manifest.json        # Métadonnées HACS/HA
├── const.py             # Constantes et mappings
├── config_flow.py       # Interface de configuration UI
├── coordinator.py       # Coordinateur central des données
├── tydom_client.py      # Client WebSocket Tydom
├── cover.py             # Volets, portails, garages
├── light.py             # Lumières et variateurs
├── switch.py            # Interrupteurs
├── climate.py           # Thermostats
├── binary_sensor.py     # Détecteurs binaires
├── sensor.py            # Capteurs numériques
└── translations/
    ├── fr.json
    └── en.json
```

**Protocole** : La box Tydom communique via **WebSocket sécurisé (WSS)** avec un protocole HTTP/1.1 encapsulé et une authentification **HTTP Digest**.

---

## 📄 Licence

MIT License — libre d'utilisation, modification et redistribution.
