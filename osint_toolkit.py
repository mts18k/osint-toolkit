import streamlit as st
import requests
import dns.resolver
import whois
import hashlib
import socket
import base64
import urllib.parse
import random
import string
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from datetime import datetime, timezone
import time

st.set_page_config(page_title="OSINT / SOCMINT Toolkit", page_icon="🕵️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    .main-header { font-size: 2.1rem; font-weight: 700; color: #4da6ff; margin-bottom: 0.15rem; }
    .sub-header { color: #aaa; font-size: 0.9rem; margin-bottom: 1rem; }
    .stButton>button { width: 100%; }
    .stApp { background-color: #0e1117; color: #fafafa; }
    section[data-testid="stSidebar"] { background-color: #161625; }
    h1,h2,h3,h4,p,span,label,.stMarkdown { color: #f0f0f0 !important; }
    .stTextInput input, .stTextArea textarea, .stSelectbox div { background-color: #1e1e2f !important; color: #fff !important; }
</style>
""", unsafe_allow_html=True)

# Historique simple
if "history" not in st.session_state:
    st.session_state.history = []

def add_history(action, detail):
    st.session_state.history.insert(0, f"{datetime.now().strftime('%H:%M')} - {action} : {detail}")
    st.session_state.history = st.session_state.history[:20]

with st.sidebar:
    st.title("🕵️ OSINT Toolkit")
    st.caption("Version 3.0 • Complet")
    st.markdown("---")
    page = st.radio("**Outils**", [
        "🏠 Accueil",
        "👤 Username",
        "📧 Email",
        "🌐 Domaine",
        "🌍 Adresse IP",
        "🔗 Analyse URL",
        "📱 Téléphone",
        "🧑 Nom / Prénom",
        "🖼️ Image inversée",
        "📨 En-têtes Email",
        "🔐 Encodeur / Hash",
        "🔑 Mot de passe",
        "🎭 Fausse identité",
        "⏱️ Timestamp",
        "🌐 User-Agent",
        "🔎 Dorks & Cheat Sheet",
        "📋 Checklist Investigation",
        "🔒 Certificat SSL",
        "📍 Mon IP + Logger",
        "📜 Historique",
        "📚 Outils recommandés"
    ])
    st.markdown("---")
    st.info("Usage éducatif & légitime uniquement")

# ==================== ACCUEIL ====================
if page == "🏠 Accueil":
    st.markdown('<p class="main-header">🕵️ OSINT / SOCMINT Toolkit v3.0</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Outil complet de renseignement en sources ouvertes</p>', unsafe_allow_html=True)
    st.success("Toutes les fonctionnalités demandées ont été ajoutées.")
    st.markdown("""
    ### Catégories disponibles
    - **Investigation** : Username, Email, Domaine, IP, URL, Téléphone, Nom/Prénom, Image, Headers
    - **Utilitaires** : Encodeur, Hash, Mot de passe, Fausse identité, Timestamp, User-Agent
    - **Avancé** : Dorks, Checklist, Certificat SSL, IP Logger info, Historique
    """)

# ==================== USERNAME ====================
elif page == "👤 Username":
    st.markdown('<p class="main-header">👤 Username (SOCMINT)</p>', unsafe_allow_html=True)
    username = st.text_input("Username", placeholder="elonmusk")
    if st.button("🔍 Rechercher", type="primary") and username:
        username = username.strip().replace("@", "")
        add_history("Username", username)
        sites = {
            "GitHub": f"https://github.com/{username}", "Twitter/X": f"https://x.com/{username}",
            "Instagram": f"https://www.instagram.com/{username}/", "Reddit": f"https://www.reddit.com/user/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}", "YouTube": f"https://www.youtube.com/@{username}",
            "LinkedIn": f"https://www.linkedin.com/in/{username}", "Twitch": f"https://www.twitch.tv/{username}",
            "Telegram": f"https://t.me/{username}", "Steam": f"https://steamcommunity.com/id/{username}",
            "GitLab": f"https://gitlab.com/{username}", "Medium": f"https://medium.com/@{username}",
            "Keybase": f"https://keybase.io/{username}", "About.me": f"https://about.me/{username}",
            "Dev.to": f"https://dev.to/{username}", "Dribbble": f"https://dribbble.com/{username}",
            "Behance": f"https://www.behance.net/{username}", "SoundCloud": f"https://soundcloud.com/{username}",
            "Spotify": f"https://open.spotify.com/user/{username}", "Chess.com": f"https://www.chess.com/member/{username}",
            "Roblox": f"https://www.roblox.com/user.aspx?username={username}", "Duolingo": f"https://www.duolingo.com/profile/{username}",
            "Pinterest": f"https://www.pinterest.com/{username}/", "Vimeo": f"https://vimeo.com/{username}",
            "Flickr": f"https://www.flickr.com/people/{username}", "HackerNews": f"https://news.ycombinator.com/user?id={username}",
            "ProductHunt": f"https://www.producthunt.com/@{username}", "CashApp": f"https://cash.app/${username}",
        }
        def check(n, u):
            try:
                r = requests.get(u, headers={"User-Agent": "Mozilla/5.0"}, timeout=6, allow_redirects=True)
                if r.status_code == 200 and not any(x in r.text.lower() for x in ["not found", "n'existe pas", "page not found", "doesn't exist"]):
                    return n, u, True
                return n, u, False
            except: return n, u, False
        res = []
        prog = st.progress(0)
        with ThreadPoolExecutor(max_workers=14) as ex:
            futs = [ex.submit(check, n, u) for n, u in sites.items()]
            for i, f in enumerate(as_completed(futs)):
                res.append(f.result())
                prog.progress((i+1)/len(futs))
        prog.empty()
        found = [r for r in res if r[2]]
        st.success(f"{len(found)} trouvé(s) / {len(sites)}")
        c1, c2 = st.columns(2)
        with c1:
            for n, u, _ in sorted(found):
                st.markdown(f"**{n}** → [{u}]({u})")
        with c2:
            with st.expander("Non trouvés"):
                for n, _, _ in sorted([r for r in res if not r[2]]):
                    st.write(f"• {n}")

# ==================== EMAIL ====================
elif page == "📧 Email":
    st.markdown('<p class="main-header">📧 Email</p>', unsafe_allow_html=True)
    email = st.text_input("Email")
    if st.button("🔍 Analyser", type="primary") and email:
        email = email.strip().lower()
        add_history("Email", email)
        if "@" in email:
            dom = email.split("@")[1]
            ghash = hashlib.md5(email.encode()).hexdigest()
            try:
                if requests.get(f"https://www.gravatar.com/avatar/{ghash}?d=404", timeout=5).status_code == 200:
                    st.success("Gravatar trouvé")
                    st.image(f"https://www.gravatar.com/avatar/{ghash}?s=120", width=100)
            except: pass
            try:
                for r in dns.resolver.resolve(dom, 'MX'):
                    st.write(f"MX: {r.exchange}")
            except: pass
            st.markdown(f"- [HIBP](https://haveibeenpwned.com/account/{quote(email)})\n- [Epieos](https://epieos.com/?q={quote(email)})")

# ==================== DOMAINE ====================
elif page == "🌐 Domaine":
    st.markdown('<p class="main-header">🌐 Domaine</p>', unsafe_allow_html=True)
    domain = st.text_input("Domaine", placeholder="example.com")
    if st.button("🔍 Analyser", type="primary") and domain:
        domain = domain.strip().lower().replace("https://","").replace("http://","").replace("www.","").split("/")[0]
        add_history("Domaine", domain)
        try:
            socket.gethostbyname(domain)
            st.warning("Domaine pris (résout)")
        except: st.success("Semble libre / non résolu")
        try:
            w = whois.whois(domain)
            st.write(f"Registrar: {w.registrar} | Création: {w.creation_date} | Exp: {w.expiration_date}")
        except: pass
        for rt in ['A','MX','NS','TXT']:
            try:
                ans = dns.resolver.resolve(domain, rt)
                st.write(f"**{rt}**")
                for a in ans: st.code(str(a))
            except: pass

# ==================== IP ====================
elif page == "🌍 Adresse IP":
    st.markdown('<p class="main-header">🌍 Adresse IP</p>', unsafe_allow_html=True)
    ip = st.text_input("IP", placeholder="8.8.8.8")
    if st.button("🔍 Analyser", type="primary") and ip:
        add_history("IP", ip)
        try:
            socket.inet_aton(ip)
            data = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,proxy,hosting", timeout=8).json()
            if data.get("status")=="success":
                c1,c2,c3 = st.columns(3)
                c1.metric("Pays", f"{data.get('country')} ({data.get('countryCode')})")
                c1.metric("Ville", data.get('city'))
                c2.metric("FAI", data.get('isp'))
                c2.metric("Org", data.get('org'))
                c3.metric("ASN", data.get('as'))
                c3.metric("Coords", f"{data.get('lat')}, {data.get('lon')}")
                if data.get("proxy"): st.write("🟡 Proxy/VPN")
                if data.get("hosting"): st.write("🟡 Datacenter")
                st.markdown(f"[Shodan](https://www.shodan.io/host/{ip}) • [AbuseIPDB](https://www.abuseipdb.com/check/{ip})")
        except: st.error("IP invalide")

# ==================== URL ====================
elif page == "🔗 Analyse URL":
    st.markdown('<p class="main-header">🔗 Analyse URL</p>', unsafe_allow_html=True)
    url = st.text_input("URL")
    if st.button("🔍 Analyser", type="primary") and url:
        if not url.startswith("http"): url = "https://" + url
        add_history("URL", url)
        try:
            r = requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=10, allow_redirects=True)
            st.write(f"Status: **{r.status_code}** | Temps: {r.elapsed.total_seconds():.2f}s | Taille: {len(r.content)} o")
            for h in ["Server","X-Powered-By","Content-Type"]:
                if h in r.headers: st.write(f"{h}: `{r.headers[h]}`")
        except Exception as e: st.error(str(e))

# ==================== TELEPHONE ====================
elif page == "📱 Téléphone":
    st.markdown('<p class="main-header">📱 Téléphone</p>', unsafe_allow_html=True)
    phone = st.text_input("Numéro")
    if st.button("🔍 Générer", type="primary") and phone:
        p = phone.replace(" ","").replace("-","")
        add_history("Téléphone", phone)
        st.code(f'"{p}"')
        st.markdown(f"[Google](https://www.google.com/search?q={quote(p)}) • [Truecaller](https://www.truecaller.com/)")

# ==================== NOM ====================
elif page == "🧑 Nom / Prénom":
    st.markdown('<p class="main-header">🧑 Nom / Prénom</p>', unsafe_allow_html=True)
    c1,c2 = st.columns(2)
    prenom = c1.text_input("Prénom")
    nom = c2.text_input("Nom")
    ville = st.text_input("Ville (opt)")
    if st.button("🔍 Générer", type="primary") and (prenom or nom):
        full = f"{prenom} {nom}".strip()
        add_history("Nom", full)
        for d in [f'"{full}"', f'"{full}" (linkedin OR facebook)', f'site:linkedin.com/in "{full}"']:
            st.code(d)
        st.markdown(f"[Google](https://www.google.com/search?q={quote(full)}) • [LinkedIn](https://www.linkedin.com/search/results/all/?keywords={quote(full)})")

# ==================== IMAGE ====================
elif page == "🖼️ Image inversée":
    st.markdown('<p class="main-header">🖼️ Image inversée</p>', unsafe_allow_html=True)
    img = st.text_input("URL de l'image")
    if img:
        enc = quote(img, safe='')
        st.markdown(f"""
        - [Google Lens](https://lens.google.com/uploadbyurl?url={enc})
        - [Yandex](https://yandex.com/images/search?rpt=imageview&url={enc})
        - [TinEye](https://tineye.com/search?url={enc})
        - [Bing](https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{enc})
        """)

# ==================== HEADERS EMAIL ====================
elif page == "📨 En-têtes Email":
    st.markdown('<p class="main-header">📨 En-têtes Email</p>', unsafe_allow_html=True)
    headers = st.text_area("Colle les headers complets", height=200)
    if st.button("🔍 Analyser", type="primary") and headers:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', headers)
        public = [ip for ip in set(ips) if not ip.startswith(("10.","192.168.","127.","0."))]
        if public:
            for ip in public:
                st.code(ip)
                st.markdown(f"[ipinfo.io/{ip}](https://ipinfo.io/{ip})")
        else:
            st.warning("Aucune IP publique trouvée")

# ==================== ENCODEUR / HASH ====================
elif page == "🔐 Encodeur / Hash":
    st.markdown('<p class="main-header">🔐 Encodeur / Hash / Comparateur</p>', unsafe_allow_html=True)
    tab1, tab2, tab3 = st.tabs(["Encodeur", "Hash texte", "Comparateur Hash"])
    with tab1:
        txt = st.text_area("Texte")
        c1,c2 = st.columns(2)
        if c1.button("Base64 Encode") and txt: st.code(base64.b64encode(txt.encode()).decode())
        if c2.button("Base64 Decode") and txt:
            try: st.code(base64.b64decode(txt).decode())
            except: st.error("Erreur")
        if c1.button("URL Encode") and txt: st.code(urllib.parse.quote(txt))
        if c2.button("URL Decode") and txt: st.code(urllib.parse.unquote(txt))
    with tab2:
        txt2 = st.text_input("Texte à hasher")
        if st.button("Hasher") and txt2:
            st.code(f"MD5    : {hashlib.md5(txt2.encode()).hexdigest()}")
            st.code(f"SHA1   : {hashlib.sha1(txt2.encode()).hexdigest()}")
            st.code(f"SHA256 : {hashlib.sha256(txt2.encode()).hexdigest()}")
    with tab3:
        h1 = st.text_input("Hash 1")
        h2 = st.text_input("Hash 2")
        if st.button("Comparer") and h1 and h2:
            if h1.lower() == h2.lower(): st.success("Identiques")
            else: st.error("Différents")

# ==================== MOT DE PASSE ====================
elif page == "🔑 Mot de passe":
    st.markdown('<p class="main-header">🔑 Mot de passe</p>', unsafe_allow_html=True)
    tab1, tab2 = st.tabs(["Générateur", "Vérifier fuite (HIBP)"])
    with tab1:
        length = st.slider("Longueur", 8, 64, 16)
        use_upper = st.checkbox("Majuscules", True)
        use_digits = st.checkbox("Chiffres", True)
        use_symbols = st.checkbox("Symboles", True)
        if st.button("Générer"):
            chars = string.ascii_lowercase
            if use_upper: chars += string.ascii_uppercase
            if use_digits: chars += string.digits
            if use_symbols: chars += "!@#$%^&*()-_=+"
            pwd = ''.join(random.choice(chars) for _ in range(length))
            st.code(pwd)
            st.download_button("Copier", pwd, "password.txt")
    with tab2:
        pwd = st.text_input("Mot de passe à vérifier", type="password")
        if st.button("Vérifier sur Have I Been Pwned") and pwd:
            sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            try:
                r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
                if suffix in r.text:
                    count = 0
                    for line in r.text.splitlines():
                        if line.startswith(suffix):
                            count = int(line.split(":")[1])
                            break
                    st.error(f"⚠️ Ce mot de passe a été vu {count} fois dans des fuites !")
                else:
                    st.success("Bonne nouvelle : pas trouvé dans les fuites connues.")
            except: st.warning("Erreur API")

# ==================== FAUSSE IDENTITE ====================
elif page == "🎭 Fausse identité":
    st.markdown('<p class="main-header">🎭 Générateur de fausse identité</p>', unsafe_allow_html=True)
    if st.button("Générer une identité", type="primary"):
        prenoms = ["Lucas","Emma","Hugo","Léa","Raphaël","Chloé","Louis","Manon","Gabriel","Jade","Arthur","Louise","Jules","Alice","Adam","Lina"]
        noms = ["Martin","Bernard","Dubois","Thomas","Robert","Richard","Petit","Durand","Leroy","Moreau","Simon","Laurent","Lefebvre","Michel","Garcia","David"]
        rues = ["Rue de la Paix","Avenue des Champs","Boulevard Victor Hugo","Rue Jean Jaurès","Place de la République","Allée des Roses"]
        villes = ["Paris","Lyon","Marseille","Toulouse","Nice","Nantes","Strasbourg","Montpellier","Bordeaux","Lille"]
        p, n = random.choice(prenoms), random.choice(noms)
        st.write(f"**Nom complet :** {p} {n}")
        st.write(f"**Email :** {p.lower()}.{n.lower()}{random.randint(1,99)}@gmail.com")
        st.write(f"**Téléphone :** 06{random.randint(10,99)}{random.randint(10,99)}{random.randint(10,99)}{random.randint(10,99)}")
        st.write(f"**Adresse :** {random.randint(1,120)} {random.choice(rues)}, {random.randint(10000,95000)} {random.choice(villes)}")
        st.write(f"**Date de naissance :** {random.randint(1,28)}/{random.randint(1,12)}/{random.randint(1975,2005)}")
        st.info("Identité 100% fictive • Pour tests / OPSEC uniquement")

# ==================== TIMESTAMP ====================
elif page == "⏱️ Timestamp":
    st.markdown('<p class="main-header">⏱️ Convertisseur Timestamp</p>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        ts = st.number_input("Timestamp (secondes)", value=int(time.time()), step=1)
        if st.button("Timestamp → Date"):
            st.code(datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    with c2:
        st.write(f"Timestamp actuel : `{int(time.time())}`")
        st.write(f"Date actuelle : `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`")

# ==================== USER AGENT ====================
elif page == "🌐 User-Agent":
    st.markdown('<p class="main-header">🌐 Générateur User-Agent</p>', unsafe_allow_html=True)
    uas = {
        "Chrome Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Firefox Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Chrome Android": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
        "Safari iPhone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Curl": "curl/8.5.0",
        "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    }
    choice = st.selectbox("Choisir un User-Agent", list(uas.keys()))
    st.code(uas[choice])
    if st.button("Générer un aléatoire"):
        st.code(random.choice(list(uas.values())))

# ==================== DORKS & CHEAT SHEET ====================
elif page == "🔎 Dorks & Cheat Sheet":
    st.markdown('<p class="main-header">🔎 Dorks & Cheat Sheet</p>', unsafe_allow_html=True)
    tab1, tab2 = st.tabs(["Dorks par catégorie", "Cheat Sheet OSINT"])
    with tab1:
        cat = st.selectbox("Catégorie", ["Email", "Documents", "Caméras / IoT", "Fichiers sensibles", "Réseaux sociaux"])
        dorks_dict = {
            "Email": ['"@gmail.com" filetype:xls', '"password" "@gmail.com"', 'site:pastebin.com "@gmail.com"'],
            "Documents": ['filetype:pdf "confidential"', 'filetype:docx "salary"', 'filetype:xlsx "password"'],
            "Caméras / IoT": ['inurl:"view/index.shtml"', 'intitle:"Live View / - AXIS"', 'inurl:/Viewer.html'],
            "Fichiers sensibles": ['filetype:env "DB_PASSWORD"', 'filetype:sql "INSERT INTO"', 'intitle:"index of" "backup"'],
            "Réseaux sociaux": ['site:linkedin.com/in "CEO"', 'site:twitter.com "email" "@gmail.com"']
        }
        for d in dorks_dict.get(cat, []):
            st.code(d)
            st.markdown(f"[Lancer](https://www.google.com/search?q={quote(d)})")
    with tab2:
        st.markdown("""
        ### Les principaux INT
        - **OSINT** : Sources ouvertes (web, médias, registres)
        - **SOCMINT** : Réseaux sociaux
        - **HUMINT** : Sources humaines
        - **SIGINT** : Signaux / communications
        - **GEOINT** : Géospatial
        - **CSINT** : Sources fermées / commerciales
        
        ### Commandes utiles
        ```bash
        pip install sherlock-project maigret holehe
        sherlock username
        maigret username
        holehe email@example.com
        ```
        """)

# ==================== CHECKLIST ====================
elif page == "📋 Checklist Investigation":
    st.markdown('<p class="main-header">📋 Checklist Investigation OSINT</p>', unsafe_allow_html=True)
    st.markdown("""
    ### Étapes recommandées
    1. **Définir l'objectif** clairement
    2. **Username** → Sherlock / Maigret / cet outil
    3. **Email** → Holehe + HIBP + Epieos
    4. **Nom/Prénom** → Google Dorks + LinkedIn + Facebook
    5. **Images** → Recherche inversée (Yandex souvent le meilleur)
    6. **Domaine / IP** → WHOIS + crt.sh + Shodan
    7. **Téléphone** → Truecaller + dorks
    8. **Croiser les infos** et vérifier les sources
    9. **Documenter** tout (captures + notes)
    10. **Respecter la loi** et l'éthique
    """)
    st.checkbox("Objectif défini")
    st.checkbox("Usernames vérifiés")
    st.checkbox("Emails analysés")
    st.checkbox("Images cherchées")
    st.checkbox("Rapport rédigé")

# ==================== SSL ====================
elif page == "🔒 Certificat SSL":
    st.markdown('<p class="main-header">🔒 Certificat SSL</p>', unsafe_allow_html=True)
    host = st.text_input("Domaine", placeholder="google.com")
    if st.button("🔍 Analyser", type="primary") and host:
        host = host.replace("https://","").replace("http://","").split("/")[0]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, 443))
                cert = s.getpeercert()
            st.write(f"**Sujet :** {dict(x[0] for x in cert.get('subject', []))}")
            st.write(f"**Émetteur :** {dict(x[0] for x in cert.get('issuer', []))}")
            st.write(f"**Valide du :** {cert.get('notBefore')}")
            st.write(f"**Valide jusqu'au :** {cert.get('notAfter')}")
            st.write(f"**Numéro de série :** {cert.get('serialNumber')}")
        except Exception as e:
            st.error(f"Erreur : {e}")

# ==================== MON IP ====================
elif page == "📍 Mon IP + Logger":
    st.markdown('<p class="main-header">📍 Mon IP + IP Logger</p>', unsafe_allow_html=True)
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
        st.code(ip)
        st.markdown(f"[Détails](https://ipinfo.io/{ip})")
    except: st.warning("Impossible de récupérer l'IP")
    st.markdown("""
    ### Services IP Logger
    - [Grabify](https://grabify.link)
    - [IPLogger](https://iplogger.com)
    
    Crée un lien → envoie-le → regarde les IP qui cliquent.
    ⚠️ Usage malveillant = illégal.
    """)

# ==================== HISTORIQUE ====================
elif page == "📜 Historique":
    st.markdown('<p class="main-header">📜 Historique de session</p>', unsafe_allow_html=True)
    if st.session_state.history:
        for h in st.session_state.history:
            st.write(h)
        if st.button("Effacer l'historique"):
            st.session_state.history = []
            st.rerun()
    else:
        st.info("Aucune recherche effectuée dans cette session.")

# ==================== OUTILS RECOMMANDES ====================
elif page == "📚 Outils recommandés":
    st.markdown('<p class="main-header">📚 Outils recommandés</p>', unsafe_allow_html=True)
    st.markdown("""
    **Username :** Sherlock, Maigret, WhatsMyName, Blackbird  
    **Email :** Holehe, HIBP, Epieos  
    **IP/Domaine :** Shodan, Censys, crt.sh, SecurityTrails  
    **Téléphone :** PhoneInfoga, Truecaller  
    **Images :** Yandex, Google Lens, TinEye  
    **IP Logger :** Grabify, IPLogger.com  
    **Frameworks :** SpiderFoot, theHarvester, Recon-ng  
    """)

st.markdown("---")
st.caption("OSINT Toolkit v3.0 • Toutes fonctionnalités • Usage éducatif & légitime uniquement")
