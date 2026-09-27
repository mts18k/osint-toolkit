import streamlit as st
import requests
import dns.resolver
import whois
import hashlib
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse
from datetime import datetime

st.set_page_config(
    page_title="OSINT / SOCMINT Toolkit",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1f77b4; margin-bottom: 0.2rem; }
    .sub-header { color: #666; font-size: 0.95rem; margin-bottom: 1.3rem; }
    .stButton>button { width: 100%; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("🕵️ OSINT Toolkit")
    st.caption("Version 2.2")
    st.markdown("---")
    page = st.radio(
        "**Choisir un outil**",
        [
            "🏠 Accueil",
            "👤 Username (SOCMINT)",
            "📧 Email",
            "🌐 Domaine",
            "🌍 Adresse IP",
            "🔗 Analyse URL",
            "📱 Numéro de téléphone",
            "🧑 Nom / Prénom",
            "🔐 Calculateur Hash",
            "📁 Analyse de fichier",
            "🔎 Dorks avancés",
            "📚 Outils recommandés"
        ]
    )
    st.markdown("---")
    st.info("Sources publiques uniquement. Usage éducatif et légitime.")

# ==================== ACCUEIL ====================
if page == "🏠 Accueil":
    st.markdown('<p class="main-header">🕵️ OSINT / SOCMINT Toolkit</p>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Version 2.2 • Outil complet de renseignement en sources ouvertes</p>', unsafe_allow_html=True)

    st.markdown("""
    ### Fonctionnalités disponibles

    | Outil | Description |
    |-------|-------------|
    | **👤 Username** | Présence sur 28+ plateformes (SOCMINT) |
    | **📧 Email** | Gravatar + MX + liens d'analyse |
    | **🌐 Domaine** | WHOIS + DNS + sous-domaines |
    | **🌍 Adresse IP** | Géolocalisation, FAI, ASN, détection VPN |
    | **🔗 Analyse URL** | Status, titre, headers |
    | **📱 Téléphone** | Liens d'analyse + dorks |
    | **🧑 Nom / Prénom** | Dorks + recherches ciblées |
    | **🔐 Hash** | MD5, SHA1, SHA256, SHA512 |
    | **📁 Fichier** | Calcul de hash d'un fichier |
    | **🔎 Dorks avancés** | Générateur de Google Dorks |
    | **📚 Outils recommandés** | Meilleurs outils OSINT gratuits |
    """)

# ==================== USERNAME ====================
elif page == "👤 Username (SOCMINT)":
    st.markdown('<p class="main-header">👤 Recherche Username (SOCMINT)</p>', unsafe_allow_html=True)
    username = st.text_input("Username à rechercher", placeholder="ex: elonmusk")
    
    if st.button("🔍 Lancer la recherche", type="primary") and username:
        username = username.strip().replace("@", "").replace(" ", "")
        
        sites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter / X": f"https://x.com/{username}",
            "Instagram": f"https://www.instagram.com/{username}/",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
            "YouTube": f"https://www.youtube.com/@{username}",
            "LinkedIn": f"https://www.linkedin.com/in/{username}",
            "Pinterest": f"https://www.pinterest.com/{username}/",
            "Twitch": f"https://www.twitch.tv/{username}",
            "Medium": f"https://medium.com/@{username}",
            "Telegram": f"https://t.me/{username}",
            "Steam": f"https://steamcommunity.com/id/{username}",
            "GitLab": f"https://gitlab.com/{username}",
            "Keybase": f"https://keybase.io/{username}",
            "About.me": f"https://about.me/{username}",
            "SoundCloud": f"https://soundcloud.com/{username}",
            "Flickr": f"https://www.flickr.com/people/{username}",
            "Vimeo": f"https://vimeo.com/{username}",
            "Dribbble": f"https://dribbble.com/{username}",
            "Behance": f"https://www.behance.net/{username}",
            "ProductHunt": f"https://www.producthunt.com/@{username}",
            "HackerNews": f"https://news.ycombinator.com/user?id={username}",
            "Dev.to": f"https://dev.to/{username}",
            "CashApp": f"https://cash.app/${username}",
            "Spotify": f"https://open.spotify.com/user/{username}",
            "Roblox": f"https://www.roblox.com/user.aspx?username={username}",
            "Chess.com": f"https://www.chess.com/member/{username}",
            "Duolingo": f"https://www.duolingo.com/profile/{username}",
        }
        
        def check_site(name, url):
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            try:
                r = requests.get(url, headers=headers, timeout=7, allow_redirects=True)
                if r.status_code == 200:
                    content = r.text.lower()
                    if any(x in content for x in ["page not found", "user not found", "doesn't exist", "not found", "n'existe pas"]):
                        return name, url, False, r.status_code
                    return name, url, True, r.status_code
                return name, url, False, r.status_code
            except:
                return name, url, False, "Erreur"
        
        results = []
        progress = st.progress(0)
        status = st.empty()
        
        with ThreadPoolExecutor(max_workers=14) as executor:
            futures = {executor.submit(check_site, n, u): n for n, u in sites.items()}
            total = len(futures)
            done = 0
            for f in as_completed(futures):
                results.append(f.result())
                done += 1
                progress.progress(done / total)
                status.text(f"Scan... {done}/{total}")
        
        progress.empty()
        status.empty()
        
        found = [r for r in results if r[2]]
        not_found = [r for r in results if not r[2]]
        
        st.success(f"**{len(found)}** profil(s) trouvé(s) sur **{len(sites)}** plateformes")
        
        c1, c2 = st.columns(2)
        with c1:
            st.subheader(f"✅ Trouvé ({len(found)})")
            for name, url, _, code in sorted(found):
                st.markdown(f"**{name}**  \n[{url}]({url})")
                st.caption(f"HTTP {code}")
                st.markdown("---")
        with c2:
            st.subheader(f"❌ Non trouvé ({len(not_found)})")
            with st.expander("Voir la liste"):
                for name, url, _, code in sorted(not_found):
                    st.write(f"• {name}")
        
        if found:
            export = f"Username: {username}\nDate: {datetime.now()}\n\n"
            for name, url, _, _ in sorted(found):
                export += f"{name}: {url}\n"
            st.download_button("📥 Télécharger", export, f"username_{username}.txt")

# ==================== EMAIL ====================
elif page == "📧 Email":
    st.markdown('<p class="main-header">📧 Analyse Email</p>', unsafe_allow_html=True)
    email = st.text_input("Email", placeholder="ex: jean.dupont@gmail.com")
    
    if st.button("🔍 Analyser", type="primary") and email:
        email = email.strip().lower()
        if "@" not in email:
            st.error("Email invalide")
        else:
            local, domain = email.split("@", 1)
            st.markdown(f"### Résultats pour `{email}`")
            
            c1, c2 = st.columns(2)
            c1.metric("Partie locale", local)
            c2.metric("Domaine", domain)
            
            st.subheader("🖼️ Gravatar")
            ghash = hashlib.md5(email.encode()).hexdigest()
            gurl = f"https://www.gravatar.com/avatar/{ghash}?d=404&s=200"
            try:
                r = requests.get(gurl, timeout=6)
                if r.status_code == 200:
                    st.success("Avatar Gravatar trouvé")
                    st.image(gurl, width=120)
                else:
                    st.info("Pas d'avatar Gravatar")
            except:
                st.warning("Erreur Gravatar")
            
            st.subheader("📬 MX Records")
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                for r in sorted([(x.preference, str(x.exchange)) for x in answers]):
                    st.write(f"Priorité {r[0]} → `{r[1]}`")
            except:
                st.warning("Aucun MX trouvé")
            
            st.subheader("🔗 Liens utiles")
            st.markdown(f"""
            - [Have I Been Pwned](https://haveibeenpwned.com/account/{quote(email)})
            - [Epieos](https://epieos.com/?q={quote(email)})
            - [Hunter.io](https://hunter.io/email-verifier/{quote(email)})
            - [Holehe (local)](https://github.com/megadose/holehe)
            """)

# ==================== DOMAINE ====================
elif page == "🌐 Domaine":
    st.markdown('<p class="main-header">🌐 Analyse Domaine</p>', unsafe_allow_html=True)
    domain_input = st.text_input("Domaine", placeholder="ex: example.com")
    
    if st.button("🔍 Analyser", type="primary") and domain_input:
        domain = domain_input.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
        st.markdown(f"### Résultats pour `{domain}`")
        
        st.subheader("📋 WHOIS")
        try:
            w = whois.whois(domain)
            c1, c2 = st.columns(2)
            with c1:
                st.write(f"**Registrar** : {w.registrar}")
                st.write(f"**Création** : {w.creation_date}")
                st.write(f"**Expiration** : {w.expiration_date}")
            with c2:
                st.write(f"**Mise à jour** : {w.updated_date}")
                if w.name_servers:
                    st.write("**NS** :")
                    for ns in (w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]):
                        st.write(f"- {ns}")
        except Exception as e:
            st.warning(f"WHOIS indisponible : {e}")
        
        st.subheader("🌍 DNS")
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                st.markdown(f"**{rtype}**")
                for r in answers:
                    st.code(str(r))
            except:
                pass
        
        st.subheader("🔎 Sous-domaines (crt.sh)")
        try:
            with st.spinner("Recherche..."):
                r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
                if r.status_code == 200:
                    subs = set()
                    for e in r.json():
                        for line in e.get('name_value', '').split('\n'):
                            line = line.strip().lower()
                            if domain in line:
                                subs.add(line)
                    subs = sorted(subs)
                    st.success(f"{len(subs)} sous-domaines trouvés")
                    cols = st.columns(3)
                    for i, s in enumerate(subs[:90]):
                        cols[i % 3].write(f"`{s}`")
                else:
                    st.warning("crt.sh non disponible")
        except Exception as e:
            st.warning(f"Erreur : {e}")

# ==================== IP ====================
elif page == "🌍 Adresse IP":
    st.markdown('<p class="main-header">🌍 Analyse IP</p>', unsafe_allow_html=True)
    ip = st.text_input("Adresse IP", placeholder="ex: 8.8.8.8")
    
    if st.button("🔍 Analyser", type="primary") and ip:
        ip = ip.strip()
        try:
            socket.inet_aton(ip)
            with st.spinner("Recherche..."):
                r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile", timeout=10)
                data = r.json()
            
            if data.get("status") == "success":
                st.success(f"Résultats pour **{ip}**")
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Pays", f"{data.get('country')} ({data.get('countryCode')})")
                    st.metric("Région", data.get('regionName'))
                    st.metric("Ville", data.get('city'))
                with c2:
                    st.metric("FAI", data.get('isp'))
                    st.metric("Organisation", data.get('org'))
                    st.metric("ASN", data.get('as'))
                with c3:
                    st.metric("Timezone", data.get('timezone'))
                    st.metric("CP", data.get('zip'))
                    st.metric("Coords", f"{data.get('lat')}, {data.get('lon')}")
                
                if data.get("proxy") or data.get("hosting") or data.get("mobile"):
                    st.subheader("Indicateurs")
                    if data.get("proxy"): st.write("🟡 Proxy / VPN détecté")
                    if data.get("hosting"): st.write("🟡 Datacenter / Hébergeur")
                    if data.get("mobile"): st.write("📱 Connexion mobile")
                
                st.markdown(f"""
                **Liens utiles :**
                - [Shodan](https://www.shodan.io/host/{ip})
                - [AbuseIPDB](https://www.abuseipdb.com/check/{ip})
                - [VirusTotal](https://www.virustotal.com/gui/ip-address/{ip})
                """)
            else:
                st.error(data.get("message", "Erreur"))
        except socket.error:
            st.error("IP invalide")
        except Exception as e:
            st.error(str(e))

# ==================== URL ====================
elif page == "🔗 Analyse URL":
    st.markdown('<p class="main-header">🔗 Analyse URL</p>', unsafe_allow_html=True)
    url_input = st.text_input("URL", placeholder="https://example.com")
    
    if st.button("🔍 Analyser", type="primary") and url_input:
        url = url_input.strip()
        if not url.startswith("http"):
            url = "https://" + url
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            with st.spinner("Analyse..."):
                r = requests.get(url, headers=headers, timeout=12, allow_redirects=True)
            
            st.success(f"`{r.url}`")
            c1, c2, c3 = st.columns(3)
            c1.metric("Status", r.status_code)
            c2.metric("Temps", f"{r.elapsed.total_seconds():.2f}s")
            c3.metric("Taille", f"{len(r.content)} o")
            
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, 'html.parser')
                title = soup.title.string if soup.title else "Aucun titre"
                st.write(f"**Titre :** {title}")
            except:
                pass
            
            st.subheader("Headers importants")
            for h in ["Server", "X-Powered-By", "Content-Type", "X-Frame-Options"]:
                if h in r.headers:
                    st.write(f"**{h}** : `{r.headers[h]}`")
            
            st.markdown(f"""
            **Analyse externe :**
            - [URLScan](https://urlscan.io/search/#{url})
            - [VirusTotal](https://www.virustotal.com/gui/url/{quote(url, safe='')})
            - [Wayback Machine](https://web.archive.org/web/*/{url})
            """)
        except Exception as e:
            st.error(str(e))

# ==================== TELEPHONE ====================
elif page == "📱 Numéro de téléphone":
    st.markdown('<p class="main-header">📱 Analyse Numéro de téléphone</p>', unsafe_allow_html=True)
    st.info("Les outils gratuits sont limités. Voici les meilleures pistes légales.")
    
    phone = st.text_input("Numéro de téléphone", placeholder="ex: +33612345678 ou 0612345678")
    
    if st.button("🔍 Générer les recherches", type="primary") and phone:
        phone_clean = phone.strip().replace(" ", "").replace("-", "").replace(".", "")
        
        st.subheader("🔗 Outils recommandés")
        st.markdown(f"""
        | Outil | Lien |
        |-------|------|
        | **Truecaller** | [Rechercher](https://www.truecaller.com/) |
        | **Sync.me** | [Rechercher](https://sync.me/) |
        | **Numverify** | [Site](https://numverify.com/) |
        | **PhoneInfoga** (local) | [GitHub](https://github.com/sundowndev/phoneinfoga) |
        """)
        
        st.subheader("🔎 Google Dorks")
        st.code(f'"{phone_clean}"')
        st.code(f'"{phone}"')
        st.code(f'"{phone_clean}" (facebook OR linkedin OR twitter OR instagram)')
        
        st.subheader("Liens directs")
        st.markdown(f"""
        - [Google](https://www.google.com/search?q={quote(phone_clean)})
        - [Google (avec +)](https://www.google.com/search?q={quote(phone)})
        """)
        
        st.warning("Ne jamais utiliser ces informations pour harceler quelqu'un.")

# ==================== NOM / PRENOM ====================
elif page == "🧑 Nom / Prénom":
    st.markdown('<p class="main-header">🧑 Recherche Nom / Prénom</p>', unsafe_allow_html=True)
    
    c1, c2 = st.columns(2)
    prenom = c1.text_input("Prénom", placeholder="Jean")
    nom = c2.text_input("Nom", placeholder="Dupont")
    ville = st.text_input("Ville (optionnel)", placeholder="Paris")
    
    if st.button("🔍 Générer", type="primary") and (prenom or nom):
        full = f"{prenom} {nom}".strip()
        enc = quote(full)
        enc_full = quote(f"{full} {ville}".strip()) if ville else enc
        
        st.markdown(f"### Recherche : **{full}**" + (f" ({ville})" if ville else ""))
        
        st.subheader("🔎 Google Dorks")
        dorks = [
            f'"{full}"',
            f'"{full}" (linkedin OR twitter OR "x.com" OR facebook OR instagram)',
            f'"{full}" (email OR @gmail OR @hotmail OR @outlook OR @yahoo)',
            f'site:linkedin.com/in "{full}"',
            f'site:facebook.com "{full}"',
            f'site:twitter.com OR site:x.com "{full}"',
            f'"{full}" (CV OR resume OR "curriculum vitae" OR "à propos")',
            f'"{full}" (téléphone OR portable OR "numéro")',
        ]
        if ville:
            dorks.append(f'"{full}" "{ville}"')
            dorks.append(f'"{full}" "{ville}" (linkedin OR facebook)')
        
        for d in dorks:
            st.code(d)
        
        st.subheader("🔗 Liens directs")
        st.markdown(f"""
        - [Google](https://www.google.com/search?q={enc_full})
        - [LinkedIn](https://www.linkedin.com/search/results/all/?keywords={enc})
        - [Twitter / X](https://x.com/search?q={enc}&f=user)
        - [Facebook](https://www.facebook.com/search/people/?q={enc})
        - [Pipl](https://pipl.com/search/?q={enc})
        - [Pages Jaunes](https://www.pagesjaunes.fr/pagesblanches/recherche?quoiqui={enc}&ou={quote(ville) if ville else ''})
        """)

# ==================== HASH ====================
elif page == "🔐 Calculateur Hash":
    st.markdown('<p class="main-header">🔐 Calculateur de Hash</p>', unsafe_allow_html=True)
    texte = st.text_area("Texte à hasher")
    
    if st.button("🔐 Calculer", type="primary") and texte:
        md5 = hashlib.md5(texte.encode()).hexdigest()
        sha1 = hashlib.sha1(texte.encode()).hexdigest()
        sha256 = hashlib.sha256(texte.encode()).hexdigest()
        sha512 = hashlib.sha512(texte.encode()).hexdigest()
        
        st.markdown(f"""
        | Algorithme | Hash |
        |------------|------|
        | **MD5** | `{md5}` |
        | **SHA-1** | `{sha1}` |
        | **SHA-256** | `{sha256}` |
        | **SHA-512** | `{sha512}` |
        """)
        
        st.download_button("📥 Télécharger", 
            f"MD5: {md5}\nSHA1: {sha1}\nSHA256: {sha256}\nSHA512: {sha512}",
            "hashes.txt")

# ==================== FICHIER ====================
elif page == "📁 Analyse de fichier":
    st.markdown('<p class="main-header">📁 Analyse de fichier (Hash)</p>', unsafe_allow_html=True)
    st.write("Calcule les hash d'un fichier (utile pour VirusTotal, etc.)")
    
    uploaded = st.file_uploader("Choisis un fichier", type=None)
    
    if uploaded is not None:
        content = uploaded.read()
        st.write(f"**Fichier :** {uploaded.name} ({len(content)} octets)")
        
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        
        st.markdown(f"""
        | Algorithme | Hash |
        |------------|------|
        | **MD5** | `{md5}` |
        | **SHA-1** | `{sha1}` |
        | **SHA-256** | `{sha256}` |
        """)
        
        st.markdown(f"""
        **Vérifier sur :**
        - [VirusTotal](https://www.virustotal.com/gui/file/{sha256})
        - [Hybrid Analysis](https://www.hybrid-analysis.com/)
        """)

# ==================== DORKS AVANCES ====================
elif page == "🔎 Dorks avancés":
    st.markdown('<p class="main-header">🔎 Générateur de Google Dorks</p>', unsafe_allow_html=True)
    
    mot = st.text_input("Mot-clé principal", placeholder="ex: jean dupont ou example.com")
    site = st.text_input("Site spécifique (optionnel)", placeholder="ex: linkedin.com")
    filetype = st.selectbox("Type de fichier (optionnel)", ["", "pdf", "doc", "docx", "xls", "xlsx", "txt", "csv", "sql", "env", "log"])
    
    if st.button("🔎 Générer les dorks", type="primary") and mot:
        st.subheader("Dorks générés")
        
        dorks = [
            f'"{mot}"',
            f'"{mot}" filetype:pdf',
            f'"{mot}" (email OR @gmail OR @hotmail)',
            f'"{mot}" (password OR motdepasse OR credentials)',
            f'intitle:"{mot}"',
            f'inurl:"{mot}"',
        ]
        
        if site:
            dorks.append(f'site:{site} "{mot}"')
            dorks.append(f'site:{site} "{mot}" filetype:pdf')
        
        if filetype:
            dorks.append(f'"{mot}" filetype:{filetype}')
        
        dorks += [
            f'"{mot}" ext:sql OR ext:env OR ext:log',
            f'"{mot}" "index of"',
            f'"{mot}" confidential OR secret OR private',
        ]
        
        for d in dorks:
            st.code(d)
            st.markdown(f"[🔍 Lancer sur Google](https://www.google.com/search?q={quote(d)})")
            st.markdown("---")

# ==================== OUTILS RECOMMANDES ====================
elif page == "📚 Outils recommandés":
    st.markdown('<p class="main-header">📚 Meilleurs outils OSINT</p>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Username / SOCMINT
    - **Sherlock** → `pip install sherlock-project`
    - **Maigret** → `pip install maigret`
    - **WhatsMyName** → [whatsmyname.app](https://whatsmyname.app)
    
    ### Email
    - **Holehe** → `pip install holehe`
    - **Have I Been Pwned** → [haveibeenpwned.com](https://haveibeenpwned.com)
    - **Epieos** → [epieos.com](https://epieos.com)
    
    ### Domaine / IP
    - **crt.sh** → sous-domaines
    - **Shodan** → [shodan.io](https://shodan.io)
    - **SecurityTrails**
    
    ### Téléphone
    - **PhoneInfoga** → [GitHub](https://github.com/sundowndev/phoneinfoga)
    - Truecaller / Sync.me
    
    ### Tout-en-un
    - **SpiderFoot**
    - **theHarvester**
    """)

st.markdown("---")
st.caption("OSINT Toolkit v2.2 • Usage éducatif et légitime uniquement")
