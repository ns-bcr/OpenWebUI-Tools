"""
title: Gmail
author: Anas
description: >-
  Acces direct a Gmail via OAuth2. Lister, rechercher, lire, rediger,
  envoyer, archiver et supprimer des emails.
  Toute lecture requiert accord prealable. Toute action requiert
  confirmation explicite de l'utilisateur.
required_open_webui_version: 0.4.0
requirements: httpx>=0.27
version: 1.1.1
licence: Attribution-NonCommercial
licence_file: LICENSE
copyright: Copyright (c) 2026 Anas and Ahmed

--- SETUP OAUTH2 ---
1. Google Cloud Console → APIs & Services → Credentials → Create OAuth 2.0 Client ID
   Type : Application Web. URI de redirection : https://developers.google.com/oauthplayground
2. Activer l'API Gmail : APIs & Services → Library → "Gmail API" → Enable
3. OAuth2 Playground (https://developers.google.com/oauthplayground) :
   → Icone engrenage → "Use your own OAuth credentials" → entrer Client ID + Secret
   → Step 1 : scope = https://mail.google.com/ → Authorize APIs
   → Step 2 : Exchange authorization code for tokens → copier le Refresh token
4. Renseigner CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN dans les Valves du Tool.
"""

from __future__ import annotations

import base64
import email as email_lib
import email.mime.text
import email.mime.multipart
import re
import time
from typing import Optional

import httpx
from pydantic import BaseModel, Field


def _plural(n: int, mot: str) -> str:
    """Accord en nombre, sans le "(s)" disgracieux."""
    return f"{n} {mot}" if n <= 1 else f"{n} {mot}s"


GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


class Tools:

    class Valves(BaseModel):
        CLIENT_ID: str = Field(
            default="",
            description="OAuth2 Client ID (Google Cloud Console).",
        )
        CLIENT_SECRET: str = Field(
            default="",
            description="OAuth2 Client Secret.",
        )
        REFRESH_TOKEN: str = Field(
            default="",
            description="Refresh token (scope : https://mail.google.com/).",
        )
        DEFAULT_MAX_RESULTS: int = Field(
            default=10,
            description="Nombre max d'emails retournes par defaut (1-50).",
        )
        REQUEST_TIMEOUT: float = Field(
            default=15.0,
            description="Timeout HTTP en secondes.",
        )

    def __init__(self) -> None:
        self.valves = self.Valves()
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0
        self.citation = False

    # ---------------------------------------------------------------- Auth

    async def _get_token(self) -> str:
        """Retourne un access token valide, en le rafraichissant si necessaire."""
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token

        if not self.valves.CLIENT_ID or not self.valves.REFRESH_TOKEN:
            raise RuntimeError(
                "CLIENT_ID et REFRESH_TOKEN manquants dans les Valves. "
                "Consulter les instructions de setup dans le header du fichier."
            )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.valves.REQUEST_TIMEOUT)
        ) as client:
            resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": self.valves.CLIENT_ID,
                    "client_secret": self.valves.CLIENT_SECRET,
                    "refresh_token": self.valves.REFRESH_TOKEN,
                    "grant_type": "refresh_token",
                },
            )

        if resp.status_code != 200:
            raise RuntimeError(
                f"Echec du rafraichissement du token Gmail "
                f"(HTTP {resp.status_code}) : {resp.text[:300]}"
            )

        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 3600)
        return self._access_token

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ---------------------------------------------------------------- HTTP

    async def _api(
        self,
        method: str,
        path: str,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        token = await self._get_token()
        url = f"{GMAIL_BASE}{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.valves.REQUEST_TIMEOUT)
        ) as client:
            resp = await client.request(
                method,
                url,
                headers=self._headers(token),
                json=json_body,
                params=clean_params,
            )

        if resp.status_code == 204:
            return {}
        if resp.status_code >= 400:
            raise RuntimeError(f"Gmail API HTTP {resp.status_code} : {resp.text[:400]}")
        return resp.json()

    # ---------------------------------------------------------------- Emit

    async def _emit(self, emitter, msg: str, done: bool = False) -> None:
        # [2026-09-28] passed checks - desactive sur demande explicite, meme
        # traitement que recall_tool.py/ultra.py/atc.py le meme jour.
        return

    # ---------------------------------------------------------------- Parsing

    def _b64decode(self, data: str) -> str:
        """Decode une chaine base64url en texte UTF-8."""
        try:
            padded = data + "=" * (4 - len(data) % 4)
            return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _extract_body(self, payload: dict) -> str:
        """
        Extrait le corps texte d'un message Gmail.
        Gere text/plain, text/html, et les structures multipart recursives.
        """
        mime_type = payload.get("mimeType", "")

        # Cas simple : text/plain ou text/html
        if mime_type in ("text/plain", "text/html"):
            raw = payload.get("body", {}).get("data", "")
            if not raw:
                return ""
            text = self._b64decode(raw)
            if mime_type == "text/html":
                text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL)
                text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.DOTALL)
                text = re.sub(r"<[^>]+>", " ", text)
                text = re.sub(r"\s+", " ", text).strip()
            return text

        # Cas multipart : parcourir les parties
        if mime_type.startswith("multipart/"):
            parts = payload.get("parts", [])
            plain_body = ""
            html_body = ""
            for part in parts:
                ptype = part.get("mimeType", "")
                if ptype == "text/plain":
                    plain_body = self._extract_body(part)
                elif ptype == "text/html":
                    html_body = self._extract_body(part)
                elif ptype.startswith("multipart/"):
                    sub = self._extract_body(part)
                    if sub:
                        plain_body = sub
            return plain_body or html_body

        return ""

    def _get_header(self, headers: list, name: str) -> str:
        """Recupere un header par nom (insensible a la casse)."""
        name_lower = name.lower()
        for h in headers:
            if h.get("name", "").lower() == name_lower:
                return h.get("value", "")
        return ""

    def _format_message(self, msg: dict, full_body: bool = False) -> str:
        """Formate un message Gmail en texte lisible pour le LLM."""
        payload = msg.get("payload", {})
        headers = payload.get("headers", [])

        subject = self._get_header(headers, "Subject") or "(sans objet)"
        sender = self._get_header(headers, "From") or "?"
        to = self._get_header(headers, "To") or "?"
        date = self._get_header(headers, "Date") or "?"
        msg_id = msg.get("id", "?")
        thread_id = msg.get("threadId", "?")
        labels = msg.get("labelIds", [])
        is_unread = "UNREAD" in labels
        snippet = msg.get("snippet", "")

        lines = [
            f"{'[NON LU] ' if is_unread else ''}**{subject}**",
            f"  De       : {sender}",
            f"  A        : {to}",
            f"  Date     : {date}",
            f"  ID       : `{msg_id}`",
            f"  Thread   : `{thread_id}`",
        ]

        if full_body:
            body = self._extract_body(payload)
            if body:
                if len(body) > 4000:
                    body = (
                        body[:4000] + "\n\n[... contenu tronque a 4000 caracteres ...]"
                    )
                lines.append(f"\n--- Corps ---\n{body}")
            else:
                lines.append("\n--- Corps : (vide ou non decodable) ---")
        else:
            if snippet:
                lines.append(f"  Apercu   : {snippet[:200]}")

        return "\n".join(lines)

    # ---------------------------------------------------------------- MIME builder

    def _build_raw(
        self,
        to: str,
        subject: str,
        body: str,
        cc: str = "",
        bcc: str = "",
        reply_to_msg_id: str = "",
        thread_id: str = "",
        references: str = "",
    ) -> tuple[str, str]:
        """
        Construit un message MIME et retourne (raw_base64url, thread_id).
        """
        msg = email_lib.mime.text.MIMEText(body, "plain", "utf-8")
        msg["To"] = to
        msg["Subject"] = subject
        if cc:
            msg["Cc"] = cc
        if bcc:
            msg["Bcc"] = bcc
        if reply_to_msg_id:
            msg["In-Reply-To"] = reply_to_msg_id
        if references:
            msg["References"] = references

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        return raw, thread_id

    # ================================================================
    # Methodes exposees au LLM
    # ================================================================

    async def check_auth_status(self, __event_emitter__=None) -> str:
        """
        Verifie que la connexion Gmail est active.
        Utiliser quand l'utilisateur signale un probleme ou veut confirmer
        la connexion avant de lancer une autre action.

        :return: Etat de la connexion avec l'adresse email et le nombre de messages.
        """
        await self._emit(__event_emitter__, "Vérification de la connexion")
        try:
            data = await self._api("GET", "/users/me/profile")
            addr = data.get("emailAddress", "?")
            total = data.get("messagesTotal", "?")
            threads = data.get("threadsTotal", "?")
            msg = f"Gmail connecte — {addr} — {total} messages, {threads} fils."
            await self._emit(__event_emitter__, msg, done=True)
            return msg
        except RuntimeError as exc:
            err = f"Erreur de connexion Gmail : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

    async def get_unread_count(self, __event_emitter__=None) -> str:
        """
        Retourne le nombre d'emails non lus dans la boite de reception.
        Action legere qui ne lit pas le contenu des emails.
        Ne pas appeler sans accord si le contexte est sensible.

        :return: Nombre de messages non lus et total dans INBOX.
        """
        await self._emit(__event_emitter__, "Comptage des non lus")
        try:
            data = await self._api("GET", "/users/me/labels/INBOX")
            unread = data.get("messagesUnread", "?")
            total = data.get("messagesTotal", "?")
            msg = f"INBOX · {_plural(unread, 'non lu')} sur {total}"
            await self._emit(__event_emitter__, msg, done=True)
            return msg
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

    async def list_recent_emails(
        self,
        max_results: int = 0,
        label: str = "INBOX",
        __event_emitter__=None,
    ) -> str:
        """
        Liste les emails recents d'un label Gmail.

        IMPORTANT — lecture de donnees privees.
        Ne pas appeler sans accord explicite de l'utilisateur.
        Toujours demander : "Veux-tu que je consulte ta boite Gmail ?"
        et attendre un 'oui' avant d'appeler.

        :param max_results: Nombre d'emails a retourner (0 = valeur par defaut des Valves).
        :param label: Label Gmail. Valeurs : INBOX (defaut), SENT, DRAFTS,
            SPAM, STARRED, UNREAD, TRASH.
        :return: Liste des emails recents avec expediteur, objet, date, ID.
        """
        n = max_results or self.valves.DEFAULT_MAX_RESULTS
        await self._emit(__event_emitter__, f"Lecture · {label}")

        try:
            data = await self._api(
                "GET",
                "/users/me/messages",
                params={"labelIds": label, "maxResults": min(n, 50)},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        messages = data.get("messages", [])
        if not messages:
            await self._emit(__event_emitter__, "Aucun email", done=True)
            return f"Aucun email dans {label}."

        await self._emit(
            __event_emitter__, f"Chargement · {_plural(len(messages), 'email')}"
        )

        results = []
        token = await self._get_token()
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.valves.REQUEST_TIMEOUT)
        ) as client:
            for m in messages:
                try:
                    resp = await client.get(
                        f"{GMAIL_BASE}/users/me/messages/{m['id']}",
                        headers=self._headers(token),
                        params={
                            "format": "metadata",
                            "metadataHeaders": ["Subject", "From", "To", "Date"],
                        },
                    )
                    if resp.status_code == 200:
                        results.append(self._format_message(resp.json()))
                except Exception:
                    continue

        await self._emit(
            __event_emitter__, f"{_plural(len(results), 'email')}", done=True
        )
        return "\n\n---\n\n".join(results) if results else "Aucun email charge."

    async def search_emails(
        self,
        query: str,
        max_results: int = 0,
        __event_emitter__=None,
    ) -> str:
        """
        Recherche des emails par mots-cles, expediteur, date, etc.
        Utilise la syntaxe de recherche Gmail :
          - from:adresse     → emails d'un expediteur specifique
          - to:adresse       → emails envoyes a cette adresse
          - subject:mot      → emails avec ce mot dans l'objet
          - after:2026/01/01 → emails apres cette date
          - before:2026/06/01→ emails avant cette date
          - is:unread        → emails non lus
          - has:attachment   → emails avec piece jointe
          - label:NomLabel   → emails dans un label specifique

        IMPORTANT — lecture de donnees privees.
        Ne pas appeler sans accord explicite de l'utilisateur.

        :param query: Requete de recherche (syntaxe Gmail standard).
        :param max_results: Nombre max de resultats (0 = defaut Valves).
        :return: Liste des emails correspondants avec ID.
        """
        n = max_results or self.valves.DEFAULT_MAX_RESULTS
        await self._emit(__event_emitter__, f"Recherche · {query}")

        try:
            data = await self._api(
                "GET",
                "/users/me/messages",
                params={"q": query, "maxResults": min(n, 50)},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        messages = data.get("messages", [])
        if not messages:
            await self._emit(__event_emitter__, "Aucun résultat", done=True)
            return f'Aucun email correspondant a : "{query}"'

        await self._emit(
            __event_emitter__, f"{_plural(len(messages), 'résultat')} · chargement"
        )

        results = []
        token = await self._get_token()
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.valves.REQUEST_TIMEOUT)
        ) as client:
            for m in messages:
                try:
                    resp = await client.get(
                        f"{GMAIL_BASE}/users/me/messages/{m['id']}",
                        headers=self._headers(token),
                        params={
                            "format": "metadata",
                            "metadataHeaders": ["Subject", "From", "To", "Date"],
                        },
                    )
                    if resp.status_code == 200:
                        results.append(self._format_message(resp.json()))
                except Exception:
                    continue

        await self._emit(
            __event_emitter__, f"{_plural(len(results), 'email')}", done=True
        )
        return "\n\n---\n\n".join(results) if results else "Aucun email charge."

    async def get_email_content(
        self,
        message_id: str,
        __event_emitter__=None,
    ) -> str:
        """
        Lit le contenu complet d'un email (corps + tous les headers).
        Utiliser quand l'utilisateur veut lire un email specifique
        dont l'ID est connu (via list ou search).

        IMPORTANT — lecture de donnees privees.
        Ne pas appeler sans accord explicite de l'utilisateur.

        :param message_id: ID de l'email (champ 'ID' des resultats list/search).
        :return: Contenu complet de l'email.
        """
        await self._emit(__event_emitter__, "Lecture de l'email")

        try:
            data = await self._api(
                "GET",
                f"/users/me/messages/{message_id}",
                params={"format": "full"},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        result = self._format_message(data, full_body=True)
        await self._emit(__event_emitter__, "Email chargé", done=True)
        return result

    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        cc: str = "",
        bcc: str = "",
        __event_emitter__=None,
    ) -> str:
        """
        Envoie un email depuis la boite Gmail.

        CONFIRMATION OBLIGATOIRE — action irreversible.
        Ne jamais appeler sans avoir presente un resume clair a l'utilisateur :
          - Destinataire (to)
          - Objet (subject)
          - Extrait du corps (body)
        Et obtenu un 'oui' explicite. Utiliser ask_clarification si necessaire.

        :param to: Adresse du destinataire (plusieurs : "a@x.com, b@y.com").
        :param subject: Objet de l'email.
        :param body: Corps de l'email en texte brut.
        :param cc: Adresses en copie (optionnel).
        :param bcc: Adresses en copie cachee (optionnel).
        :return: Confirmation d'envoi avec l'ID du message.
        """
        await self._emit(__event_emitter__, f"Envoi · {to}")

        try:
            raw, _ = self._build_raw(to, subject, body, cc, bcc)
            data = await self._api(
                "POST",
                "/users/me/messages/send",
                json_body={"raw": raw},
            )
        except RuntimeError as exc:
            err = f"Echec de l'envoi : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        msg_id = data.get("id", "?")
        result = f"Email envoye. ID : `{msg_id}`"
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def reply_to_email(
        self,
        message_id: str,
        body: str,
        __event_emitter__=None,
    ) -> str:
        """
        Repond a un email existant en conservant le fil de discussion.

        CONFIRMATION OBLIGATOIRE — action irreversible.
        Presenter le destinataire et un extrait de la reponse,
        attendre 'oui' avant d'appeler.

        :param message_id: ID de l'email auquel repondre.
        :param body: Corps de la reponse en texte brut.
        :return: Confirmation d'envoi.
        """
        await self._emit(__event_emitter__, "Récupération de l'original")

        try:
            orig = await self._api(
                "GET",
                f"/users/me/messages/{message_id}",
                params={
                    "format": "metadata",
                    "metadataHeaders": ["Subject", "From", "Message-ID", "References"],
                },
            )
        except RuntimeError as exc:
            err = f"Impossible de recuperer l'email original : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        payload = orig.get("payload", {})
        headers = payload.get("headers", [])
        thread_id = orig.get("threadId", "")

        orig_from = self._get_header(headers, "From")
        orig_subject = self._get_header(headers, "Subject")
        orig_message_id = self._get_header(headers, "Message-ID")
        orig_references = self._get_header(headers, "References")

        if not orig_subject.lower().startswith("re:"):
            orig_subject = "Re: " + orig_subject

        new_references = (
            f"{orig_references} {orig_message_id}".strip()
            if orig_references
            else orig_message_id
        )

        await self._emit(__event_emitter__, f"Réponse · {orig_from}")

        try:
            raw, tid = self._build_raw(
                to=orig_from,
                subject=orig_subject,
                body=body,
                reply_to_msg_id=orig_message_id,
                thread_id=thread_id,
                references=new_references,
            )
            data = await self._api(
                "POST",
                "/users/me/messages/send",
                json_body={"raw": raw, "threadId": tid},
            )
        except RuntimeError as exc:
            err = f"Echec de l'envoi : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        msg_id = data.get("id", "?")
        result = f"Reponse envoyee a {orig_from}. ID : `{msg_id}`"
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def create_draft(
        self,
        to: str,
        subject: str,
        body: str,
        cc: str = "",
        __event_emitter__=None,
    ) -> str:
        """
        Cree un brouillon Gmail sans l'envoyer.
        Utile pour preparer un email que l'utilisateur finalisera depuis Gmail.
        Ne necessite pas de confirmation — le brouillon ne part pas.

        :param to: Destinataire.
        :param subject: Objet.
        :param body: Corps de l'email en texte brut.
        :param cc: Copie (optionnel).
        :return: Confirmation avec ID du brouillon.
        """
        await self._emit(__event_emitter__, "Création du brouillon")

        try:
            raw, _ = self._build_raw(to, subject, body, cc)
            data = await self._api(
                "POST",
                "/users/me/drafts",
                json_body={"message": {"raw": raw}},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        draft_id = data.get("id", "?")
        result = f"Brouillon cree. ID : `{draft_id}`. Visible dans Gmail > Brouillons."
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def archive_email(
        self,
        message_id: str,
        __event_emitter__=None,
    ) -> str:
        """
        Archive un email : le retire de INBOX sans le supprimer.
        Reste accessible via Tous les messages.

        CONFIRMATION OBLIGATOIRE.
        Indiquer quel email sera archive (objet + expediteur),
        attendre 'oui' avant d'appeler.

        :param message_id: ID de l'email a archiver.
        :return: Confirmation.
        """
        await self._emit(__event_emitter__, "Archivage")

        try:
            await self._api(
                "POST",
                f"/users/me/messages/{message_id}/modify",
                json_body={"removeLabelIds": ["INBOX"]},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        result = f"Email `{message_id}` archive (retire de INBOX)."
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def delete_email(
        self,
        message_id: str,
        __event_emitter__=None,
    ) -> str:
        """
        Deplace un email vers la corbeille (suppression douce).
        L'email reste 30 jours dans la corbeille avant suppression definitive.

        CONFIRMATION OBLIGATOIRE — action quasi-irreversible.
        Indiquer clairement quel email sera supprime (objet + expediteur + date),
        attendre une confirmation explicite de l'utilisateur avant d'appeler.

        :param message_id: ID de l'email a supprimer.
        :return: Confirmation.
        """
        await self._emit(__event_emitter__, "Mise à la corbeille")

        try:
            await self._api(
                "POST",
                f"/users/me/messages/{message_id}/trash",
                json_body={},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        result = f"Email `{message_id}` deplace vers la corbeille."
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def mark_as_read(
        self,
        message_id: str,
        __event_emitter__=None,
    ) -> str:
        """
        Marque un email comme lu (retire le label UNREAD).
        Action legere sans besoin de confirmation.

        :param message_id: ID de l'email.
        :return: Confirmation.
        """
        await self._emit(__event_emitter__, "Marqué comme lu")

        try:
            await self._api(
                "POST",
                f"/users/me/messages/{message_id}/modify",
                json_body={"removeLabelIds": ["UNREAD"]},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        result = f"Email `{message_id}` marque comme lu."
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def mark_as_unread(
        self,
        message_id: str,
        __event_emitter__=None,
    ) -> str:
        """
        Marque un email comme non lu (ajoute le label UNREAD).
        Action legere sans besoin de confirmation.

        :param message_id: ID de l'email.
        :return: Confirmation.
        """
        await self._emit(__event_emitter__, "Marqué comme non lu")

        try:
            await self._api(
                "POST",
                f"/users/me/messages/{message_id}/modify",
                json_body={"addLabelIds": ["UNREAD"]},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        result = f"Email `{message_id}` marque comme non lu."
        await self._emit(__event_emitter__, result, done=True)
        return result

    async def add_label(
        self,
        message_id: str,
        label_name: str,
        __event_emitter__=None,
    ) -> str:
        """
        Ajoute un label existant a un email.
        Le label doit exister dans Gmail (les labels sont casses : sensibles
        a la casse et specifiques au compte).
        Ne necessite pas de confirmation — action reversible.

        :param message_id: ID de l'email.
        :param label_name: Nom exact du label Gmail (ex: "Travail", "Factures").
        :return: Confirmation ou erreur si le label n'existe pas.
        """
        await self._emit(__event_emitter__, f"Label · {label_name}")

        try:
            # Recuperer la liste des labels pour trouver l'ID
            labels_data = await self._api("GET", "/users/me/labels")
            labels = labels_data.get("labels", [])
            label_id = None
            for lbl in labels:
                if lbl.get("name", "").lower() == label_name.lower():
                    label_id = lbl["id"]
                    break

            if not label_id:
                available = [l["name"] for l in labels if l.get("type") == "user"]
                err = (
                    f"Label '{label_name}' introuvable. "
                    f"Labels disponibles : {', '.join(available) or 'aucun'}"
                )
                await self._emit(__event_emitter__, err, done=True)
                return err

            await self._api(
                "POST",
                f"/users/me/messages/{message_id}/modify",
                json_body={"addLabelIds": [label_id]},
            )
        except RuntimeError as exc:
            err = f"Erreur : {exc}"
            await self._emit(__event_emitter__, err, done=True)
            return err

        result = f"Label '{label_name}' ajoute a l'email `{message_id}`."
        await self._emit(__event_emitter__, result, done=True)
        return result
