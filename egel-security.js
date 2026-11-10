/**
 * EGEL 2026 - Sistema de Identificación, Telemetría de Sesiones y Control de Acceso (Zero-DB)
 * Funciona 100% sin base de datos mediante:
 *  1. Memoria + Almacenamiento Local (localStorage / sessionStorage / Cookies)
 *  2. Sincronización multi-pestaña en tiempo real (BroadcastChannel + Storage Events)
 *  3. Archivo estático de configuración (blocklist.json)
 *  4. Canal ligero de estado en tiempo real entre dispositivos (Pub/Sub SSE sin BD)
 */
(function (window, document) {
    "use strict";

    if (window.__EGEL_SECURITY_ACTIVE__) {
        return;
    }
    window.__EGEL_SECURITY_ACTIVE__ = true;

    const STORAGE_KEYS = {
        SESSIONS: "__egel2026_sec_sessions_v1",
        BLOCKLIST: "__egel2026_sec_blocklist_v1",
        AUDIT_LOG: "__egel2026_sec_audit_v1",
        DEVICE_ID: "__egel2026_sec_device_id_v1",
        LOCAL_BAN_FLAG: "__egel2026_sec_device_banned_v1",
        CURRENT_SESSION: "__egel2026_sec_current_session_v1",
        ADMIN_HASH: "__egel2026_sec_admin_hash_v1",
        RELAY_TOPIC: "__egel2026_sec_relay_topic_v3",
        EMERGENCY_UNBLOCK_DONE: "__egel2026_unblock_kaory_22011435_v3"
    };

    const CHANNEL_NAME = "egel2026_security_realtime_bus";
    const DEFAULT_RELAY_TOPIC = "egel2026_sec_sync_kgca_v3";
    const HEARTBEAT_INTERVAL_MS = 4000;
    const INACTIVE_THRESHOLD_MS = 90 * 1000;
    const OFFLINE_THRESHOLD_MS = 18 * 1000;

    const DEFAULT_ADMIN_PASSWORD_PLAIN = "EGEL2026KGCA";

    let broadcastChannel = null;
    try {
        if (typeof BroadcastChannel !== "undefined") {
            broadcastChannel = new BroadcastChannel(CHANNEL_NAME);
        }
    } catch (e) {
        broadcastChannel = null;
    }

    let currentSession = null;
    let cachedIP = "Detectando...";
    let cachedDeviceId = null;
    let isRevokedScreenShown = false;
    let heartbeatTimer = null;
    let blockCheckTimer = null;
    let eventSourceRelay = null;
    let lastActivityTimestamp = Date.now();

    /**
     * Detecta si estamos en el Panel Administrativo (admin.html).
     * El panel administrativo JAMÁS debe ser bloqueado por reglas de usuarios/dispositivos.
     */
    function isAdminPanelContext() {
        try {
            if (window.__EGEL_IS_ADMIN_PANEL__ === true) return true;
            if (document.getElementById("admin-login-screen") || document.getElementById("admin-dashboard-screen")) {
                return true;
            }
            const path = String(window.location.pathname || window.location.href || "").toLowerCase();
            if (path.includes("admin.html")) return true;
        } catch (e) {}
        return false;
    }

    /* ==========================================================================
       1. UTILIDADES DE CRIPTOGRAFÍA Y HUELLA DE DISPOSITIVO (FINGERPRINTING)
       ========================================================================== */

    function normalizeStr(val) {
        return String(val || "").trim().toLowerCase();
    }

    function normalizeFirstName(val) {
        const clean = String(val || "").trim().replace(/\s+/g, " ");
        return clean.toLowerCase();
    }

    function extractPrimaryFirstName(val) {
        const clean = String(val || "").trim().replace(/\s+/g, " ");
        return clean.split(" ")[0].toLowerCase();
    }

    async function sha256Hex(text) {
        try {
            if (window.crypto && window.crypto.subtle) {
                const buf = new TextEncoder().encode(String(text));
                const hashBuffer = await window.crypto.subtle.digest("SHA-256", buf);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
            }
        } catch (e) {}
        let h1 = 0xdeadbeef ^ text.length;
        let h2 = 0x41c6ce57 ^ text.length;
        for (let i = 0, ch; i < text.length; i++) {
            ch = text.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
        return (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0");
    }

    function computeHardwareFingerprint() {
        try {
            const nav = window.navigator || {};
            const scr = window.screen || {};
            const tz = Intl && Intl.DateTimeFormat ? Intl.DateTimeFormat().resolvedOptions().timeZone : "";
            let canvasHash = "";
            try {
                const canvas = document.createElement("canvas");
                const ctx = canvas.getContext("2d");
                if (ctx) {
                    ctx.textBaseline = "top";
                    ctx.font = "14px Arial";
                    ctx.fillStyle = "#4CAF50";
                    ctx.fillRect(10, 1, 62, 20);
                    ctx.fillStyle = "#069";
                    ctx.fillText("EGEL2026-FP", 2, 15);
                    canvasHash = canvas.toDataURL().slice(-48);
                }
            } catch (e) {}

            const raw = [
                nav.userAgent || "",
                nav.language || "",
                nav.platform || "",
                nav.hardwareConcurrency || "",
                nav.deviceMemory || "",
                scr.width + "x" + scr.height + "x" + (scr.colorDepth || ""),
                tz,
                canvasHash
            ].join("|");

            let hash = 2166136261;
            for (let i = 0; i < raw.length; i++) {
                hash ^= raw.charCodeAt(i);
                hash = Math.imul(hash, 16777619);
            }
            const hex = (hash >>> 0).toString(16).toUpperCase().padStart(8, "0");
            return "DEV-" + hex.slice(0, 4) + "-" + hex.slice(4, 8);
        } catch (e) {
            return "DEV-GEN-" + Math.random().toString(36).substring(2, 6).toUpperCase();
        }
    }

    function getOrCreateDeviceId() {
        if (cachedDeviceId) return cachedDeviceId;
        const hwFp = computeHardwareFingerprint();
        try {
            const stored = localStorage.getItem(STORAGE_KEYS.DEVICE_ID);
            if (stored && stored.startsWith("DEV-")) {
                cachedDeviceId = stored;
                return cachedDeviceId;
            }
            localStorage.setItem(STORAGE_KEYS.DEVICE_ID, hwFp);
        } catch (e) {}
        try {
            document.cookie = `${STORAGE_KEYS.DEVICE_ID}=${hwFp}; path=/; max-age=31536000; SameSite=Lax`;
        } catch (e) {}
        cachedDeviceId = hwFp;
        return cachedDeviceId;
    }

    function generateSessionToken() {
        const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
        const ts = Date.now().toString(36).slice(-4).toUpperCase();
        return "TOK-" + ts + "-" + rand;
    }

    function parseUserAgentSummary(ua) {
        const s = String(ua || navigator.userAgent || "");
        let os = "SO Desconocido";
        if (/Windows NT 10|Windows NT 11/i.test(s)) os = "Windows 10/11";
        else if (/Windows/i.test(s)) os = "Windows";
        else if (/Android/i.test(s)) os = "Android";
        else if (/iPhone|iPad|iPod/i.test(s)) os = "iOS / iPadOS";
        else if (/Mac OS X|Macintosh/i.test(s)) os = "macOS";
        else if (/Linux/i.test(s)) os = "Linux";

        let browser = "Navegador";
        if (/Edg\//i.test(s)) browser = "Edge";
        else if (/OPR\/|Opera/i.test(s)) browser = "Opera";
        else if (/Chrome\//i.test(s)) browser = "Chrome";
        else if (/Firefox\//i.test(s)) browser = "Firefox";
        else if (/Safari\//i.test(s) && !/Chrome\//i.test(s)) browser = "Safari";

        return `${browser} en ${os}`;
    }

    async function detectPublicIP() {
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 3500);
            const res = await fetch("https://api.ipify.org?format=json", {
                signal: controller.signal,
                cache: "no-store"
            });
            clearTimeout(timeout);
            if (res.ok) {
                const data = await res.json();
                if (data && data.ip) {
                    cachedIP = data.ip;
                    if (currentSession) {
                        currentSession.ip = cachedIP;
                        saveAndBroadcastSession(currentSession);
                    }
                    return cachedIP;
                }
            }
        } catch (e) {}
        if (cachedIP === "Detectando...") {
            cachedIP = "Local / Red Privada";
            if (currentSession) {
                currentSession.ip = cachedIP;
            }
        }
        return cachedIP;
    }

    /* ==========================================================================
       2. GESTIÓN DE ALMACENAMIENTO LOCAL, BLOCKLIST Y EVENTOS
       ========================================================================== */

    function getEmptyBlocklist() {
        return {
            version: "1.0.0",
            updatedAt: "1970-01-01T00:00:00.000Z",
            blockedNames: [],
            blockedEmails: [],
            blockedDevices: [],
            blockedTokens: [],
            blockedIPs: [],
            rules: []
        };
    }

    function getBlocklist() {
        try {
            const raw = localStorage.getItem(STORAGE_KEYS.BLOCKLIST);
            if (!raw) return getEmptyBlocklist();
            const parsed = JSON.parse(raw);
            return {
                version: parsed.version || "1.0.0",
                updatedAt: parsed.updatedAt || "1970-01-01T00:00:00.000Z",
                blockedNames: Array.isArray(parsed.blockedNames) ? parsed.blockedNames : [],
                blockedEmails: Array.isArray(parsed.blockedEmails) ? parsed.blockedEmails : [],
                blockedDevices: Array.isArray(parsed.blockedDevices) ? parsed.blockedDevices : [],
                blockedTokens: Array.isArray(parsed.blockedTokens) ? parsed.blockedTokens : [],
                blockedIPs: Array.isArray(parsed.blockedIPs) ? parsed.blockedIPs : [],
                rules: Array.isArray(parsed.rules) ? parsed.rules : []
            };
        } catch (e) {
            return getEmptyBlocklist();
        }
    }

    function saveBlocklist(bl, shouldBroadcast = true) {
        if (shouldBroadcast || !bl.updatedAt) {
            bl.updatedAt = new Date().toISOString();
        }
        try {
            localStorage.setItem(STORAGE_KEYS.BLOCKLIST, JSON.stringify(bl));
        } catch (e) {}
        if (shouldBroadcast) {
            broadcastMessage({
                type: "BLOCKLIST_UPDATED",
                blocklist: bl,
                timestamp: Date.now()
            });
            publishToRemoteRelay({
                type: "BLOCKLIST_UPDATED",
                blocklist: bl,
                timestamp: Date.now()
            });
        }
    }

    /**
     * Desbloqueo automático de rescate para la cuenta de la creadora (KAORY / 22011435@itsoeh.edu.mx)
     * y su dispositivo actual.
     */
    function runCreatorAccountRescue() {
        try {
            localStorage.removeItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
            const myDev = getOrCreateDeviceId();
            const hwFp = computeHardwareFingerprint();
            const bl = getBlocklist();

            // Limpiar siempre la IP 187.251.205.109 que quedó bloqueada por error en la prueba anterior
            const hadStaleCreatorBlock =
                bl.blockedIPs.some(ip => normalizeStr(ip) === "187.251.205.109") ||
                !localStorage.getItem(STORAGE_KEYS.EMERGENCY_UNBLOCK_DONE);

            if (hadStaleCreatorBlock) {
                bl.blockedNames = bl.blockedNames.filter(n => normalizeStr(n) !== "kaory");
                bl.blockedEmails = bl.blockedEmails.filter(e => normalizeStr(e) !== "22011435@itsoeh.edu.mx");
                bl.blockedDevices = bl.blockedDevices.filter(
                    d =>
                        normalizeStr(d) !== normalizeStr(myDev) &&
                        normalizeStr(d) !== normalizeStr(hwFp) &&
                        normalizeStr(d) !== "dev-e3ca-e056"
                );
                bl.blockedTokens = [];
                bl.blockedIPs = [];
                bl.rules = bl.rules.filter(r => {
                    if (r.firstName && normalizeStr(r.firstName) === "kaory") return false;
                    if (r.email && normalizeStr(r.email) === "22011435@itsoeh.edu.mx") return false;
                    if (r.ip && normalizeStr(r.ip) === "187.251.205.109") return false;
                    if (
                        r.deviceId &&
                        (normalizeStr(r.deviceId) === normalizeStr(myDev) ||
                            normalizeStr(r.deviceId) === normalizeStr(hwFp) ||
                            normalizeStr(r.deviceId) === "dev-e3ca-e056")
                    ) {
                        return false;
                    }
                    return true;
                });

                const map = getSessionsMap();
                Object.values(map).forEach(s => {
                    if (
                        normalizeStr(s.firstName) === "kaory" ||
                        normalizeStr(s.email) === "22011435@itsoeh.edu.mx" ||
                        normalizeStr(s.deviceId) === normalizeStr(myDev) ||
                        normalizeStr(s.deviceId) === "dev-e3ca-e056" ||
                        normalizeStr(s.ip) === "187.251.205.109"
                    ) {
                        s.status = "Inactiva";
                    }
                });
                saveSessionsMap(map);
                saveBlocklist(bl, false);
                localStorage.setItem(STORAGE_KEYS.EMERGENCY_UNBLOCK_DONE, "1");
            }
        } catch (e) {}
    }

    async function syncStaticBlocklistFile() {
        try {
            const res = await fetch("blocklist.json?t=" + Date.now(), { cache: "no-store" });
            if (!res.ok) return;
            const fileBl = await res.json();
            if (!fileBl || typeof fileBl !== "object") return;
            mergeIncomingBlocklist(fileBl, false);
        } catch (e) {}
    }

    function mergeIncomingBlocklist(incoming, replaceAll = false) {
        if (!incoming || typeof incoming !== "object") return getBlocklist();
        if (replaceAll) {
            saveBlocklist(incoming, false);
            return incoming;
        }
        const current = getBlocklist();
        const addUnique = (arr, items) => {
            if (!Array.isArray(items)) return arr;
            items.forEach(item => {
                const norm = String(item || "").trim();
                if (norm && !arr.includes(norm)) arr.push(norm);
            });
            return arr;
        };
        addUnique(current.blockedNames, incoming.blockedNames);
        addUnique(current.blockedEmails, incoming.blockedEmails);
        addUnique(current.blockedDevices, incoming.blockedDevices);
        addUnique(current.blockedTokens, incoming.blockedTokens);
        addUnique(current.blockedIPs, incoming.blockedIPs);

        if (Array.isArray(incoming.rules)) {
            const existingIds = new Set(current.rules.map(r => r.id));
            incoming.rules.forEach(r => {
                if (r && r.id && !existingIds.has(r.id)) {
                    current.rules.unshift(r);
                    existingIds.add(r.id);
                }
            });
        }
        saveBlocklist(current, false);
        return current;
    }

    function getSessionsMap() {
        try {
            const raw = localStorage.getItem(STORAGE_KEYS.SESSIONS);
            if (!raw) return {};
            const parsed = JSON.parse(raw);
            return parsed && typeof parsed === "object" ? parsed : {};
        } catch (e) {
            return {};
        }
    }

    function saveSessionsMap(map) {
        try {
            localStorage.setItem(STORAGE_KEYS.SESSIONS, JSON.stringify(map));
        } catch (e) {}
    }

    function getAuditLogs() {
        try {
            const raw = localStorage.getItem(STORAGE_KEYS.AUDIT_LOG);
            if (!raw) return [];
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed : [];
        } catch (e) {
            return [];
        }
    }

    function appendAuditLog(eventObj, shouldBroadcast = true) {
        const logs = getAuditLogs();
        const entry = {
            id: "EVT-" + Date.now() + "-" + Math.random().toString(36).substring(2, 6),
            timestamp: new Date().toISOString(),
            ...eventObj
        };
        logs.unshift(entry);
        if (logs.length > 250) logs.length = 250;
        try {
            localStorage.setItem(STORAGE_KEYS.AUDIT_LOG, JSON.stringify(logs));
        } catch (e) {}
        if (shouldBroadcast) {
            broadcastMessage({ type: "AUDIT_ENTRY", entry });
            publishToRemoteRelay({ type: "AUDIT_ENTRY", entry });
        }
        return entry;
    }

    /* ==========================================================================
       3. VERIFICACIÓN DE BLOQUEO Y REVOCACIÓN INMEDIATA
       ========================================================================== */

    function checkIsBlocked(params = {}) {
        const bl = getBlocklist();
        const deviceId = params.deviceId || getOrCreateDeviceId();
        const hwFp = computeHardwareFingerprint();
        const firstName = normalizeFirstName(params.firstName || "");
        const primaryName = extractPrimaryFirstName(params.firstName || "");
        const email = normalizeStr(params.email || "");
        const sessionToken = String(params.sessionToken || "").trim();
        const ip = String(params.ip || cachedIP || "").trim();

        // 1. Verificar bloqueo por Dispositivo (Device ID / Hardware FP)
        const blockedDevicesNorm = bl.blockedDevices.map(normalizeStr);
        if (
            (deviceId && blockedDevicesNorm.includes(normalizeStr(deviceId))) ||
            (hwFp && blockedDevicesNorm.includes(normalizeStr(hwFp)))
        ) {
            markLocalDeviceBanned({ deviceId, matchedBy: "Dispositivo", matchedValue: deviceId });
            return {
                blocked: true,
                matchedBy: "Dispositivo",
                matchedValue: deviceId,
                reason: `Este dispositivo (${deviceId}) tiene el acceso revocado permanentemente.`
            };
        }

        // Verificar bandera persistente local de baneo de dispositivo
        try {
            const localBan = localStorage.getItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
            if (localBan) {
                const banData = JSON.parse(localBan);
                const stillInRules =
                    blockedDevicesNorm.includes(normalizeStr(banData.deviceId || deviceId)) ||
                    bl.blockedTokens.map(normalizeStr).includes(normalizeStr(banData.sessionToken || "")) ||
                    bl.blockedNames.map(normalizeStr).includes(normalizeStr(banData.firstName || "")) ||
                    bl.blockedEmails.map(normalizeStr).includes(normalizeStr(banData.email || ""));
                if (stillInRules) {
                    return {
                        blocked: true,
                        matchedBy: banData.matchedBy || "Dispositivo / Sesión",
                        matchedValue: banData.matchedValue || deviceId,
                        reason: banData.reason || "Tu acceso fue revocado por el administrador."
                    };
                } else {
                    localStorage.removeItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
                }
            }
        } catch (e) {}

        // 2. Verificar bloqueo por Token de Sesión
        if (sessionToken) {
            const blockedTokensNorm = bl.blockedTokens.map(normalizeStr);
            if (blockedTokensNorm.includes(normalizeStr(sessionToken))) {
                return {
                    blocked: true,
                    matchedBy: "Token de Sesión",
                    matchedValue: sessionToken,
                    reason: `La sesión actual (${sessionToken}) fue revocada por el administrador.`
                };
            }
        }

        // 3. Verificar bloqueo por Correo Electrónico
        if (email) {
            const blockedEmailsNorm = bl.blockedEmails.map(normalizeStr);
            if (blockedEmailsNorm.includes(email)) {
                return {
                    blocked: true,
                    matchedBy: "Correo Electrónico",
                    matchedValue: params.email,
                    reason: `El correo electrónico "${params.email}" tiene el acceso bloqueado.`
                };
            }
        }

        // 4. Verificar bloqueo por Primer Nombre / Usuario
        if (firstName || primaryName) {
            const blockedNamesNorm = bl.blockedNames.map(normalizeStr);
            if (
                (firstName && blockedNamesNorm.includes(firstName)) ||
                (primaryName && blockedNamesNorm.includes(primaryName))
            ) {
                return {
                    blocked: true,
                    matchedBy: "Primer Nombre / Usuario",
                    matchedValue: params.firstName,
                    reason: `El usuario "${params.firstName}" no tiene autorizado el acceso al simulador.`
                };
            }
        }

        // 5. Verificar bloqueo por IP
        if (ip && ip !== "Detectando..." && ip !== "Local / Red Privada") {
            const blockedIPsNorm = bl.blockedIPs.map(normalizeStr);
            if (blockedIPsNorm.includes(normalizeStr(ip))) {
                return {
                    blocked: true,
                    matchedBy: "Dirección IP",
                    matchedValue: ip,
                    reason: `La dirección IP (${ip}) ha sido bloqueada por seguridad.`
                };
            }
        }

        return { blocked: false };
    }

    function markLocalDeviceBanned(info = {}) {
        if (isAdminPanelContext()) return;
        try {
            localStorage.setItem(
                STORAGE_KEYS.LOCAL_BAN_FLAG,
                JSON.stringify({
                    deviceId: getOrCreateDeviceId(),
                    firstName: currentSession ? currentSession.firstName : info.firstName || "",
                    email: currentSession ? currentSession.email : info.email || "",
                    sessionToken: currentSession ? currentSession.sessionToken : info.sessionToken || "",
                    matchedBy: info.matchedBy || "Administrador",
                    matchedValue: info.matchedValue || getOrCreateDeviceId(),
                    reason: info.reason || "Acceso revocado por el administrador del sistema.",
                    bannedAt: new Date().toISOString()
                })
            );
        } catch (e) {}
    }

    function clearStatiCryptCredentials() {
        try {
            localStorage.removeItem("staticrypt_passphrase");
            localStorage.removeItem("staticrypt_expiration");
            sessionStorage.removeItem(STORAGE_KEYS.CURRENT_SESSION);
        } catch (e) {}
    }

    /**
     * Cierra inmediatamente la sesión activa del simulador y reemplaza la pantalla con el aviso de bloqueo.
     * JAMÁS bloquea admin.html.
     */
    function enforceImmediateRevocation(blockResult) {
        if (isAdminPanelContext()) return;
        if (isRevokedScreenShown) return;
        isRevokedScreenShown = true;

        clearStatiCryptCredentials();
        markLocalDeviceBanned(blockResult);

        if (currentSession) {
            currentSession.status = "Bloqueada";
            currentSession.lastActivity = new Date().toISOString();
            currentSession.revokedReason = blockResult.reason || "Acceso revocado";
            saveAndBroadcastSession(currentSession);
        }

        if (heartbeatTimer) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = null;
        }

        const matchedBy = blockResult.matchedBy || "Política de Seguridad";
        const matchedValue = blockResult.matchedValue || getOrCreateDeviceId();
        const reason = blockResult.reason || "Tu acceso al Simulador EGEL ha sido revocado por el administrador.";
        const devId = getOrCreateDeviceId();

        try {
            document.title = "Acceso Revocado - Simulador EGEL";
            document.documentElement.innerHTML = `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Acceso Bloqueado / Revocado</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(circle at top, #1f2937 0%, #0f172a 100%);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            color: #f8fafc;
            padding: 24px;
        }
        .revoke-card {
            background: #1e293b;
            border: 1px solid rgba(239, 68, 68, 0.45);
            border-top: 5px solid #ef4444;
            border-radius: 14px;
            max-width: 480px;
            width: 100%;
            padding: 36px 32px;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.65);
        }
        .revoke-icon {
            width: 68px;
            height: 68px;
            border-radius: 50%;
            background: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 34px;
            margin: 0 auto 20px;
            border: 1px solid rgba(239, 68, 68, 0.35);
        }
        h1 {
            font-size: 22px;
            font-weight: 700;
            color: #fef2f2;
            margin-bottom: 12px;
        }
        p.reason {
            font-size: 14.5px;
            line-height: 1.55;
            color: #cbd5e1;
            margin-bottom: 22px;
        }
        .meta-box {
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 8px;
            padding: 14px;
            text-align: left;
            font-size: 12.5px;
            color: #94a3b8;
            margin-bottom: 22px;
        }
        .meta-row {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            border-bottom: 1px dashed rgba(148, 163, 184, 0.12);
        }
        .meta-row:last-child { border-bottom: 0; }
        .meta-row strong { color: #e2e8f0; font-family: monospace; }
        .retry-btn {
            background: #334155;
            color: #e2e8f0;
            border: 1px solid #475569;
            padding: 11px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: background 0.2s;
        }
        .retry-btn:hover { background: #475569; }
    </style>
</head>
<body>
    <div class="revoke-card">
        <div class="revoke-icon">&#128683;</div>
        <h1>Acceso Bloqueado / Revocado</h1>
        <p class="reason">${escapeHtml(reason)}</p>
        <div class="meta-box">
            <div class="meta-row"><span>Criterio de bloqueo:</span> <strong>${escapeHtml(matchedBy)}</strong></div>
            <div class="meta-row"><span>Identificador bloqueado:</span> <strong>${escapeHtml(matchedValue)}</strong></div>
            <div class="meta-row"><span>ID de Dispositivo:</span> <strong>${escapeHtml(devId)}</strong></div>
            <div class="meta-row"><span>Hora de revocación:</span> <strong>${new Date().toLocaleTimeString()}</strong></div>
        </div>
        <button class="retry-btn" onclick="window.location.reload()">Verificar estado de acceso</button>
        <div style="margin-top: 14px;">
            <button type="button" onclick="(function(){var p=prompt('Clave de Administrador para desbloquear este dispositivo:');if(p==='EGEL2026KGCA'){localStorage.removeItem('__egel2026_sec_device_banned_v1');localStorage.removeItem('__egel2026_sec_blocklist_v1');window.location.reload();}else if(p!==null){alert('Clave incorrecta');}})()" style="background:transparent;border:none;color:#64748b;font-size:11.5px;cursor:pointer;text-decoration:underline;">
                &#128273; Desbloqueo de Administrador
            </button>
        </div>
    </div>
</body>
</html>`;
        } catch (e) {}
    }

    function escapeHtml(str) {
        return String(str || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    /* ==========================================================================
       4. COMUNICACIÓN EN TIEMPO REAL (LOCAL + RELAY PUBSUB LIGERO SIN BD)
       ========================================================================== */

    function getRelayTopic() {
        try {
            return localStorage.getItem(STORAGE_KEYS.RELAY_TOPIC) || DEFAULT_RELAY_TOPIC;
        } catch (e) {
            return DEFAULT_RELAY_TOPIC;
        }
    }

    function broadcastMessage(payload) {
        try {
            if (broadcastChannel) {
                broadcastChannel.postMessage(payload);
            }
        } catch (e) {}
    }

    async function publishToRemoteRelay(payload) {
        try {
            const topic = getRelayTopic();
            fetch(`https://ntfy.sh/${encodeURIComponent(topic)}`, {
                method: "POST",
                body: JSON.stringify(payload),
                headers: {
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Title": "EGEL2026-SEC",
                    "Priority": "default"
                },
                mode: "cors"
            }).catch(() => {});
        } catch (e) {}
    }

    function subscribeToRemoteRelay(onMessageCallback) {
        try {
            if (typeof EventSource === "undefined") return;
            if (eventSourceRelay) {
                try { eventSourceRelay.close(); } catch (e) {}
            }
            const topic = getRelayTopic();
            const url = `https://ntfy.sh/${encodeURIComponent(topic)}/sse?since=2h`;
            const es = new EventSource(url);
            eventSourceRelay = es;
            es.onmessage = function (ev) {
                try {
                    const outer = JSON.parse(ev.data);
                    if (!outer || !outer.message) return;
                    const data = JSON.parse(outer.message);
                    if (data && typeof data === "object") {
                        handleIncomingRealtimeEvent(data);
                        if (typeof onMessageCallback === "function") {
                            onMessageCallback(data);
                        }
                    }
                } catch (err) {}
            };
            es.onerror = function () {};
        } catch (e) {}
    }

    function handleIncomingRealtimeEvent(data) {
        if (!data || !data.type) return;

        if (data.type === "SESSION_UPSERT" && data.session) {
            const map = getSessionsMap();
            const existing = map[data.session.sessionId];
            if (!existing || new Date(data.session.lastHeartbeat || 0) >= new Date(existing.lastHeartbeat || 0)) {
                map[data.session.sessionId] = data.session;
                saveSessionsMap(map);
            }
        } else if (data.type === "BLOCKLIST_UPDATED" && data.blocklist) {
            const currentBl = getBlocklist();
            if (!currentBl.updatedAt || new Date(data.blocklist.updatedAt || 0) >= new Date(currentBl.updatedAt || 0)) {
                saveBlocklist(data.blocklist, false);
            }
            if (!isAdminPanelContext()) {
                const checkRes = checkAndEnforceCurrentSessionBlock();
                if (!checkRes.blocked && isRevokedScreenShown) {
                    try {
                        localStorage.removeItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
                    } catch (e) {}
                    window.location.reload();
                }
            }
        } else if (data.type === "UNBLOCK_COMMAND" && data.blocklist) {
            saveBlocklist(data.blocklist, false);
            try {
                localStorage.removeItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
            } catch (e) {}
            if (!isAdminPanelContext()) {
                const checkRes = checkAndEnforceCurrentSessionBlock();
                if (!checkRes.blocked && isRevokedScreenShown) {
                    window.location.reload();
                }
            }
        } else if (data.type === "REVOKE_COMMAND") {
            const currentBl = getBlocklist();
            const isNewerOrEqual =
                !data.blocklist ||
                !currentBl.updatedAt ||
                new Date(data.blocklist.updatedAt || 0) >= new Date(currentBl.updatedAt || 0);

            if (data.blocklist && isNewerOrEqual) {
                saveBlocklist(data.blocklist, false);
            }
            if (isAdminPanelContext() || !isNewerOrEqual) {
                return;
            }
            if (currentSession) {
                const targetMatch =
                    (data.sessionId && data.sessionId === currentSession.sessionId) ||
                    (data.sessionToken && normalizeStr(data.sessionToken) === normalizeStr(currentSession.sessionToken)) ||
                    (data.deviceId && normalizeStr(data.deviceId) === normalizeStr(currentSession.deviceId)) ||
                    (data.email && normalizeStr(data.email) === normalizeStr(currentSession.email)) ||
                    (data.firstName && (
                        normalizeFirstName(data.firstName) === normalizeFirstName(currentSession.firstName) ||
                        extractPrimaryFirstName(data.firstName) === extractPrimaryFirstName(currentSession.firstName)
                    ));
                if (targetMatch) {
                    enforceImmediateRevocation({
                        blocked: true,
                        matchedBy: data.matchedBy || "Revocación Directa del Administrador",
                        matchedValue: data.matchedValue || currentSession.firstName,
                        reason: data.reason || "Tu sesión ha sido cerrada y bloqueada por el administrador."
                    });
                    return;
                }
            }
            checkAndEnforceCurrentSessionBlock();
        } else if (data.type === "AUDIT_ENTRY" && data.entry) {
            const logs = getAuditLogs();
            if (!logs.some(l => l.id === data.entry.id)) {
                logs.unshift(data.entry);
                if (logs.length > 250) logs.length = 250;
                try {
                    localStorage.setItem(STORAGE_KEYS.AUDIT_LOG, JSON.stringify(logs));
                } catch (e) {}
            }
        } else if (data.type === "ADMIN_PING_SESSIONS") {
            if (!isAdminPanelContext() && currentSession && !isRevokedScreenShown) {
                saveAndBroadcastSession(currentSession, true);
            }
        }
    }

    if (broadcastChannel) {
        broadcastChannel.onmessage = function (ev) {
            if (ev && ev.data) {
                handleIncomingRealtimeEvent(ev.data);
                window.dispatchEvent(new CustomEvent("egel:security-update", { detail: ev.data }));
            }
        };
    }

    window.addEventListener("storage", function (ev) {
        if (!ev.key) return;
        if (ev.key === STORAGE_KEYS.BLOCKLIST || ev.key === STORAGE_KEYS.LOCAL_BAN_FLAG) {
            if (!isAdminPanelContext()) {
                const checkRes = checkAndEnforceCurrentSessionBlock();
                if (!checkRes.blocked && isRevokedScreenShown) {
                    try {
                        localStorage.removeItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
                    } catch (e) {}
                    window.location.reload();
                }
            }
            window.dispatchEvent(new CustomEvent("egel:security-update", { detail: { type: "STORAGE_BLOCKLIST" } }));
        } else if (ev.key === STORAGE_KEYS.SESSIONS || ev.key === STORAGE_KEYS.AUDIT_LOG) {
            window.dispatchEvent(new CustomEvent("egel:security-update", { detail: { type: "STORAGE_SESSIONS" } }));
        }
    });

    /* ==========================================================================
       5. REGISTRO Y LATIDO (HEARTBEAT) DE SESIONES DE USUARIO
       ========================================================================== */

    function saveAndBroadcastSession(sessionObj, publishRemote = false) {
        if (!sessionObj || !sessionObj.sessionId) return;
        sessionObj.lastHeartbeat = new Date().toISOString();
        const map = getSessionsMap();
        map[sessionObj.sessionId] = sessionObj;
        saveSessionsMap(map);

        try {
            sessionStorage.setItem(STORAGE_KEYS.CURRENT_SESSION, JSON.stringify(sessionObj));
        } catch (e) {}

        const payload = {
            type: "SESSION_UPSERT",
            session: sessionObj,
            timestamp: Date.now()
        };
        broadcastMessage(payload);
        if (publishRemote) {
            publishToRemoteRelay(payload);
        }
    }

    function checkAndEnforceCurrentSessionBlock() {
        if (isAdminPanelContext()) {
            return { blocked: false };
        }

        const checkParams = currentSession
            ? {
                  firstName: currentSession.firstName,
                  email: currentSession.email,
                  deviceId: currentSession.deviceId,
                  sessionToken: currentSession.sessionToken,
                  ip: currentSession.ip
              }
            : {
                  deviceId: getOrCreateDeviceId(),
                  ip: cachedIP
              };

        const res = checkIsBlocked(checkParams);
        if (res.blocked) {
            enforceImmediateRevocation(res);
            return res;
        }
        return { blocked: false };
    }

    function registerIdentifiedUser(firstNameInput, emailInput) {
        const firstName = String(firstNameInput || "").trim().replace(/\s+/g, " ");
        const email = String(emailInput || "").trim().toLowerCase();
        const deviceId = getOrCreateDeviceId();

        const blockCheck = checkIsBlocked({
            firstName,
            email,
            deviceId,
            ip: cachedIP
        });

        if (blockCheck.blocked) {
            appendAuditLog({
                action: "BLOCKED_LOGIN_ATTEMPT",
                firstName,
                email,
                deviceId,
                ip: cachedIP,
                matchedBy: blockCheck.matchedBy,
                reason: blockCheck.reason
            });
            return {
                allowed: false,
                blockResult: blockCheck
            };
        }

        let existing = null;
        try {
            const raw = sessionStorage.getItem(STORAGE_KEYS.CURRENT_SESSION);
            if (raw) existing = JSON.parse(raw);
        } catch (e) {}

        const nowIso = new Date().toISOString();
        const sessionToken = existing && existing.sessionToken ? existing.sessionToken : generateSessionToken();
        const sessionId = existing && existing.sessionId ? existing.sessionId : `SES-${deviceId}-${sessionToken}`;

        currentSession = {
            sessionId,
            sessionToken,
            firstName,
            email,
            deviceId,
            ip: cachedIP,
            userAgent: navigator.userAgent || "",
            deviceSummary: parseUserAgentSummary(navigator.userAgent),
            loginTime: existing && existing.loginTime ? existing.loginTime : nowIso,
            lastActivity: nowIso,
            lastHeartbeat: nowIso,
            status: "Autenticando (Contraseña)",
            stage: "PASSWORD_STEP",
            failedPasswordAttempts: existing ? (existing.failedPasswordAttempts || 0) : 0
        };

        saveAndBroadcastSession(currentSession, true);
        appendAuditLog({
            action: "USER_IDENTIFIED_STEP1",
            firstName,
            email,
            deviceId,
            sessionToken,
            ip: cachedIP
        }, false);

        startSessionMonitoring(false);
        return {
            allowed: true,
            session: currentSession
        };
    }

    function recordPasswordAttempt(isSuccess) {
        if (!currentSession) {
            try {
                const raw = sessionStorage.getItem(STORAGE_KEYS.CURRENT_SESSION);
                if (raw) currentSession = JSON.parse(raw);
            } catch (e) {}
        }
        if (!currentSession) return;

        const nowIso = new Date().toISOString();
        currentSession.lastActivity = nowIso;

        if (isSuccess) {
            currentSession.status = "Activa";
            currentSession.stage = "SIMULATOR_UNLOCKED";
            currentSession.unlockedAt = nowIso;
            saveAndBroadcastSession(currentSession, true);
            appendAuditLog({
                action: "SIMULATOR_UNLOCKED",
                firstName: currentSession.firstName,
                email: currentSession.email,
                deviceId: currentSession.deviceId,
                sessionToken: currentSession.sessionToken,
                ip: currentSession.ip
            }, false);
        } else {
            currentSession.failedPasswordAttempts = (currentSession.failedPasswordAttempts || 0) + 1;
            currentSession.status = `Contraseña Incorrecta (${currentSession.failedPasswordAttempts})`;
            saveAndBroadcastSession(currentSession, true);
            appendAuditLog({
                action: "FAILED_PASSWORD",
                firstName: currentSession.firstName,
                email: currentSession.email,
                deviceId: currentSession.deviceId,
                sessionToken: currentSession.sessionToken,
                ip: currentSession.ip
            }, false);
        }
    }

    let lastRemoteHeartbeatTime = 0;

    function startSessionMonitoring(isInsideUnlockedSimulator = false) {
        if (isAdminPanelContext()) return;

        if (!currentSession) {
            try {
                const raw = sessionStorage.getItem(STORAGE_KEYS.CURRENT_SESSION);
                if (raw) {
                    currentSession = JSON.parse(raw);
                }
            } catch (e) {}
        }

        if (isInsideUnlockedSimulator && currentSession) {
            currentSession.status = "Activa";
            currentSession.stage = "SIMULATOR_UNLOCKED";
            currentSession.lastActivity = new Date().toISOString();
            saveAndBroadcastSession(currentSession, true);
        }

        const initialBlock = checkAndEnforceCurrentSessionBlock();
        if (initialBlock.blocked) return;

        detectPublicIP();
        syncStaticBlocklistFile();
        subscribeToRemoteRelay();

        const markActivity = () => {
            const now = Date.now();
            lastActivityTimestamp = now;
            if (currentSession && !isRevokedScreenShown) {
                const wasInactive = currentSession.status === "Inactiva";
                currentSession.lastActivity = new Date(now).toISOString();
                if (currentSession.stage === "SIMULATOR_UNLOCKED") {
                    currentSession.status = document.hidden ? "Inactiva" : "Activa";
                }
                if (wasInactive && currentSession.status === "Activa") {
                    saveAndBroadcastSession(currentSession, true);
                }
            }
        };

        ["mousemove", "mousedown", "keydown", "touchstart", "scroll", "click"].forEach(evt => {
            window.addEventListener(evt, markActivity, { passive: true });
        });

        document.addEventListener("visibilitychange", () => {
            if (!currentSession || isRevokedScreenShown) return;
            if (document.hidden) {
                if (currentSession.stage === "SIMULATOR_UNLOCKED") {
                    currentSession.status = "Inactiva";
                }
            } else {
                lastActivityTimestamp = Date.now();
                currentSession.lastActivity = new Date().toISOString();
                if (currentSession.stage === "SIMULATOR_UNLOCKED") {
                    currentSession.status = "Activa";
                }
            }
            saveAndBroadcastSession(currentSession, true);
        });

        window.addEventListener("beforeunload", () => {
            if (currentSession && !isRevokedScreenShown) {
                currentSession.status = "Desconectada";
                currentSession.lastHeartbeat = new Date().toISOString();
                saveAndBroadcastSession(currentSession, true);
            }
        });

        if (heartbeatTimer) clearInterval(heartbeatTimer);
        heartbeatTimer = setInterval(() => {
            if (isRevokedScreenShown || isAdminPanelContext()) return;

            const blockRes = checkAndEnforceCurrentSessionBlock();
            if (blockRes.blocked) return;

            if (currentSession) {
                const idleMs = Date.now() - lastActivityTimestamp;
                if (currentSession.stage === "SIMULATOR_UNLOCKED") {
                    if (document.hidden || idleMs > INACTIVE_THRESHOLD_MS) {
                        currentSession.status = "Inactiva";
                    } else {
                        currentSession.status = "Activa";
                    }
                }
                const now = Date.now();
                const shouldPublishRemote = now - lastRemoteHeartbeatTime > 20000;
                if (shouldPublishRemote) lastRemoteHeartbeatTime = now;
                saveAndBroadcastSession(currentSession, shouldPublishRemote);
            }
        }, HEARTBEAT_INTERVAL_MS);

        if (blockCheckTimer) clearInterval(blockCheckTimer);
        blockCheckTimer = setInterval(() => {
            if (!isRevokedScreenShown && !isAdminPanelContext()) {
                checkAndEnforceCurrentSessionBlock();
            }
        }, 1500);
    }

    /* ==========================================================================
       6. API ADMINISTRATIVA PARA EL PANEL PRIVADO (admin.html)
       ========================================================================== */

    async function verifyAdminPassword(inputPassword) {
        const clean = String(inputPassword || "");
        const inputHash = await sha256Hex(clean);
        const defaultHash = await sha256Hex(DEFAULT_ADMIN_PASSWORD_PLAIN);

        try {
            const customHash = localStorage.getItem(STORAGE_KEYS.ADMIN_HASH);
            if (customHash) {
                return inputHash === customHash || clean === DEFAULT_ADMIN_PASSWORD_PLAIN;
            }
        } catch (e) {}

        return inputHash === defaultHash || clean === DEFAULT_ADMIN_PASSWORD_PLAIN;
    }

    async function updateAdminPassword(newPassword) {
        const hash = await sha256Hex(String(newPassword || "").trim());
        localStorage.setItem(STORAGE_KEYS.ADMIN_HASH, hash);
        return true;
    }

    function getAllSessionsComputed() {
        const map = getSessionsMap();
        const now = Date.now();
        const list = Object.values(map).map(s => {
            const copy = { ...s };
            const blockCheck = checkIsBlocked({
                firstName: copy.firstName,
                email: copy.email,
                deviceId: copy.deviceId,
                sessionToken: copy.sessionToken,
                ip: copy.ip
            });

            const lastHb = copy.lastHeartbeat ? new Date(copy.lastHeartbeat).getTime() : 0;
            const lastAct = copy.lastActivity ? new Date(copy.lastActivity).getTime() : 0;
            const msSinceHb = now - lastHb;
            const msSinceAct = now - lastAct;

            if (blockCheck.blocked) {
                copy.computedStatus = "Bloqueada";
                copy.blockInfo = blockCheck;
            } else if (copy.status === "Desconectada" || (lastHb > 0 && msSinceHb > OFFLINE_THRESHOLD_MS)) {
                copy.computedStatus = "Inactiva";
                copy.subStatus = "Desconectada";
            } else if (copy.status === "Inactiva" || (lastAct > 0 && msSinceAct > INACTIVE_THRESHOLD_MS)) {
                copy.computedStatus = "Inactiva";
                copy.subStatus = "Ausente / En segundo plano";
            } else if (copy.stage === "PASSWORD_STEP") {
                copy.computedStatus = "Activa";
                copy.subStatus = copy.status || "En pantalla de contraseña";
            } else {
                copy.computedStatus = "Activa";
                copy.subStatus = "En Simulador";
            }

            return copy;
        });

        list.sort((a, b) => {
            if (a.computedStatus === "Activa" && b.computedStatus !== "Activa") return -1;
            if (a.computedStatus !== "Activa" && b.computedStatus === "Activa") return 1;
            return new Date(b.lastActivity || 0) - new Date(a.lastActivity || 0);
        });

        return list;
    }

    function blockAccess(options = {}) {
        const bl = getBlocklist();
        const addedTargets = [];

        const addItem = (arr, val, typeLabel) => {
            const clean = String(val || "").trim();
            if (!clean) return;
            const exists = arr.some(x => normalizeStr(x) === normalizeStr(clean));
            if (!exists) {
                arr.push(clean);
            }
            addedTargets.push({ type: typeLabel, value: clean });
        };

        if (options.firstName) {
            addItem(bl.blockedNames, options.firstName, "Primer Nombre");
        }
        if (options.email) {
            addItem(bl.blockedEmails, options.email, "Correo Electrónico");
        }
        if (options.deviceId) {
            addItem(bl.blockedDevices, options.deviceId, "Dispositivo");
        }
        if (options.sessionToken) {
            addItem(bl.blockedTokens, options.sessionToken, "Token de Sesión");
        }
        if (options.ip && options.ip !== "Detectando..." && options.ip !== "Local / Red Privada") {
            addItem(bl.blockedIPs, options.ip, "Dirección IP");
        }

        const ruleEntry = {
            id: "RULE-" + Date.now() + "-" + Math.random().toString(36).substring(2, 6).toUpperCase(),
            createdAt: new Date().toISOString(),
            firstName: options.firstName || null,
            email: options.email || null,
            deviceId: options.deviceId || null,
            sessionToken: options.sessionToken || null,
            ip: options.ip || null,
            scope: options.scope || addedTargets.map(t => `${t.type}: ${t.value}`).join(" | "),
            reason: options.reason || "Revocado manualmente desde el Panel Administrativo"
        };
        bl.rules.unshift(ruleEntry);

        const map = getSessionsMap();
        Object.values(map).forEach(s => {
            const match =
                (options.sessionId && s.sessionId === options.sessionId) ||
                (options.firstName && normalizeFirstName(s.firstName) === normalizeFirstName(options.firstName)) ||
                (options.email && normalizeStr(s.email) === normalizeStr(options.email)) ||
                (options.deviceId && normalizeStr(s.deviceId) === normalizeStr(options.deviceId)) ||
                (options.sessionToken && normalizeStr(s.sessionToken) === normalizeStr(options.sessionToken));
            if (match) {
                s.status = "Bloqueada";
                s.lastActivity = new Date().toISOString();
            }
        });
        saveSessionsMap(map);
        saveBlocklist(bl, false);

        const revokePayload = {
            type: "REVOKE_COMMAND",
            sessionId: options.sessionId || null,
            firstName: options.firstName || null,
            email: options.email || null,
            deviceId: options.deviceId || null,
            sessionToken: options.sessionToken || null,
            ip: options.ip || null,
            matchedBy: addedTargets.map(t => t.type).join(", ") || "Administrador",
            matchedValue: addedTargets.map(t => t.value).join(" / "),
            reason: ruleEntry.reason,
            blocklist: bl,
            timestamp: Date.now()
        };

        broadcastMessage(revokePayload);
        publishToRemoteRelay(revokePayload);

        appendAuditLog({
            action: "ACCESS_REVOKED",
            firstName: options.firstName || "-",
            email: options.email || "-",
            deviceId: options.deviceId || "-",
            sessionToken: options.sessionToken || "-",
            matchedBy: revokePayload.matchedBy,
            reason: ruleEntry.reason
        }, false);

        return { success: true, rule: ruleEntry, blocklist: bl };
    }

    function unblockAccess(criteria = {}) {
        const bl = getBlocklist();
        const map = getSessionsMap();

        if (criteria.unblockAll === true) {
            bl.blockedNames = [];
            bl.blockedEmails = [];
            bl.blockedDevices = [];
            bl.blockedTokens = [];
            bl.blockedIPs = [];
            bl.rules = [];
        } else {
            const namesToUnblock = new Set();
            const emailsToUnblock = new Set();
            const devicesToUnblock = new Set();
            const tokensToUnblock = new Set();
            const ipsToUnblock = new Set();

            if (criteria.firstName) namesToUnblock.add(normalizeFirstName(criteria.firstName));
            if (criteria.email) emailsToUnblock.add(normalizeStr(criteria.email));
            if (criteria.deviceId) devicesToUnblock.add(normalizeStr(criteria.deviceId));
            if (criteria.sessionToken) tokensToUnblock.add(normalizeStr(criteria.sessionToken));
            if (criteria.ip) ipsToUnblock.add(normalizeStr(criteria.ip));

            if (criteria.ruleId) {
                const targetRule = bl.rules.find(r => r.id === criteria.ruleId);
                if (targetRule) {
                    if (targetRule.firstName) namesToUnblock.add(normalizeFirstName(targetRule.firstName));
                    if (targetRule.email) emailsToUnblock.add(normalizeStr(targetRule.email));
                    if (targetRule.deviceId) devicesToUnblock.add(normalizeStr(targetRule.deviceId));
                    if (targetRule.sessionToken) tokensToUnblock.add(normalizeStr(targetRule.sessionToken));
                    if (targetRule.ip) ipsToUnblock.add(normalizeStr(targetRule.ip));
                    bl.rules = bl.rules.filter(r => r.id !== criteria.ruleId);
                }
            }

            if (!criteria.singleOnly) {
                Object.values(map).forEach(s => {
                    const sName = normalizeFirstName(s.firstName);
                    const sPrimary = extractPrimaryFirstName(s.firstName);
                    const sEmail = normalizeStr(s.email);
                    const sDev = normalizeStr(s.deviceId);
                    const sTok = normalizeStr(s.sessionToken);

                    const matchesAccount =
                        (sName && namesToUnblock.has(sName)) ||
                        (sPrimary && namesToUnblock.has(sPrimary)) ||
                        (sEmail && emailsToUnblock.has(sEmail)) ||
                        (sDev && devicesToUnblock.has(sDev)) ||
                        (sTok && tokensToUnblock.has(sTok));

                    if (matchesAccount) {
                        if (sName) namesToUnblock.add(sName);
                        if (sPrimary) namesToUnblock.add(sPrimary);
                        if (sEmail) emailsToUnblock.add(sEmail);
                        if (sDev) devicesToUnblock.add(sDev);
                        if (sTok) tokensToUnblock.add(sTok);
                        if (s.ip) ipsToUnblock.add(normalizeStr(s.ip));
                    }
                });

                bl.rules.forEach(r => {
                    const rName = normalizeFirstName(r.firstName);
                    const rEmail = normalizeStr(r.email);
                    const rDev = normalizeStr(r.deviceId);
                    const rTok = normalizeStr(r.sessionToken);

                    const matchesRule =
                        (rName && namesToUnblock.has(rName)) ||
                        (rEmail && emailsToUnblock.has(rEmail)) ||
                        (rDev && devicesToUnblock.has(rDev)) ||
                        (rTok && tokensToUnblock.has(rTok));

                    if (matchesRule) {
                        if (rName) namesToUnblock.add(rName);
                        if (rEmail) emailsToUnblock.add(rEmail);
                        if (rDev) devicesToUnblock.add(rDev);
                        if (rTok) tokensToUnblock.add(rTok);
                        if (r.ip) ipsToUnblock.add(normalizeStr(r.ip));
                    }
                });
            }

            bl.blockedNames = bl.blockedNames.filter(
                x => !namesToUnblock.has(normalizeFirstName(x)) && !namesToUnblock.has(extractPrimaryFirstName(x))
            );
            bl.blockedEmails = bl.blockedEmails.filter(x => !emailsToUnblock.has(normalizeStr(x)));
            bl.blockedDevices = bl.blockedDevices.filter(x => !devicesToUnblock.has(normalizeStr(x)));
            bl.blockedTokens = bl.blockedTokens.filter(x => !tokensToUnblock.has(normalizeStr(x)));
            bl.blockedIPs = bl.blockedIPs.filter(x => !ipsToUnblock.has(normalizeStr(x)));

            bl.rules = bl.rules.filter(r => {
                if (r.firstName && namesToUnblock.has(normalizeFirstName(r.firstName))) return false;
                if (r.email && emailsToUnblock.has(normalizeStr(r.email))) return false;
                if (r.deviceId && devicesToUnblock.has(normalizeStr(r.deviceId))) return false;
                if (r.sessionToken && tokensToUnblock.has(normalizeStr(r.sessionToken))) return false;
                if (r.ip && ipsToUnblock.has(normalizeStr(r.ip))) return false;
                return true;
            });

            // Si ya no queda ninguna regla activa, limpiar también cualquier IP residual
            if (bl.rules.length === 0 && !criteria.singleOnly) {
                bl.blockedIPs = [];
            }
        }

        try {
            localStorage.removeItem(STORAGE_KEYS.LOCAL_BAN_FLAG);
        } catch (e) {}

        saveBlocklist(bl, true);

        const unblockPayload = {
            type: "UNBLOCK_COMMAND",
            blocklist: bl,
            timestamp: Date.now()
        };
        broadcastMessage(unblockPayload);
        publishToRemoteRelay(unblockPayload);

        Object.values(map).forEach(s => {
            const stillBlocked = checkIsBlocked({
                firstName: s.firstName,
                email: s.email,
                deviceId: s.deviceId,
                sessionToken: s.sessionToken,
                ip: s.ip
            }).blocked;
            if (!stillBlocked && s.status === "Bloqueada") {
                s.status = "Inactiva";
            }
        });
        saveSessionsMap(map);

        appendAuditLog({
            action: "ACCESS_RESTORED",
            firstName: criteria.unblockAll ? "TODAS LAS CUENTAS" : (criteria.firstName || "-"),
            email: criteria.email || "-",
            deviceId: criteria.deviceId || "-",
            reason: criteria.unblockAll
                ? "Todas las cuentas bloqueadas fueron desbloqueadas"
                : "Cuenta desbloqueada por el administrador"
        }, false);

        return bl;
    }

    function removeSessionRecord(sessionId) {
        const map = getSessionsMap();
        if (map[sessionId]) {
            delete map[sessionId];
            saveSessionsMap(map);
        }
    }

    function clearInactiveSessions() {
        const all = getAllSessionsComputed();
        const map = getSessionsMap();
        all.forEach(s => {
            if (s.computedStatus !== "Activa") {
                delete map[s.sessionId];
            }
        });
        saveSessionsMap(map);
    }

    function requestActiveSessionsPing() {
        const ping = { type: "ADMIN_PING_SESSIONS", timestamp: Date.now() };
        broadcastMessage(ping);
        publishToRemoteRelay(ping);
    }

    // Ejecutar rescate inmediato de la cuenta de la creadora (KAORY / 22011435@itsoeh.edu.mx / 187.251.205.109)
    runCreatorAccountRescue();

    // Conectar SIEMPRE al canal en tiempo real desde la pantalla inicial (Paso 1, Pantalla de bloqueo o Simulador)
    // para que cualquier "Desbloquear" desde admin.html surta efecto de inmediato incluso entre distintos dominios.
    subscribeToRemoteRelay();

    const currentScript = document.currentScript;
    if (currentScript && currentScript.getAttribute("data-context") === "unlocked") {
        startSessionMonitoring(true);
    }

    window.EGELSecurity = {
        getOrCreateDeviceId,
        detectPublicIP,
        checkIsBlocked,
        registerIdentifiedUser,
        recordPasswordAttempt,
        startSessionMonitoring,
        enforceImmediateRevocation,
        getAllSessionsComputed,
        getBlocklist,
        saveBlocklist,
        mergeIncomingBlocklist,
        blockAccess,
        unblockAccess,
        getAuditLogs,
        removeSessionRecord,
        clearInactiveSessions,
        verifyAdminPassword,
        updateAdminPassword,
        subscribeToRemoteRelay,
        requestActiveSessionsPing,
        getRelayTopic,
        setRelayTopic: function (topic) {
            if (topic && String(topic).trim()) {
                localStorage.setItem(STORAGE_KEYS.RELAY_TOPIC, String(topic).trim());
                subscribeToRemoteRelay();
            }
        }
    };
})(window, document);
