import { randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const DATEI_ORDNER = dirname(fileURLToPath(import.meta.url));
const DIST_ORDNER = resolve(DATEI_ORDNER, "..", "dist");
const MAX_BODY_BYTES = 32 * 1024;
const MAX_EMAILS_PRO_STUNDE = 20;
const ABSENDER = "Lead Liebe <info@leadliebe.com>";
const ANTWORT_ADRESSE = "info@leadliebe.com";

class OeffentlicherFehler extends Error {
  constructor(status, meldung) {
    super(meldung);
    this.status = status;
    this.oeffentlich = true;
  }
}

class InternerDienstfehler extends Error {}

function envPflicht(name, alternativen = []) {
  for (const schluessel of [name, ...alternativen]) {
    const wert = process.env[schluessel]?.trim();
    if (wert) return wert;
  }
  throw new Error(`Server-Konfiguration unvollständig: ${name}`);
}

function positivePort(raw) {
  const wert = Number(raw || 8080);
  if (!Number.isInteger(wert) || wert < 1 || wert > 65535) {
    throw new Error("Server-Konfiguration unvollständig: PORT");
  }
  return wert;
}

const SUPABASE_URL = envPflicht("SUPABASE_URL").replace(/\/$/, "");
const SUPABASE_ANON_KEY = envPflicht("SUPABASE_ANON_KEY", [
  "SUPABASE_PUBLISHABLE_KEY",
]);
const SUPABASE_SERVICE_ROLE_KEY = envPflicht("SUPABASE_SERVICE_ROLE_KEY");
const RESEND_API_KEY = envPflicht("RESEND_API_KEY");
const PORT = positivePort(process.env.PORT);

const supabaseAdresse = new URL(SUPABASE_URL);
if (
  supabaseAdresse.protocol !== "https:" &&
  !(
    supabaseAdresse.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(supabaseAdresse.hostname)
  )
) {
  throw new Error("Server-Konfiguration unvollständig: SUPABASE_URL");
}

const SUPABASE_ORIGIN = supabaseAdresse.origin;
const SUPABASE_WS_ORIGIN = `${supabaseAdresse.protocol === "https:" ? "wss:" : "ws:"}//${supabaseAdresse.host}`;
const salesSperren = new Map();

const MIME = new Map([
  [".avif", "image/avif"],
  [".css", "text/css; charset=utf-8"],
  [".csv", "text/csv; charset=utf-8"],
  [".gif", "image/gif"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".pdf", "application/pdf"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webmanifest", "application/manifest+json"],
  [".webp", "image/webp"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
  [".xml", "application/xml; charset=utf-8"],
]);

function setzeSicherheitsHeader(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  );
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "base-uri 'self'",
      `connect-src 'self' ${SUPABASE_ORIGIN} ${SUPABASE_WS_ORIGIN}`,
      "font-src 'self' data:",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "img-src 'self' data: blob: https:",
      "object-src 'none'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "worker-src 'self' blob:",
    ].join("; "),
  );
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
}

function jsonAntwort(res, status, daten) {
  setzeSicherheitsHeader(res);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(daten));
}

function methodeNichtErlaubt(res, erlaubt) {
  res.setHeader("Allow", erlaubt.join(", "));
  jsonAntwort(res, 405, {
    ok: false,
    meldung: "Diese Aktion ist hier nicht erlaubt.",
  });
}

function bearerToken(req) {
  const authorization = req.headers.authorization;
  if (
    typeof authorization !== "string" ||
    !authorization.startsWith("Bearer ")
  ) {
    throw new OeffentlicherFehler(401, "Bitte erneut anmelden.");
  }
  const token = authorization.slice(7).trim();
  if (!token || token.length > 8192) {
    throw new OeffentlicherFehler(401, "Bitte erneut anmelden.");
  }
  return token;
}

async function leseJson(req) {
  const contentType = req.headers["content-type"];
  if (
    typeof contentType !== "string" ||
    !contentType.toLowerCase().startsWith("application/json")
  ) {
    throw new OeffentlicherFehler(
      415,
      "Die Eingabe muss als JSON gesendet werden.",
    );
  }
  const contentLength = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    throw new OeffentlicherFehler(413, "Die Eingabe ist zu groß.");
  }

  const teile = [];
  let groesse = 0;
  for await (const teil of req) {
    groesse += teil.length;
    if (groesse > MAX_BODY_BYTES) {
      throw new OeffentlicherFehler(413, "Die Eingabe ist zu groß.");
    }
    teile.push(teil);
  }

  if (groesse === 0) {
    throw new OeffentlicherFehler(400, "Die Eingabe fehlt.");
  }

  let daten;
  try {
    daten = JSON.parse(Buffer.concat(teile).toString("utf8"));
  } catch {
    throw new OeffentlicherFehler(400, "Die Eingabe ist ungültig.");
  }
  if (!daten || typeof daten !== "object" || Array.isArray(daten)) {
    throw new OeffentlicherFehler(400, "Die Eingabe ist ungültig.");
  }
  return daten;
}

function istUuid(wert) {
  if (typeof wert !== "string" || wert.length !== 36) return false;
  const bindestriche = new Set([8, 13, 18, 23]);
  const hex = "0123456789abcdefABCDEF";
  for (let i = 0; i < wert.length; i += 1) {
    if (bindestriche.has(i)) {
      if (wert[i] !== "-") return false;
    } else if (!hex.includes(wert[i])) {
      return false;
    }
  }
  return true;
}

function normaleEmail(wert) {
  if (typeof wert !== "string") return null;
  const email = wert.trim();
  if (
    email.length < 3 ||
    email.length > 254 ||
    email.includes("\r") ||
    email.includes("\n") ||
    email.includes("\t") ||
    email.includes("\f") ||
    email.includes("\v") ||
    email.includes("\0") ||
    email.includes(" ")
  ) {
    return null;
  }
  const teile = email.split("@");
  if (
    teile.length !== 2 ||
    !teile[0] ||
    !teile[1] ||
    teile[0].length > 64 ||
    !teile[1].includes(".") ||
    teile[1].startsWith(".") ||
    teile[1].endsWith(".")
  ) {
    return null;
  }
  return email;
}

function sichererBetreff(wert) {
  if (typeof wert !== "string") return null;
  const betreff = wert.trim();
  if (
    !betreff ||
    betreff.length > 200 ||
    betreff.includes("\r") ||
    betreff.includes("\n") ||
    betreff.includes("\0")
  ) {
    return null;
  }
  return betreff;
}

function sichererText(wert, maximum = 20_000) {
  if (typeof wert !== "string") return null;
  const text = wert.trim();
  if (!text || text.length > maximum || text.includes("\0")) return null;
  return text;
}

async function fetchMitZeitlimit(url, optionen, millisekunden = 10_000) {
  return fetch(url, {
    ...optionen,
    signal: AbortSignal.timeout(millisekunden),
  });
}

async function authentifizierterNutzer(token) {
  let antwort;
  try {
    antwort = await fetchMitZeitlimit(`${SUPABASE_URL}/auth/v1/user`, {
      method: "GET",
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new OeffentlicherFehler(
      503,
      "Die Anmeldung kann gerade nicht geprüft werden.",
    );
  }
  if (!antwort.ok) {
    throw new OeffentlicherFehler(401, "Bitte erneut anmelden.");
  }
  let nutzer;
  try {
    nutzer = await antwort.json();
  } catch {
    throw new OeffentlicherFehler(401, "Bitte erneut anmelden.");
  }
  if (!istUuid(nutzer?.id)) {
    throw new OeffentlicherFehler(401, "Bitte erneut anmelden.");
  }
  return nutzer;
}

function restUrl(tabelle, parameter = {}) {
  const url = new URL(`${SUPABASE_URL}/rest/v1/${tabelle}`);
  for (const [name, wert] of Object.entries(parameter)) {
    if (wert !== undefined && wert !== null) {
      url.searchParams.set(name, String(wert));
    }
  }
  return url;
}

async function restAnfrage(
  tabelle,
  { method = "GET", parameter = {}, body, prefer },
) {
  let antwort;
  try {
    antwort = await fetchMitZeitlimit(restUrl(tabelle, parameter), {
      method,
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "Accept-Profile": "crm",
        "Content-Profile": "crm",
        "Content-Type": "application/json; charset=utf-8",
        ...(prefer ? { Prefer: prefer } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new InternerDienstfehler("Datenzugriff nicht erreichbar");
  }

  if (!antwort.ok) {
    throw new InternerDienstfehler("Datenzugriff abgelehnt");
  }
  if (antwort.status === 204) return null;

  const text = await antwort.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new InternerDienstfehler("Datenantwort ungültig");
  }
}

async function restListe(tabelle, parameter) {
  const daten = await restAnfrage(tabelle, { parameter });
  if (!Array.isArray(daten)) {
    throw new InternerDienstfehler("Datenliste ungültig");
  }
  return daten;
}

async function aktiverSales(nutzerId) {
  const zeilen = await restListe("sales", {
    select: "id,user_id,tenant,administrator,access_mode,disabled",
    user_id: `eq.${nutzerId}`,
    disabled: "eq.false",
    limit: "2",
  });
  if (zeilen.length !== 1) {
    throw new OeffentlicherFehler(
      403,
      "Für dieses Konto besteht kein aktiver Arbeitszugang.",
    );
  }
  const sales = zeilen[0];
  if (
    !istUuid(sales.id) ||
    sales.user_id !== nutzerId ||
    sales.disabled !== false ||
    typeof sales.tenant !== "string" ||
    !sales.tenant.trim()
  ) {
    throw new OeffentlicherFehler(
      403,
      "Für dieses Konto besteht kein aktiver Arbeitszugang.",
    );
  }
  return sales;
}

async function kontaktImTenant(contactId, tenant) {
  const kontakte = await restListe("contacts", {
    select: "id,tenant,company_id,email,first_name,last_name",
    id: `eq.${contactId}`,
    tenant: `eq.${tenant}`,
    limit: "2",
  });
  if (kontakte.length !== 1) {
    throw new OeffentlicherFehler(404, "Der Kontakt wurde nicht gefunden.");
  }
  const kontakt = kontakte[0];
  if (!istUuid(kontakt.company_id)) {
    throw new OeffentlicherFehler(
      409,
      "Dem Kontakt ist keine gültige Firma zugeordnet.",
    );
  }
  const firmen = await restListe("companies", {
    select: "id,tenant,name",
    id: `eq.${kontakt.company_id}`,
    tenant: `eq.${tenant}`,
    limit: "2",
  });
  if (firmen.length !== 1) {
    throw new OeffentlicherFehler(
      409,
      "Die Firmenzuordnung des Kontakts ist ungültig.",
    );
  }
  return { kontakt, firma: firmen[0] };
}

async function terminImScope(appointmentId, sales) {
  const termine = await restListe("appointments", {
    select:
      "id,tenant,sales_id,company_id,contact_id,title,starts_at,ends_at,notes,recipient_email,status,invite_status",
    id: `eq.${appointmentId}`,
    tenant: `eq.${sales.tenant}`,
    sales_id: `eq.${sales.id}`,
    limit: "2",
  });
  if (termine.length !== 1) {
    throw new OeffentlicherFehler(404, "Der Termin wurde nicht gefunden.");
  }
  const termin = termine[0];
  if (termin.status === "cancelled") {
    throw new OeffentlicherFehler(
      409,
      "Für einen abgesagten Termin wird keine Einladung versendet.",
    );
  }
  if (termin.invite_status === "sent") {
    throw new OeffentlicherFehler(
      409,
      "Für diesen Termin wurde die Einladung bereits versendet.",
    );
  }
  const { kontakt, firma } = await kontaktImTenant(
    termin.contact_id,
    sales.tenant,
  );
  if (
    kontakt.company_id !== termin.company_id ||
    firma.id !== termin.company_id
  ) {
    throw new OeffentlicherFehler(
      409,
      "Kontakt und Termin passen nicht zusammen.",
    );
  }
  const empfaenger = normaleEmail(termin.recipient_email);
  const kontaktEmail = normaleEmail(kontakt.email);
  if (
    !empfaenger ||
    !kontaktEmail ||
    empfaenger.toLocaleLowerCase("de") !== kontaktEmail.toLocaleLowerCase("de")
  ) {
    throw new OeffentlicherFehler(
      409,
      "Die Terminadresse muss der gespeicherten Kontaktadresse entsprechen.",
    );
  }
  return { termin, kontakt, firma, empfaenger };
}

function utcIcsDatum(datum) {
  return `${datum
    .toISOString()
    .slice(0, 19)
    .replaceAll("-", "")
    .replaceAll(":", "")}Z`;
}

function zurichIcsDatum(datum) {
  const teile = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Zurich",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(datum);
  const wert = Object.fromEntries(
    teile
      .filter((teil) => teil.type !== "literal")
      .map((teil) => [teil.type, teil.value]),
  );
  return `${wert.year}${wert.month}${wert.day}T${wert.hour}${wert.minute}${wert.second}`;
}

function deutschesDatum(datum) {
  return new Intl.DateTimeFormat("de-CH", {
    timeZone: "Europe/Zurich",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).format(datum);
}

function deutscheZeit(datum) {
  return new Intl.DateTimeFormat("de-CH", {
    timeZone: "Europe/Zurich",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(datum);
}

function icsText(wert) {
  return String(wert ?? "")
    .replaceAll("\\", "\\\\")
    .replaceAll("\r\n", "\\n")
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\n")
    .replaceAll(",", "\\,")
    .replaceAll(";", "\\;");
}

function baueTerminMail(termin) {
  const start = new Date(termin.starts_at);
  const ende = new Date(termin.ends_at);
  if (
    !Number.isFinite(start.getTime()) ||
    !Number.isFinite(ende.getTime()) ||
    ende <= start
  ) {
    throw new OeffentlicherFehler(409, "Die Terminzeit ist ungültig.");
  }
  const titel = sichererBetreff(termin.title);
  if (!titel) {
    throw new OeffentlicherFehler(409, "Der Termintitel ist ungültig.");
  }

  const beschreibung = sichererText(
    termin.notes || "Termin mit Lead Liebe",
    5_000,
  );
  const ics = [
    "BEGIN:VCALENDAR",
    "PRODID:-//Lead Liebe//Termin//DE",
    "VERSION:2.0",
    "CALSCALE:GREGORIAN",
    "METHOD:REQUEST",
    "BEGIN:VTIMEZONE",
    "TZID:Europe/Zurich",
    "X-LIC-LOCATION:Europe/Zurich",
    "BEGIN:DAYLIGHT",
    "TZOFFSETFROM:+0100",
    "TZOFFSETTO:+0200",
    "TZNAME:CEST",
    "DTSTART:19700329T020000",
    "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU",
    "END:DAYLIGHT",
    "BEGIN:STANDARD",
    "TZOFFSETFROM:+0200",
    "TZOFFSETTO:+0100",
    "TZNAME:CET",
    "DTSTART:19701025T030000",
    "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU",
    "END:STANDARD",
    "END:VTIMEZONE",
    "BEGIN:VEVENT",
    `UID:${termin.id}@crm.leadliebe.com`,
    `DTSTAMP:${utcIcsDatum(new Date())}`,
    `DTSTART;TZID=Europe/Zurich:${zurichIcsDatum(start)}`,
    `DTEND;TZID=Europe/Zurich:${zurichIcsDatum(ende)}`,
    `SUMMARY:${icsText(titel)}`,
    `DESCRIPTION:${icsText(beschreibung)}`,
    "STATUS:CONFIRMED",
    "TRANSP:OPAQUE",
    "SEQUENCE:0",
    "END:VEVENT",
    "END:VCALENDAR",
    "",
  ].join("\r\n");

  const body = [
    "Guten Tag",
    "",
    "hiermit bestätigen wir Ihren Termin:",
    "",
    titel,
    `${deutschesDatum(start)}, ${deutscheZeit(start)} bis ${deutscheZeit(ende)} Uhr`,
    "Zeitzone: Europe/Zurich",
    "",
    "Die Kalendereinladung ist dieser E-Mail beigefügt.",
    "",
    "Freundliche Grüsse",
    "Lead Liebe",
  ].join("\n");

  return {
    betreff: `Terminbestätigung: ${titel}`,
    body,
    anhang: {
      filename: "Termin-Lead-Liebe.ics",
      content: Buffer.from(ics, "utf8").toString("base64"),
      content_type: "text/calendar; charset=utf-8; method=REQUEST",
    },
  };
}

async function mitSalesSperre(salesId, arbeit) {
  const vorher = salesSperren.get(salesId) || Promise.resolve();
  let freigeben;
  const tor = new Promise((resolveTor) => {
    freigeben = resolveTor;
  });
  const kette = vorher.then(() => tor);
  salesSperren.set(salesId, kette);
  await vorher;
  try {
    return await arbeit();
  } finally {
    freigeben();
    if (salesSperren.get(salesId) === kette) salesSperren.delete(salesId);
  }
}

async function pruefeStundenlimit(salesId) {
  const seit = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const letzte = await restListe("email_messages", {
    select: "id",
    sales_id: `eq.${salesId}`,
    created_at: `gte.${seit}`,
    order: "created_at.desc",
    limit: String(MAX_EMAILS_PRO_STUNDE),
  });
  if (letzte.length >= MAX_EMAILS_PRO_STUNDE) {
    throw new OeffentlicherFehler(
      429,
      "Das Stundenlimit von 20 E-Mails ist erreicht. Bitte später erneut versuchen.",
    );
  }
}

async function mitWiederholung(arbeit, versuche = 3) {
  let letzterFehler;
  for (let versuch = 1; versuch <= versuche; versuch += 1) {
    try {
      return await arbeit();
    } catch (fehler) {
      letzterFehler = fehler;
      if (versuch < versuche) {
        await new Promise((resolveZeit) =>
          setTimeout(resolveZeit, versuch * 150),
        );
      }
    }
  }
  throw letzterFehler;
}

async function protokolliereAktivitaet({
  sales,
  kontakt,
  firma,
  emailMessageId,
  appointmentId,
  eventType,
  outcome,
  note,
}) {
  await restAnfrage("activity_events", {
    method: "POST",
    body: {
      id: randomUUID(),
      tenant: sales.tenant,
      sales_id: sales.id,
      company_id: firma.id,
      contact_id: kontakt.id,
      event_type: eventType,
      outcome,
      note,
      happened_at: new Date().toISOString(),
      metadata: {
        email_message_id: emailMessageId,
        appointment_id: appointmentId || null,
        consent_confirmed: appointmentId ? null : true,
      },
    },
    prefer: "return=minimal",
  });
}

async function sendeNachricht({
  empfaenger,
  betreff,
  body,
  anhang,
  emailMessageId,
}) {
  let antwort;
  try {
    antwort = await fetchMitZeitlimit(
      "https://api.resend.com/emails",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json; charset=utf-8",
          "Idempotency-Key": `crm-${emailMessageId}`,
        },
        body: JSON.stringify({
          from: ABSENDER,
          to: [empfaenger],
          reply_to: ANTWORT_ADRESSE,
          subject: betreff,
          text: body,
          ...(anhang ? { attachments: [anhang] } : {}),
        }),
      },
      15_000,
    );
  } catch {
    throw new InternerDienstfehler("Versand nicht erreichbar");
  }
  if (!antwort.ok) {
    throw new InternerDienstfehler("Versand abgelehnt");
  }
  let daten = null;
  try {
    daten = await antwort.json();
  } catch {
    // Eine erfolgreiche HTTP-Antwort ist der Versandbeleg; die externe ID ist optional.
  }
  return typeof daten?.id === "string" && daten.id.length <= 300
    ? daten.id
    : null;
}

async function setzeEmailStatus(emailMessageId, tenant, daten) {
  const zeilen = await restAnfrage("email_messages", {
    method: "PATCH",
    parameter: {
      id: `eq.${emailMessageId}`,
      tenant: `eq.${tenant}`,
      select: "id",
    },
    body: daten,
    prefer: "return=representation",
  });
  if (!Array.isArray(zeilen) || zeilen.length !== 1) {
    throw new InternerDienstfehler("E-Mail-Protokoll nicht aktualisiert");
  }
}

async function setzeTerminEinladung(appointmentId, sales, status, sentAt) {
  if (!appointmentId) return;
  const zeilen = await restAnfrage("appointments", {
    method: "PATCH",
    parameter: {
      id: `eq.${appointmentId}`,
      tenant: `eq.${sales.tenant}`,
      sales_id: `eq.${sales.id}`,
      select: "id",
    },
    body: {
      invite_status: status,
      invite_sent_at: sentAt,
    },
    prefer: "return=representation",
  });
  if (!Array.isArray(zeilen) || zeilen.length !== 1) {
    throw new InternerDienstfehler("Terminstatus nicht aktualisiert");
  }
}

async function markiereFehlversand({
  emailMessageId,
  sales,
  kontakt,
  firma,
  appointmentId,
}) {
  const aufgaben = [
    () =>
      setzeEmailStatus(emailMessageId, sales.tenant, {
        status: "failed",
        provider_id: null,
        error: "Versand fehlgeschlagen",
        sent_at: null,
      }),
    () =>
      protokolliereAktivitaet({
        sales,
        kontakt,
        firma,
        emailMessageId,
        appointmentId,
        eventType: "email_failed",
        outcome: "failed",
        note: "E-Mail-Versand fehlgeschlagen",
      }),
    () => setzeTerminEinladung(appointmentId, sales, "failed", null),
  ];
  await Promise.allSettled(aufgaben.map((aufgabe) => mitWiederholung(aufgabe)));
}

async function fuehreVersandAus({
  sales,
  kontakt,
  firma,
  appointmentId,
  messageKind,
  empfaenger,
  betreff,
  body,
  anhang,
}) {
  return mitSalesSperre(sales.id, async () => {
    await pruefeStundenlimit(sales.id);

    const emailMessageId = randomUUID();
    await restAnfrage("email_messages", {
      method: "POST",
      body: {
        id: emailMessageId,
        tenant: sales.tenant,
        sales_id: sales.id,
        company_id: firma.id,
        contact_id: kontakt.id,
        appointment_id: appointmentId || null,
        recipient: empfaenger,
        subject: betreff,
        body,
        message_kind: messageKind,
        status: "queued",
      },
      prefer: "return=minimal",
    });

    let providerId;
    try {
      providerId = await sendeNachricht({
        empfaenger,
        betreff,
        body,
        anhang,
        emailMessageId,
      });
    } catch {
      await markiereFehlversand({
        emailMessageId,
        sales,
        kontakt,
        firma,
        appointmentId,
      });
      throw new OeffentlicherFehler(
        502,
        "Die E-Mail konnte nicht versendet werden. Bitte später erneut versuchen.",
      );
    }

    const sentAt = new Date().toISOString();
    let protokolliert = true;
    const protokollSchritte = [
      () =>
        setzeEmailStatus(emailMessageId, sales.tenant, {
          status: "sent",
          provider_id: providerId,
          error: null,
          sent_at: sentAt,
        }),
      () =>
        protokolliereAktivitaet({
          sales,
          kontakt,
          firma,
          emailMessageId,
          appointmentId,
          eventType: "email_sent",
          outcome: "sent",
          note:
            messageKind === "appointment"
              ? "Terminbestätigung versendet"
              : "E-Mail versendet",
        }),
      () => setzeTerminEinladung(appointmentId, sales, "sent", sentAt),
    ];
    const ergebnisse = await Promise.allSettled(
      protokollSchritte.map((schritt) => mitWiederholung(schritt)),
    );
    if (ergebnisse.some((ergebnis) => ergebnis.status === "rejected")) {
      protokolliert = false;
    }

    return { emailMessageId, protokolliert };
  });
}

async function crmEmail(req, res) {
  if (req.method !== "POST") {
    methodeNichtErlaubt(res, ["POST"]);
    return;
  }
  const token = bearerToken(req);
  const eingabe = await leseJson(req);
  const nutzer = await authentifizierterNutzer(token);
  const sales = await aktiverSales(nutzer.id);
  if (eingabe.consentConfirmed !== true) {
    throw new OeffentlicherFehler(
      400,
      "Bitte bestätigen, dass der Empfänger diese E-Mail gewünscht oder erlaubt hat.",
    );
  }
  if (!istUuid(eingabe.companyId) || !istUuid(eingabe.contactId)) {
    throw new OeffentlicherFehler(
      400,
      "Bitte Firma und Kontakt gültig wählen.",
    );
  }
  const betreff = sichererBetreff(eingabe.subject);
  const body = sichererText(eingabe.body);
  if (!betreff || !body) {
    throw new OeffentlicherFehler(
      400,
      "Betreff und Nachricht müssen vollständig sein.",
    );
  }
  const { kontakt, firma } = await kontaktImTenant(
    eingabe.contactId,
    sales.tenant,
  );
  if (
    firma.id !== eingabe.companyId ||
    kontakt.company_id !== eingabe.companyId
  ) {
    throw new OeffentlicherFehler(
      409,
      "Firma und Kontakt passen nicht zusammen.",
    );
  }
  const empfaenger = normaleEmail(kontakt.email);
  const angefragterEmpfaenger = normaleEmail(eingabe.to);
  if (!empfaenger) {
    throw new OeffentlicherFehler(
      409,
      "Beim Kontakt ist keine gültige E-Mail-Adresse gespeichert.",
    );
  }
  if (
    !angefragterEmpfaenger ||
    angefragterEmpfaenger.toLocaleLowerCase("de") !==
      empfaenger.toLocaleLowerCase("de")
  ) {
    throw new OeffentlicherFehler(
      409,
      "Die Empfängeradresse stimmt nicht mit dem gespeicherten Kontakt überein.",
    );
  }
  const ergebnis = await fuehreVersandAus({
    sales,
    kontakt,
    firma,
    appointmentId: null,
    messageKind: "outbound",
    empfaenger,
    betreff,
    body,
    anhang: null,
  });
  jsonAntwort(res, 200, {
    ok: true,
    meldung: "Die E-Mail wurde versendet.",
    protokolliert: ergebnis.protokolliert,
    nachrichtId: ergebnis.emailMessageId,
  });
}

async function crmTerminEinladung(req, res) {
  if (req.method !== "POST") {
    methodeNichtErlaubt(res, ["POST"]);
    return;
  }
  const token = bearerToken(req);
  const eingabe = await leseJson(req);
  const nutzer = await authentifizierterNutzer(token);
  const sales = await aktiverSales(nutzer.id);
  if (eingabe.consentConfirmed !== true) {
    throw new OeffentlicherFehler(
      400,
      "Bitte bestätigen, dass der Termin mit dem Empfänger vereinbart wurde.",
    );
  }
  if (!istUuid(eingabe.appointmentId)) {
    throw new OeffentlicherFehler(400, "Bitte einen gültigen Termin wählen.");
  }
  const { termin, kontakt, firma, empfaenger } = await terminImScope(
    eingabe.appointmentId,
    sales,
  );
  const mail = baueTerminMail(termin);
  const ergebnis = await fuehreVersandAus({
    sales,
    kontakt,
    firma,
    appointmentId: termin.id,
    messageKind: "appointment",
    empfaenger,
    betreff: mail.betreff,
    body: mail.body,
    anhang: mail.anhang,
  });
  jsonAntwort(res, 200, {
    ok: true,
    meldung: "Die Terminbestätigung wurde versendet.",
    protokolliert: ergebnis.protokolliert,
    nachrichtId: ergebnis.emailMessageId,
  });
}

function dateiCacheHeader(pfad) {
  if (pfad.endsWith("index.html")) {
    return "no-cache, max-age=0, must-revalidate";
  }
  if (pfad.includes(`${sep}assets${sep}`)) {
    return "public, max-age=31536000, immutable";
  }
  return "public, max-age=3600";
}

async function vorhandeneDatei(pfad) {
  try {
    const info = await stat(pfad);
    return info.isFile() ? info : null;
  } catch {
    return null;
  }
}

async function statischeDatei(req, res, pathname) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    methodeNichtErlaubt(res, ["GET", "HEAD"]);
    return;
  }

  let dekodiert;
  try {
    dekodiert = decodeURIComponent(pathname);
  } catch {
    throw new OeffentlicherFehler(400, "Die Adresse ist ungültig.");
  }
  if (dekodiert.includes("\0")) {
    throw new OeffentlicherFehler(400, "Die Adresse ist ungültig.");
  }

  const relativ = dekodiert === "/" ? "index.html" : `.${dekodiert}`;
  let dateipfad = resolve(DIST_ORDNER, relativ);
  if (
    dateipfad !== DIST_ORDNER &&
    !dateipfad.startsWith(`${DIST_ORDNER}${sep}`)
  ) {
    throw new OeffentlicherFehler(404, "Die Seite wurde nicht gefunden.");
  }

  let info = await vorhandeneDatei(dateipfad);
  if (!info && extname(dekodiert) === "") {
    dateipfad = resolve(DIST_ORDNER, "index.html");
    info = await vorhandeneDatei(dateipfad);
  }
  if (!info) {
    throw new OeffentlicherFehler(404, "Die Seite wurde nicht gefunden.");
  }

  setzeSicherheitsHeader(res);
  res.statusCode = 200;
  res.setHeader(
    "Content-Type",
    MIME.get(extname(dateipfad).toLowerCase()) || "application/octet-stream",
  );
  res.setHeader("Content-Length", String(info.size));
  res.setHeader("Cache-Control", dateiCacheHeader(dateipfad));
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  const stream = createReadStream(dateipfad);
  stream.on("error", () => {
    if (!res.headersSent) {
      jsonAntwort(res, 500, {
        ok: false,
        meldung: "Die Datei kann gerade nicht geladen werden.",
      });
    } else {
      res.destroy();
    }
  });
  stream.pipe(res);
}

const server = createServer(async (req, res) => {
  const requestId = randomUUID();
  res.setHeader("X-Request-Id", requestId);
  try {
    const url = new URL(req.url || "/", "http://localhost");
    if (url.pathname === "/healthz") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        methodeNichtErlaubt(res, ["GET", "HEAD"]);
        return;
      }
      if (req.method === "HEAD") {
        setzeSicherheitsHeader(res);
        res.statusCode = 200;
        res.setHeader("Cache-Control", "no-store");
        res.end();
      } else {
        jsonAntwort(res, 200, { ok: true, status: "aktiv" });
      }
      return;
    }
    if (url.pathname === "/api/crm/email") {
      await crmEmail(req, res);
      return;
    }
    if (url.pathname === "/api/crm/appointment-invite") {
      await crmTerminEinladung(req, res);
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      throw new OeffentlicherFehler(
        404,
        "Diese Schnittstelle existiert nicht.",
      );
    }
    await statischeDatei(req, res, url.pathname);
  } catch (fehler) {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    if (fehler?.oeffentlich) {
      jsonAntwort(res, fehler.status, { ok: false, meldung: fehler.message });
      return;
    }
    console.error(`[crm-email] ${requestId} interner Fehler`);
    jsonAntwort(res, 500, {
      ok: false,
      meldung: "Die Aktion konnte gerade nicht abgeschlossen werden.",
    });
  }
});

server.requestTimeout = 20_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 60;

server.listen(PORT, "0.0.0.0", () => {
  console.warn(`[crm-runtime] aktiv auf Port ${PORT}`);
});
