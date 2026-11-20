import asyncio
import ipaddress
import logging
import os
import socket
import time
from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse

import aiohttp
import aiosqlite
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from dotenv import load_dotenv
from openpyxl import Workbook

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
DB_PATH = os.getenv("DB_PATH", "sites.db")
HTTP_TIMEOUT = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("site-monitor")

# ---------------------------------------------------------------- DB

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, url)
);
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    response_ms INTEGER,
    has_ssl INTEGER,
    checked_at TEXT NOT NULL,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);
"""


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLE)
        await db.commit()


# ---------------------------------------------------------------- SSRF-защита

# Явно заблокированные сети (в дополнение к ipaddress.is_private/loopback)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),          # ULA
    ipaddress.ip_network("fe80::/10"),         # link-local v6
]


def _is_ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
       or ip.is_reserved or ip.is_unspecified:
        return True
    return any(ip in net for net in BLOCKED_NETWORKS)


def normalize_url(raw: str) -> str | None:
    """Возвращает нормализованный URL или None, если URL некорректен."""
    raw = raw.strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None
    # Отбрасываем нестандартные порты и userinfo — снижает риск SSRF/подмены
    return f"{parsed.scheme}://{parsed.hostname}"


async def is_url_safe(url: str) -> tuple[bool, str]:
    """Резолвит домен и проверяет, что ни один IP не является локальным/приватным."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False, "Не удалось выделить домен из URL."

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        return False, f"Не удалось разрешить домен: {host}"

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Некорректный IP от DNS: {ip_str}"
        if _is_ip_blocked(ip):
            return False, f"Домен резолвится в запрещённый IP ({ip})."

    return True, ""


# ---------------------------------------------------------------- HTTP проверка

async def check_site(session: aiohttp.ClientSession, url: str) -> dict:
    start = time.perf_counter()
    status_code: int | None = None
    has_ssl = int(urlparse(url).scheme == "https")
    error: str | None = None
    try:
        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            ssl=False,  # SSL проверяем фактом использования HTTPS-схемы
        ) as resp:
            status_code = resp.status
            await resp.read()
    except asyncio.TimeoutError:
        error = "Таймаут"
    except aiohttp.ClientConnectorCertificateError:
        error = "Ошибка SSL-сертификата"
        has_ssl = 0
    except aiohttp.ClientError as e:
        error = f"Сетевая ошибка: {type(e).__name__}"
    except Exception as e:  # noqa: BLE001
        error = f"Ошибка: {type(e).__name__}"

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return {
        "url": url,
        "status_code": status_code,
        "response_ms": elapsed_ms,
        "has_ssl": has_ssl,
        "error": error,
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------- FSM

class AddSite(StatesGroup):
    waiting_url = State()


# ---------------------------------------------------------------- Клавиатуры

def main_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="➕ Добавить сайт", callback_data="add_site")],
            [InlineKeyboardButton(text="📋 Мои сайты", callback_data="list_sites")],
            [InlineKeyboardButton(text="🔄 Проверить сейчас", callback_data="check_now")],
            [InlineKeyboardButton(text="📊 Скачать отчёт Excel", callback_data="report_excel")],
        ]
    )


def back_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="⬅️ В меню", callback_data="menu")]
        ]
    )


# ---------------------------------------------------------------- Роутер

router = Router()


@router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(
        "👋 <b>Привет!</b>\n\n"
        "Я помогу мониторить доступность ваших сайтов: проверяю HTTP-код, "
        "SSL и время отклика.\n\nВыберите действие:",
        reply_markup=main_menu_kb(),
    )


@router.callback_query(F.data == "menu")
async def cb_menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.message.edit_text(
        "Главное меню:",
        reply_markup=main_menu_kb(),
    )
    await callback.answer()


# ------------------------------------------------ Добавить сайт (FSM)

@router.callback_query(F.data == "add_site")
async def cb_add_site(callback: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(AddSite.waiting_url)
    await callback.message.edit_text(
        "🔗 Отправьте URL сайта (например, <code>https://example.com</code>).\n"
        "Или /cancel для отмены.",
    )
    await callback.answer()


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer("Отменено.", reply_markup=main_menu_kb())


@router.message(AddSite.waiting_url)
async def process_add_site(message: Message, state: FSMContext) -> None:
    url = normalize_url(message.text or "")
    if not url:
        await message.answer(
            "❌ Некорректный URL. Попробуйте ещё раз, например: <code>https://example.com</code>"
        )
        return

    safe, reason = await is_url_safe(url)
    if not safe:
        await message.answer(f"⛔ URL отклонён: {reason}")
        return

    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO sites (user_id, url, created_at) VALUES (?, ?, ?)",
                (message.from_user.id, url, datetime.now().isoformat(timespec="seconds")),
            )
            await db.commit()
        except aiosqlite.IntegrityError:
            await message.answer("ℹ️ Этот сайт уже есть в вашем списке.")
            await state.clear()
            await message.answer("Главное меню:", reply_markup=main_menu_kb())
            return

    await state.clear()
    await message.answer(
        f"✅ Сайт добавлен: <code>{url}</code>",
        reply_markup=main_menu_kb(),
    )


# ------------------------------------------------ Мои сайты

@router.callback_query(F.data == "list_sites")
async def cb_list_sites(callback: CallbackQuery) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id, url FROM sites WHERE user_id = ? ORDER BY id",
            (callback.from_user.id,),
        ) as cur:
            rows = await cur.fetchall()

    if not rows:
        await callback.message.edit_text(
            "📭 У вас пока нет добавленных сайтов.",
            reply_markup=back_kb(),
        )
        await callback.answer()
        return

    buttons = [
        [InlineKeyboardButton(text=f"❌ {url}", callback_data=f"del:{sid}")]
        for sid, url in rows
    ]
    buttons.append([InlineKeyboardButton(text="⬅️ В меню", callback_data="menu")])
    await callback.message.edit_text(
        "📋 <b>Ваши сайты</b>\nНажмите на сайт, чтобы удалить:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("del:"))
async def cb_delete_site(callback: CallbackQuery) -> None:
    try:
        site_id = int(callback.data.split(":", 1)[1])
    except (ValueError, IndexError):
        await callback.answer("Некорректный запрос", show_alert=True)
        return

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA foreign_keys = ON")
        cur = await db.execute(
            "DELETE FROM sites WHERE id = ? AND user_id = ?",
            (site_id, callback.from_user.id),
        )
        await db.commit()
        deleted = cur.rowcount

    if deleted:
        await callback.answer("Удалено ✅")
    else:
        await callback.answer("Сайт не найден", show_alert=True)
    await cb_list_sites(callback)


# ------------------------------------------------ Проверить сейчас

@router.callback_query(F.data == "check_now")
async def cb_check_now(callback: CallbackQuery) -> None:
    user_id = callback.from_user.id
    await callback.answer("Проверяю сайты…")

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id, url FROM sites WHERE user_id = ? ORDER BY id",
            (user_id,),
        ) as cur:
            rows = await cur.fetchall()

    if not rows:
        await callback.message.edit_text(
            "📭 Нет сайтов для проверки. Сначала добавьте сайт.",
            reply_markup=back_kb(),
        )
        return

    await callback.message.edit_text(
        f"🔄 Проверяю {len(rows)} сайт(ов)…\nЭто может занять до {HTTP_TIMEOUT} сек на сайт."
    )

    timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    results: list[dict] = []

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_site(session, url) for _sid, url in rows]
        results = await asyncio.gather(*tasks)

    # сохраняем историю
    now = datetime.now().isoformat(timespec="seconds")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            "INSERT INTO checks (site_id, user_id, url, status_code, response_ms, has_ssl, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (sid, user_id, r["url"], r["status_code"], r["response_ms"],
                 r["has_ssl"], r["checked_at"])
                for (sid, _url), r in zip(rows, results)
            ],
        )
        await db.commit()

    lines = ["📊 <b>Результаты проверки</b>\n"]
    for r in results:
        if r["error"]:
            status = f"❌ {r['error']}"
        else:
            status = f"<b>{r['status_code']}</b>"
        ssl_mark = "🔒 SSL" if r["has_ssl"] else "🔓 без SSL"
        lines.append(
            f"• <code>{r['url']}</code>\n"
            f"   Статус: {status} | ⏱ {r['response_ms']} мс | {ssl_mark}"
        )

    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:4000] + "\n…"

    await callback.message.edit_text(text, reply_markup=back_kb())


# ------------------------------------------------ Отчёт Excel

@router.callback_query(F.data == "report_excel")
async def cb_report_excel(callback: CallbackQuery) -> None:
    user_id = callback.from_user.id
    await callback.answer("Готовлю отчёт…")

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT url, status_code, response_ms, checked_at "
            "FROM checks WHERE user_id = ? ORDER BY checked_at DESC LIMIT 1000",
            (user_id,),
        ) as cur:
            rows = await cur.fetchall()

    if not rows:
        await callback.message.edit_text(
            "📭 Нет данных для отчёта. Сначала выполните проверку.",
            reply_markup=back_kb(),
        )
        return

    wb = Workbook()
    ws = wb.active
    ws.title = "Отчёт"
    ws.append(["URL", "Статус код", "Время отклика (мс)", "Дата проверки"])
    for url, code, ms, when in rows:
        ws.append([url, code if code is not None else "ошибка", ms, when])

    # автоширина столбцов
    for col in ws.columns:
        max_len = max((len(str(c.value)) for c in col if c.value is not None), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 60)

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    await callback.message.answer_document(
        BufferedInputFile(buf.getvalue(), filename=filename),
        caption="📊 Отчёт по проверкам сайтов",
    )


# ---------------------------------------------------------------- Запуск

async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN не задан в переменных окружения")

    await init_db()

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    log.info("Бот запущен")
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Бот остановлен")