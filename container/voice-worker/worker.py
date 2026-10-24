"""Voice worker: the audio half of a call between Jegor and a nanoclaw persona.

The host owns everything else (Matrix, the persona session, memory). It hands
this worker a LiveKit URL + JWT over one authenticated WebSocket, the worker
joins the room, turns Jegor's speech into `heard` text (Silero VAD + Smart Turn
+ faster-whisper on CPU) and speaks the host's `say` chunks with qwentts.cpp's
tts-server on the GPU. The tts-server is spawned per call so VRAM is only held
while a call is up. `played.upTo` counts characters of the turn's text that
were spoken before the turn ended or was cut off.

The same process serves POST /transcribe on :8190 for voice messages. The
whisper model loads on first use and is dropped after 5 idle minutes because
the box has no swap.
"""
import asyncio, base64, contextlib, gc, io, json, logging, os, re, sys, threading, time

import aiohttp, av, numpy as np, websockets
from aiohttp import web
from faster_whisper import WhisperModel, decode_audio
from livekit import rtc
from pipecat.audio.turn.base_turn_analyzer import EndOfTurnState
from pipecat.audio.turn.smart_turn.local_smart_turn_v3 import LocalSmartTurnAnalyzerV3
from pipecat.audio.vad.silero import SileroVADAnalyzer
from pipecat.audio.vad.vad_analyzer import VADParams, VADState

env = os.environ.get
TTS_URL = f"http://127.0.0.1:{env('TTS_PORT', '8191')}"
ALLOW = set(env("TRANSCRIBE_ALLOW", "127.0.0.1,192.168.1.11,192.168.1.12,192.168.1.13,192.168.1.17").split(","))
IN_RATE, OUT_RATE, FRAME = 16000, 24000, 480  # FRAME = 20 ms at OUT_RATE
log = logging.getLogger("voice")
TOKEN = os.environ.pop("VOICE_TOKEN", "")  # keep it out of the tts-server's environment
PDEATH = [sys.executable, "-I", "-c", "import ctypes,os,signal,sys; ctypes.CDLL(None).prctl(1, signal.SIGKILL); os.execv(sys.argv[1], sys.argv[1:])"]
calls: dict[str, "Call"] = {}
_whisper, _used, _lock, _transcribing = None, 0.0, threading.Lock(), asyncio.Semaphore(1)


async def unload_idle_whisper():
    global _whisper
    while True:
        await asyncio.sleep(30)
        if _whisper and not calls and time.monotonic() - _used > 300:
            with _lock:
                _whisper = None
            gc.collect()


def b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))


def text_of(audio, language=None) -> tuple[str, str]:
    global _whisper, _used
    with _lock:
        if _whisper is None:
            _whisper = WhisperModel(env("WHISPER_MODEL", "small"), device="cpu", compute_type="int8", cpu_threads=4)
        model = _whisper
    try:
        segs, info = model.transcribe(audio, language=language, beam_size=1, condition_on_previous_text=False, without_timestamps=True)
        return " ".join(s.text.strip() for s in segs).strip(), info.language
    finally:
        _used = time.monotonic()


def decode_short(data: bytes) -> np.ndarray:
    with av.open(io.BytesIO(data)) as c:  # check the length before decoding: a tiny opus file can be hours of PCM
        if not 0 < (c.duration or 0) <= 61_000_000:
            raise ValueError("audio must be under 60 s")
    return decode_audio(io.BytesIO(data))[:60 * IN_RATE]


async def transcribe_http(req: web.Request) -> web.Response:
    if req.remote not in ALLOW:
        raise web.HTTPForbidden()
    data = await req.read()
    async with _transcribing:
        try:
            audio = await asyncio.to_thread(decode_short, data)
        except (ValueError, av.error.FFmpegError) as e:
            raise web.HTTPBadRequest(text=str(e))
        text, lang = await asyncio.to_thread(text_of, audio)
    return web.json_response({"text": text, "language": lang})


class Call:
    def __init__(self, send, msg: dict):
        self.send, self.id, self.msg = send, msg["callId"], msg
        voice = msg.get("voice") or {}
        self.speaker = voice.get("speaker") or ("ref" if voice.get("ref") else env("TTS_SPEAKER", "serena"))
        self.instruct = None if voice.get("ref") else voice.get("instruct")  # base (clone) models reject instructions
        self.room, self.source = rtc.Room(), rtc.AudioSource(OUT_RATE, 1, queue_size_ms=200)
        self.tts, self.http, self.turn, self.upto, self.dropped, self.heard_n = None, None, None, 0, set(), 0
        self.texts, self.pcm, self.workers, self.listener, self.starting = asyncio.Queue(), asyncio.Queue(), [], None, None
        self.keys, self.stopping = list((msg.get("e2ee") or {}).get("keys", [])), False

    async def emit(self, kind: str, **kw):
        await self.send(json.dumps({"type": kind, "callId": self.id, **kw}))

    async def start(self):
        voice = self.msg.get("voice") or {}
        mode = "base" if voice.get("ref") else "customvoice"
        self.tts = await asyncio.create_subprocess_exec(  # PDEATH: the tts-server dies with us, never orphaning VRAM
            *PDEATH, os.environ["TTS_BIN"], "--model", os.environ[f"TTS_MODEL_{mode.upper()}"], "--codec", os.environ["TTS_CODEC"],
            "--host", "127.0.0.1", "--port", TTS_URL.rsplit(":", 1)[1], "--lang", "English",
            env={**os.environ, "LD_LIBRARY_PATH": env("TTS_LD_LIBRARY_PATH", "")})
        self.http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_connect=5))
        self.vad, self.eot = SileroVADAnalyzer(params=VADParams(stop_secs=0.2)), LocalSmartTurnAnalyzerV3()
        self.vad.set_sample_rate(IN_RATE)
        self.eot.set_sample_rate(IN_RATE)
        await asyncio.wait_for(self.tts_ready(), 60)
        if voice.get("ref"):
            wav = open(voice["ref"], "rb").read()  # a path on this box: host messages are capped at 64 KiB
            body = {"name": "ref", "wav_b64": base64.b64encode(wav).decode(), "ref_text": voice.get("refText", "")}
            async with self.http.post(f"{TTS_URL}/v1/audio/voices", json=body) as r:
                r.raise_for_status()
        await asyncio.gather(self.warm_up(), asyncio.to_thread(text_of, np.zeros(IN_RATE, np.float32), "en"))
        e2ee, opts = self.msg.get("e2ee"), rtc.RoomOptions(auto_subscribe=True)
        if e2ee is not None:  # Element Call keys are raw per-participant bytes, derived with HKDF like livekit-client
            opts.encryption = rtc.E2EEOptions(key_provider_options=rtc.KeyProviderOptions(
                ratchet_window_size=10, key_ring_size=256, key_derivation_function=rtc.e2ee.proto_e2ee.KeyDerivationFunction.HKDF))
        self.room.on("track_subscribed", self.on_track)
        self.room.on("disconnected", lambda *_: asyncio.ensure_future(self.stop("disconnected")))
        await self.room.connect(self.msg["livekitUrl"], self.msg["jwt"], opts)
        for k in self.keys:
            self.apply_key(k)
        track = rtc.LocalAudioTrack.create_audio_track("voice", self.source)
        await self.room.local_participant.publish_track(track, rtc.TrackPublishOptions(source=rtc.TrackSource.SOURCE_MICROPHONE))
        self.workers = [asyncio.create_task(self.synth_loop()), asyncio.create_task(self.play_loop())]
        log.info("call %s up in %s", self.id, self.room.name)

    async def warm_up(self):  # the first synthesis after load is twice as slow
        async for _ in self.synth("Hi.", None):
            pass

    async def tts_ready(self):
        while self.tts.returncode is None:
            with contextlib.suppress(aiohttp.ClientError):
                async with self.http.get(f"{TTS_URL}/health") as r:
                    if r.status == 200:
                        return
            await asyncio.sleep(0.2)
        raise RuntimeError("tts-server exited")

    def started(self, task: asyncio.Task):
        if not task.cancelled() and task.exception():
            log.warning("call start failed: %r", task.exception())
            asyncio.ensure_future(self.stop("error: start failed"))

    def set_key(self, k: dict):
        if self.msg.get("e2ee") is None:
            return log.warning("keys for an unencrypted call ignored")
        self.keys.append(k)
        if self.room.isconnected():
            self.apply_key(k)

    def apply_key(self, k: dict):
        self.room.e2ee_manager.key_provider.set_key(k["participant"], b64(k["key"]), int(k.get("index", 0)))

    def on_track(self, track, pub, participant):  # a 1:1 call: the newest remote audio track is Jegor's
        if track.kind == rtc.TrackKind.KIND_AUDIO:
            if self.listener:
                self.listener.cancel()
            self.listener = asyncio.create_task(self.listen(rtc.AudioStream(track, sample_rate=IN_RATE, num_channels=1)))

    async def listen(self, stream: rtc.AudioStream):
        vad, turn = self.vad, self.eot
        turn.clear()
        utter, preroll, prev = bytearray(), [], VADState.QUIET
        async for ev in stream:
            pcm = bytes(ev.frame.data)
            state = await vad.analyze_audio(pcm)
            if state == VADState.SPEAKING and not utter:
                utter.extend(b"".join(preroll))
                if self.turn is not None:
                    await self.interrupt(bargein=True)
            if utter:
                utter.extend(pcm)
            else:
                preroll = (preroll + [pcm])[-50:]
            done = turn.append_audio(pcm, state in (VADState.STARTING, VADState.SPEAKING)) == EndOfTurnState.COMPLETE
            if state == VADState.QUIET and prev in (VADState.SPEAKING, VADState.STOPPING):
                done = done or (await turn.analyze_end_of_turn())[0] == EndOfTurnState.COMPLETE
            prev = state
            if len(utter) >= 30 * IN_RATE * 2:  # force-end a 30 s monologue
                done = True
                turn.clear()
            if done and utter:
                t0, audio = time.monotonic(), np.frombuffer(bytes(utter), np.int16).astype(np.float32) / 32768
                utter.clear()
                text, _ = await asyncio.to_thread(text_of, audio, "en")
                log.info("heard %.1f s in %.0f ms", len(audio) / IN_RATE, (time.monotonic() - t0) * 1000)
                if text:
                    self.heard_n += 1
                    await self.emit("heard", turnId=f"u{self.heard_n}", text=text[:2000], emotion=None, final=True)

    async def synth(self, text: str, style: str | None):
        body = {"input": text, "voice": self.speaker, "language": "English", "response_format": "pcm"}
        if self.speaker != "ref" and (style or self.instruct):
            body["instructions"] = style or self.instruct
        async with self.http.post(f"{TTS_URL}/v1/audio/speech", json=body) as r:
            r.raise_for_status()
            async for chunk in r.content.iter_any():
                yield chunk

    async def synth_loop(self):
        while True:
            turn, chunk, style, final = await self.texts.get()
            buf = b""
            if chunk.strip():
                async for data in self.synth(chunk, style):
                    buf += data
                    cut = len(buf) - len(buf) % (FRAME * 2)
                    if cut:
                        self.pcm.put_nowait(buf[:cut])
                        buf = buf[cut:]
            if buf:
                self.pcm.put_nowait(buf + b"\0" * (FRAME * 2 - len(buf)))
            self.pcm.put_nowait((turn, len(chunk), final))

    async def play_loop(self):
        while True:
            item = await self.pcm.get()
            if isinstance(item, tuple):
                turn, n, final = item
                self.upto += n
                if final:
                    await self.source.wait_for_playout()
                    await self.emit("played", turnId=turn, upTo=self.upto)
                    if self.turn == turn:
                        self.turn, self.upto = None, 0
                continue
            for i in range(0, len(item), FRAME * 2):
                await self.source.capture_frame(rtc.AudioFrame(item[i:i + FRAME * 2], OUT_RATE, 1, FRAME))

    async def say(self, msg: dict):
        if msg["turnId"] in self.dropped:
            return
        if self.turn != msg["turnId"]:
            self.turn, self.upto = msg["turnId"], 0
        parts = re.findall(r".+?(?:[.!?…]+\s+|$)", msg.get("chunk", ""), re.S) or [""]  # per sentence: finer upTo, earlier audio
        for i, part in enumerate(parts):
            self.texts.put_nowait((msg["turnId"], part, msg.get("style"), msg.get("final", False) and i == len(parts) - 1))

    async def interrupt(self, bargein=False):
        turn, upto = self.turn, self.upto
        for t in self.workers:
            t.cancel()
        self.source.clear_queue()
        self.texts, self.pcm, self.turn, self.upto = asyncio.Queue(), asyncio.Queue(), None, 0
        self.workers = [asyncio.create_task(self.synth_loop()), asyncio.create_task(self.play_loop())]
        self.dropped.add(turn)
        if bargein:
            await self.emit("bargein", turnId=turn)
        await self.emit("played", turnId=turn, upTo=upto)

    async def stop(self, reason: str):
        if self.stopping:
            return
        self.stopping = True
        try:
            for t in [self.starting, *self.workers, self.listener]:
                if t:
                    t.cancel()
            await self.room.disconnect()
            await self.source.aclose()
            if self.http:
                await self.http.close()
        except Exception as e:
            log.warning("stop: %r", e)
        finally:
            if self.tts and self.tts.returncode is None:
                self.tts.terminate()
                try:
                    await asyncio.wait_for(self.tts.wait(), 10)
                except asyncio.TimeoutError:
                    self.tts.kill()
                    await self.tts.wait()
            calls.pop(self.id, None)  # only now: a new call must find port 8191 free
            with contextlib.suppress(Exception):
                await self.emit("ended", reason=reason)


async def serve_host():
    urls, delay = os.environ["VOICE_HOST_URLS"].split(","), 1
    while True:
        for url in urls:  # only the node running the orchestrator answers
            try:
                async with websockets.connect(url, additional_headers={"Authorization": f"Bearer {TOKEN}"},
                                              open_timeout=3, max_size=64 * 1024) as ws:
                    log.info("connected to %s", url)
                    delay = 1
                    async for raw in ws:
                        await handle(ws, raw)
            except (OSError, asyncio.TimeoutError, websockets.WebSocketException) as e:
                log.warning("%s: %s", url, type(e).__name__)
            for call in list(calls.values()):
                await call.stop("host gone")
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30)


async def handle(ws, raw):
    try:
        msg = json.loads(raw)
        kind, call = msg.get("type"), calls.get(msg.get("callId"))
    except (ValueError, AttributeError):
        return log.warning("malformed message ignored")
    try:
        if kind == "start" and calls:
            await ws.send(json.dumps({"type": "ended", "callId": msg["callId"], "reason": "busy"}))
        elif kind == "start":
            calls[msg["callId"]] = call = Call(ws.send, msg)
            call.starting = asyncio.create_task(call.start())
            call.starting.add_done_callback(call.started)
        elif call is None:
            log.warning("no call for %s", kind)
        elif kind == "say":
            await call.say(msg)
        elif kind == "cancel" and msg.get("turnId") is not None and msg.get("turnId") == call.turn:
            await call.interrupt()
        elif kind == "keys":
            call.set_key(msg)
        elif kind == "stop":
            await call.stop("stopped")
    except Exception as e:
        log.warning("%s ignored: %r", kind, e)


async def main():
    app = web.Application(client_max_size=12 * 1024 * 1024)
    app.router.add_post("/transcribe", transcribe_http)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", int(env("TRANSCRIBE_PORT", "8190"))).start()
    await asyncio.gather(serve_host(), unload_idle_whisper())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(main())
