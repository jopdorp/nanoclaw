"""Plays the host side against a local worker: one call in a throwaway LiveKit room.

  harness.py speech.wav [--e2ee]   (env LIVEKIT_URL, LIVEKIT_API_KEY, LIVEKIT_API_SECRET)

Starts the host WebSocket on :8765 (token "test"), joins as the caller, speaks
the wav, answers the first `heard` with a canned reply, then talks over the
second reply to check barge-in. Prints latencies, deletes the room.
"""
import asyncio, base64, json, os, sys, time, wave

import numpy as np, websockets
from livekit import api, rtc

ROOM, KEY = f"voice-test-{int(time.time())}", os.urandom(32)
REPLY = ["Sure, I can hear you fine.", "It is a nice day for a quick test call."]
LONG = ["Let me tell you a rather long story about a lighthouse keeper.", "Every night he climbed the stairs.",
        "He counted every one of them, all the way up.", "And then he counted them again on the way down."]


def token(identity: str) -> str:
    grant = api.VideoGrants(room_join=True, room=ROOM)
    return api.AccessToken().with_identity(identity).with_grants(grant).to_jwt()


async def main():
    wav = wave.open(sys.argv[1])
    speech = np.frombuffer(wav.readframes(wav.getnframes()), np.int16)
    rate, e2ee = wav.getframerate(), "--e2ee" in sys.argv
    t, events = {}, asyncio.Queue()
    src = rtc.AudioSource(rate, 1, queue_size_ms=50)
    room = rtc.Room()
    opts = rtc.RoomOptions()
    if e2ee:
        opts.encryption = rtc.E2EEOptions(key_provider_options=rtc.KeyProviderOptions(
            ratchet_window_size=10, key_ring_size=256, key_derivation_function=rtc.e2ee.proto_e2ee.KeyDerivationFunction.HKDF))

    async def hear(track):
        async for ev in rtc.AudioStream(track, sample_rate=24000, num_channels=1):
            loud = np.sqrt(np.mean(np.frombuffer(ev.frame.data, np.int16).astype(np.float32) ** 2)) > 300
            now = time.monotonic()
            if loud:
                t.setdefault("first_audio", now)
                t["last_loud"] = now

    room.on("track_subscribed", lambda track, *_: asyncio.ensure_future(hear(track)) if track.kind == rtc.TrackKind.KIND_AUDIO else None)
    lk = api.LiveKitAPI(os.environ["LIVEKIT_URL"].replace("wss://", "https://"))
    await lk.room.create_room(api.CreateRoomRequest(name=ROOM, empty_timeout=60))
    await room.connect(os.environ["LIVEKIT_URL"], token("jegor"), opts)
    if e2ee:
        for who in ("jegor", "persona"):
            room.e2ee_manager.key_provider.set_key(who, KEY, 0)
    await room.local_participant.publish_track(rtc.LocalAudioTrack.create_audio_track("mic", src))
    talking = asyncio.Event()

    async def mic():
        n, i = rate // 100, 0
        while True:
            chunk = speech[i:i + n] if talking.is_set() else np.zeros(n, np.int16)
            i = i + n if talking.is_set() else 0
            if talking.is_set() and i >= len(speech):
                talking.clear()
                t["speech_end"] = time.monotonic()
            await src.capture_frame(rtc.AudioFrame(np.pad(chunk, (0, n - len(chunk))).tobytes(), rate, 1, n))

    async def host(ws):
        assert ws.request.headers["Authorization"] == "Bearer test"
        voice = {"speaker": os.environ.get("TTS_SPEAKER", "serena"), "instruct": "Warm, relaxed and friendly."}
        start = {"type": "start", "callId": "c1", "livekitUrl": os.environ["LIVEKIT_URL"], "jwt": token("persona"),
                 "room": ROOM, "voice": voice}
        if e2ee:
            start["e2ee"] = {"keys": [{"participant": p, "index": 0, "key": base64.b64encode(KEY).decode()} for p in ("jegor", "persona")]}
        t["start"] = time.monotonic()
        await ws.send(json.dumps(start))
        async for raw in ws:
            await events.put(json.loads(raw))

    async def say(turn, sentences):
        await ws_conn.send(json.dumps({"type": "say", "callId": "c1", "turnId": turn, "chunk": " ".join(sentences), "final": True}))

    async def expect(kind):
        while (ev := await events.get())["type"] != kind:
            print("  event", ev)
        print("  event", ev)
        return ev

    connected = asyncio.get_running_loop().create_future()
    server = await websockets.serve(lambda ws: (connected.set_result(ws), host(ws))[1], "127.0.0.1", 8765)
    asyncio.ensure_future(mic())
    ws_conn = await connected
    while "persona" not in {p.identity for p in room.remote_participants.values()} or not room.remote_participants["persona"].track_publications:
        await asyncio.sleep(0.05)
    print(f"worker ready {time.monotonic() - t['start']:.2f} s after start")
    await asyncio.sleep(1)

    talking.set()
    await expect("heard")
    t["heard"] = time.monotonic()
    t.pop("first_audio", None)
    await say("r1", REPLY)
    await expect("played")
    print(f"speech end -> heard {t['heard'] - t['speech_end']:.2f} s, -> first audio {t['first_audio'] - t['speech_end']:.2f} s")

    await say("r2", LONG)
    while "first_audio" not in t or t["first_audio"] < t["heard"]:
        t.pop("first_audio", None)
        await asyncio.sleep(0.05)
    await asyncio.sleep(1.5)
    t["barge"] = time.monotonic()
    talking.set()
    await expect("bargein")
    print(f"bargein msg {time.monotonic() - t['barge']:.2f} s after talking over")
    await expect("played")
    await asyncio.sleep(2)
    print(f"persona audio stopped {t['last_loud'] - t['barge']:.2f} s after talking over")
    await expect("heard")
    await ws_conn.send(json.dumps({"type": "stop", "callId": "c1"}))
    await expect("ended")
    await room.disconnect()
    await lk.room.delete_room(api.DeleteRoomRequest(room=ROOM))
    print("test room still listed:", ROOM in [r.name for r in (await lk.room.list_rooms(api.ListRoomsRequest())).rooms])
    await lk.aclose()
    server.close()


asyncio.run(main())
