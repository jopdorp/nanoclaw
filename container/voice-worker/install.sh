#!/bin/sh
# Installs the voice worker into /userdata/ai/voice on the Batocera box. Touches
# nothing outside it (qwentts is only read for its tts-server binary), needs no
# compiler (wheels only). Safe to re-run.
set -eu
D=/userdata/ai/voice QT=${QWENTTS_DIR:-/userdata/ai/qwentts} SRC=$(dirname "$0")
PY=${PYTHON:-$(ls /userdata/*/venv*/bin/python3 /userdata/ai/*/venv/bin/python3 2>/dev/null | head -1)}
mkdir -p $D/models/whisper-small
[ "$(cd "$SRC" && pwd)" = "$D" ] || cp "$SRC"/worker.py "$SRC"/harness.py "$SRC"/requirements.txt "$SRC"/run.sh $D/
[ -x $D/venv/bin/python ] || "$PY" -m venv $D/venv
$D/venv/bin/pip install -q --prefer-binary -r $D/requirements.txt
fetch() {  # repo@rev file sha256 dest
  [ -s "$4" ] && echo "$3  $4" | sha256sum -c >/dev/null 2>&1 && return
  curl -fsSL -o "$4.part" "https://huggingface.co/${1%@*}/resolve/${1#*@}/$2"
  echo "$3  $4.part" | sha256sum -c >/dev/null 2>&1 || { rm -f "$4.part"; echo "sha256 mismatch: $2" >&2; exit 1; }
  mv "$4.part" "$4"
}
TTS=Serveurperso/Qwen3-TTS-GGUF@b7ee2e8c7459c3bea99da23e3d178125a7d1713c
fetch $TTS qwen-talker-0.6b-customvoice-Q4_K_M.gguf b3a7e6613d80f8a703c06267fc1e94d48ce91932ab82ab6e31c50f4ca4868e1e $D/models/customvoice.gguf
fetch $TTS qwen-talker-0.6b-base-Q4_K_M.gguf 4b468ec7b1f62b90ef4ca316c0aa57deadfd54b2cf9651703ea753cedaf04226 $D/models/base.gguf
fetch $TTS qwen-tokenizer-12hz-Q4_K_M.gguf cf3788b4d50aaa665fb6e57c170396aae03a3555fea52d2b5d0cda902d658039 $D/models/codec.gguf
W=Systran/faster-whisper-small@536b0662742c02347bc0e980a01041f333bce120
fetch $W model.bin 3e305921506d8872816023e4c273e75d2419fb89b24da97b4fe7bce14170d671 $D/models/whisper-small/model.bin
fetch $W config.json b55496ac7940a7ae47d2c01eab40edfd8701feec1229d9cce3b40014383fb828 $D/models/whisper-small/config.json
fetch $W tokenizer.json fb7b63191e9bb045082c79fd742a3106a12c99513ab30df4a0d47fa6cb6fd0ab $D/models/whisper-small/tokenizer.json
fetch $W vocabulary.txt 34ce3fe1c5041027b3f8d42912270993f986dbc4bb34cf27f951e34a1e453913 $D/models/whisper-small/vocabulary.txt
BIN=$(find $QT -name tts-server -type f -perm -u+x | head -1)
cat > $D/voice.env <<ENV
TTS_BIN=$BIN
TTS_LD_LIBRARY_PATH=$(dirname "$BIN"):$QT/lib
TTS_MODEL_CUSTOMVOICE=$D/models/customvoice.gguf
TTS_MODEL_BASE=$D/models/base.gguf
TTS_CODEC=$D/models/codec.gguf
WHISPER_MODEL=$D/models/whisper-small
HF_HUB_OFFLINE=1
ENV
[ -f $D/host.env ] || (umask 077; printf 'VOICE_HOST_URLS=ws://192.168.1.11:30901,ws://192.168.1.12:30901,ws://192.168.1.13:30901,ws://192.168.1.17:30901\nVOICE_TOKEN=\n' > $D/host.env)
echo "installed; set VOICE_TOKEN in $D/host.env, then $D/run.sh start"
