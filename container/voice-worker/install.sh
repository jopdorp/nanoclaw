#!/bin/sh
# Installs the voice worker into /userdata/ai/voice on the Batocera box. Touches
# nothing outside /userdata, needs no compiler (wheels only). Safe to re-run.
set -eu
D=/userdata/ai/voice QT=${QWENTTS_DIR:-/userdata/ai/qwentts} Q=${QWENTTS_QUANT:-Q8_0}
PY=${PYTHON:-$(ls /userdata/*/venv*/bin/python3 /userdata/ai/*/venv/bin/python3 2>/dev/null | head -1)}
mkdir -p $D/hf
cp "$(dirname "$0")"/worker.py "$(dirname "$0")"/harness.py "$(dirname "$0")"/requirements.txt "$(dirname "$0")"/run.sh $D/
[ -x $D/venv/bin/python ] || "$PY" -m venv $D/venv
$D/venv/bin/pip install -q --only-binary=:all: -r $D/requirements.txt
HF_HOME=$D/hf $D/venv/bin/python -c "from faster_whisper import WhisperModel; WhisperModel('small', device='cpu', compute_type='int8')"
for f in qwen-talker-0.6b-customvoice-$Q qwen-talker-0.6b-base-$Q qwen-tokenizer-12hz-$Q; do
  [ -s $QT/models/$f.gguf ] || curl -fL -o $QT/models/$f.gguf.part https://huggingface.co/Serveurperso/Qwen3-TTS-GGUF/resolve/main/$f.gguf
  [ -f $QT/models/$f.gguf.part ] && mv $QT/models/$f.gguf.part $QT/models/$f.gguf
done
BIN=$(find $QT -name tts-server -type f -perm -u+x | head -1)
cat > $D/voice.env <<ENV
TTS_BIN=$BIN
LD_LIBRARY_PATH=$(dirname "$BIN"):$QT/lib
TTS_MODEL_CUSTOMVOICE=$QT/models/qwen-talker-0.6b-customvoice-$Q.gguf
TTS_MODEL_BASE=$QT/models/qwen-talker-0.6b-base-$Q.gguf
TTS_CODEC=$QT/models/qwen-tokenizer-12hz-$Q.gguf
HF_HOME=$D/hf
ENV
[ -f $D/host.env ] || printf 'VOICE_HOST_URLS=ws://192.168.1.11:30901,ws://192.168.1.12:30901,ws://192.168.1.13:30901,ws://192.168.1.17:30901\nVOICE_TOKEN=\n' > $D/host.env
chmod 600 $D/host.env
echo "installed; set VOICE_TOKEN in $D/host.env, then $D/run.sh start"
