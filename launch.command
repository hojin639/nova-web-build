#!/bin/bash
# NOVA Web — macOS launcher
# 더블클릭하면 자동으로 설치 + 실행됩니다.
cd "$(dirname "$0")"

echo "==============================="
echo "  NOVA Web - macOS Launcher"
echo "==============================="

# Python 확인
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3이 설치되어 있지 않습니다."
    echo "https://www.python.org/downloads/ 에서 설치해주세요."
    read -p "아무 키나 누르세요..."
    exit 1
fi

# venv 생성 (최초 1회)
if [ ! -d "venv" ]; then
    echo "[*] 가상환경 생성 중..."
    python3 -m venv venv
fi

source venv/bin/activate

# 패키지 설치 (최초 1회)
if [ ! -f "venv/.installed" ]; then
    echo "[*] 패키지 설치 중..."
    pip install -r requirements.txt
    touch venv/.installed
fi

echo "[*] NOVA Web 시작..."
echo "[*] 브라우저에서 http://127.0.0.1:5000 이 열립니다."
echo ""
python3 run.py
