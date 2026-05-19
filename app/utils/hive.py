import httpx

from typing import Optional

HIVE_API_KEY = str()

SIGHTENGINE_USER = str()

SIGHTENGINE_SECRET = str()

def set_key(key):
    global HIVE_API_KEY
    HIVE_API_KEY = key

def set_sightengine(user, secret):
    global SIGHTENGINE_USER, SIGHTENGINE_SECRET
    SIGHTENGINE_USER = user
    SIGHTENGINE_SECRET = secret

async def detect_ai_image(image_bytes, mime_type="image/jpeg"):
    if not SIGHTENGINE_USER:
        return None
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post("https://api.sightengine.com/1.0/check.json",data={"models":"genai","api_user":SIGHTENGINE_USER,"api_secret":SIGHTENGINE_SECRET},files={"media":("image.jpg",image_bytes,"image/jpeg")})
            if resp.status_code != 200:
                return None
            d = resp.json()
            print("Sightengine image:", d)
            return float(d.get("type",{}).get("ai_generated",0) or 0)
    except Exception as e:
        print("Sightengine image error:", e)
        return None

async def detect_ai_audio(audio_bytes):
    if not SIGHTENGINE_USER:
        return None
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post("https://api.sightengine.com/1.0/audio/check.json",data={"models":"genai","api_user":SIGHTENGINE_USER,"api_secret":SIGHTENGINE_SECRET},files={"media":("audio.mp3",audio_bytes,"audio/mpeg")})
            if resp.status_code != 200:
                print("Sightengine audio error:", resp.text)
                return None
            d = resp.json()
            print("Sightengine audio:", d)
            return float(d.get("type",{}).get("ai_generated",0) or 0)
    except Exception as e:
        print("Sightengine audio error:", e)
        return None