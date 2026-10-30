from flask import Flask, request, jsonify
import json
import binascii
import requests
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import asyncio
import urllib3
import datetime
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import info_pb2
from byte import Encrypt_ID, encrypt_api

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==================== CONFIG ====================
OB_VERSION = "OB55"

# ==================== RANK MAP ====================

RANK_MAP = {
    309: "Master",
    321: "Grandmaster",
    307: "Heroic",
}

def ts_to_str(ts):
    if not ts:
        return None
    try:
        dt = datetime.datetime.utcfromtimestamp(int(ts))
        return dt.strftime("%d %b %Y at %I:%M:%S %p")
    except:
        return str(ts)

# ==================== FORMAT RESPONSE ====================

def format_response(data):
    p = data.get("basicInfo", {})
    captain = data.get("captainBasicInfo", {})
    guild = data.get("guildInfo", {})
    pet = data.get("petInfo", {})
    social = data.get("socialInfo", {})
    credit = data.get("creditScoreInfo", {})

    br_rank_name = RANK_MAP.get(p.get("brMaxRank"), "Unranked")
    leader_br_rank = RANK_MAP.get(guild.get("brMaxRank"), "Unranked")

    return {
        "ActivityInformation": {
            "BRPoints": p.get("brPoints"),
            "BRRank": br_rank_name,
            "CreatedAt": ts_to_str(p.get("createAt")),
            "CurrentBpBadges": p.get("bpBadges"),
            "LastLogin": ts_to_str(p.get("lastLogin")),
            "MostRecentOB": p.get("releaseVersion"),
            "ShowBRRank": "True" if p.get("showBrRank") else "False",
            "ShowCSRank": "True" if p.get("showCsRank") else "False"
        },
        "BasicInformation": {
            "Exp": p.get("exp"),
            "HonorScore": credit.get("creditScore"),
            "Level": p.get("level"),
            "Likes": p.get("likes"),
            "Name": p.get("nickname"),
            "Region": p.get("region"),
            "Signature": social.get("signature"),
            "Title": str(p.get("titleId")),
            "UID": str(p.get("uid"))
        },
        "GuildInformation": {
            "GuildID": str(captain.get("uid")),
            "GuildLevel": captain.get("guildLevel"),
            "GuildName": captain.get("nickname"),
            "LiveMembers": captain.get("liveMembers"),
            "MaxMembers": captain.get("maxMembers")
        },
        "LeaderInformation": {
            "BRPoints": guild.get("brPoints"),
            "BRRank": leader_br_rank,
            "BpBadges": guild.get("bpBadges"),
            "CreatedAt": ts_to_str(guild.get("createAt")),
            "LastLogin": ts_to_str(guild.get("lastLogin")),
            "Level": guild.get("level"),
            "MostRecentOB": guild.get("releaseVersion"),
            "Name": guild.get("guildName"),
            "Region": guild.get("region"),
            "Title": str(guild.get("titleId")),
            "UID": str(guild.get("guildId"))
        },
        "PetDetails": {
            "Equipped": "Yes" if pet.get("equipped") else "No",
            "PetExp": pet.get("petExp"),
            "PetLevel": pet.get("petLevel"),
            "PetSkill": str(pet.get("petSkill")),
            "PetSkin": str(pet.get("petSkin")),
            "PetType": str(pet.get("petType"))
        },
        "server_used": "IND",
        "status": "success"
    }

# ==================== VISIT ENCRYPTION ====================

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

# ==================== DECODE ====================

from google.protobuf import message_factory

def _expected_wire(field):
    """Proto field type -> wire type (0=varint, 1=64-bit, 2=length-delimited, 5=32-bit)"""
    t = field.type
    if t in (field.TYPE_DOUBLE, field.TYPE_FIXED64, field.TYPE_SFIXED64):
        return 1
    if t in (field.TYPE_FLOAT, field.TYPE_FIXED32, field.TYPE_SFIXED32):
        return 5
    if t in (field.TYPE_STRING, field.TYPE_BYTES, field.TYPE_MESSAGE, field.TYPE_GROUP):
        return 2
    return 0

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def _skip_field(buf, pos, wire):
    if wire == 0:
        _, pos = _read_varint(buf, pos)
        return pos
    if wire == 1:
        return pos + 8
    if wire == 5:
        return pos + 4
    if wire == 2:
        ln, pos = _read_varint(buf, pos)
        return pos + ln
    raise ValueError(f"bad wire type {wire}")

def _varint_bytes(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def _sanitize(buf, msg_desc, dropped, path=""):
    """Garena ke response me kuch fields aise aate hain jinpe strict protobuf
    parse pura fail ho jata hai — (1) schema se alag wire type, (2) nickname/
    signature me invalid UTF-8 bytes, (3) kisi sub-message ka corrupt payload.
    Ye function sirf unhi kharab fields ko hata kar baaki saara data bilkul
    same rakhta hai, taki parse chal jaye aur response mil jaye. Nested
    messages ke andar bhi recursively check hota hai."""
    out = bytearray()
    pos = 0
    fields = {f.number: f for f in msg_desc.fields}
    while pos < len(buf):
        start = pos
        try:
            tag, pos = _read_varint(buf, pos)
            num, wire = tag >> 3, tag & 7
            f = fields.get(num)
            if f is None:
                # unknown field — protobuf khud skip karta hai, as-is rakho
                pos = _skip_field(buf, pos, wire)
                out += buf[start:pos]
                continue
            exp = _expected_wire(f)
            packed_ok = f.is_repeated and exp == 0 and wire == 2  # repeated numeric packed form valid hai
            if wire != exp and not packed_ok:
                pos = _skip_field(buf, pos, wire)
                dropped.append(f"{path}{msg_desc.name}.{f.name} (field {num}: wire {wire}, expected {exp})")
                continue
            if wire == 2:
                ln, p2 = _read_varint(buf, pos)
                payload = bytes(buf[p2:p2 + ln])
                if len(payload) < ln:
                    dropped.append(f"{path}{msg_desc.name}.{f.name} (field {num}: truncated data)")
                    break
                if f.type == f.TYPE_STRING:
                    try:
                        payload.decode('utf-8')
                    except UnicodeDecodeError:
                        dropped.append(f"{path}{msg_desc.name}.{f.name} (field {num}: invalid UTF-8)")
                        pos = p2 + ln
                        continue
                if f.type == f.TYPE_MESSAGE:
                    clean = _sanitize(payload, f.message_type, dropped, path + msg_desc.name + ".")
                    try:
                        _cls = message_factory.GetMessageClass(f.message_type)
                        _m = _cls()
                        _m.ParseFromString(clean)
                    except Exception:
                        dropped.append(f"{path}{msg_desc.name}.{f.name} (field {num}: corrupt sub-message)")
                        pos = p2 + ln
                        continue
                    out += _varint_bytes(tag)
                    out += _varint_bytes(len(clean))
                    out += clean
                    pos = p2 + ln
                    continue
                pos = p2 + ln
                out += buf[start:pos]
                continue
            pos = _skip_field(buf, pos, wire)
            out += buf[start:pos]
        except Exception:
            # corrupt field — iske aage resync mushkil hai, jo data bachaya wahi rakho
            dropped.append(f"{path}{msg_desc.name}: corrupt field ke baad ka data chhoda gaya")
            break
    return bytes(out)

def decode_protobuf(binary):
    try:
        items = info_pb2.PlayerInfoResponse()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        print(f"PROTOBUF DECODE ERROR: {e} — tolerant decode try kar raha hu")
    # Tolerant path: kharab/mismatch fields hata kar dobara parse
    try:
        dropped = []
        clean = _sanitize(binary, info_pb2.PlayerInfoResponse.DESCRIPTOR, dropped)
        items = info_pb2.PlayerInfoResponse()
        items.ParseFromString(clean)
        if dropped:
            print("TOLERANT DECODE — ye fields kharab/mismatch the, drop kiye gaye:")
            for d in dropped:
                print("  -", d)
        return items
    except Exception as e:
        print(f"TOLERANT DECODE BHI FAIL: {e}")
        return None

# ==================== COMMON FUNCTIONS ====================

def load_tokens(region):
    try:
        region = region.upper()
        if region == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
            return tokens
        else:
            return None
    except:
        return None

def get_visit_url(region):
    region = region.upper()
    if region == "BD":
        return "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    else:
        return None

def get_spam_url(region):
    region = region.upper()
    if region == "BD":
        return "https://clientbp.ggpolarbear.com/RequestAddingFriend"
    else:
        return None

# ==================== VISIT FUNCTIONS ====================

async def make_visit_request_async(encrypt, region, token, session):
    try:
        url = get_visit_url(region)
        if not url:
            return None

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': OB_VERSION
        }

        async with session.post(url, data=edata, headers=headers, ssl=False, timeout=5) as response:
            if response.status != 200:
                return None
            hex_data = await response.read()
            binary = bytes.fromhex(hex_data.hex())
            decode = decode_protobuf(binary)
            return decode
    except:
        return None

# ==================== SPAM FUNCTIONS ====================

def send_spam_request(uid, token, region, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        url = get_spam_url(region)

        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": OB_VERSION,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Host": "clientbp.ggpolarbear.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }

        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False, timeout=5)

        if response.status_code == 200:
            results["success"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        print(f"Spam error: {e}")
        results["failed"] += 1

# ==================== API ENDPOINTS ====================

@app.route('/visit', methods=['GET'])
async def visit():
    """Visit endpoint - 100 successful visits using 100 tokens"""
    target_uid = request.args.get("uid")
    region = request.args.get("region", "BD").upper()

    if not target_uid:
        return jsonify({"error": "Target UID is required"}), 400

    if region != "BD":
        return jsonify({"error": "Only BD region is supported"}), 400

    try:
        tokens = load_tokens(region)
        if tokens is None or not tokens:
            return jsonify({"error": "No tokens available for BD region"}), 400

        if len(tokens) < 100:
            return jsonify({"error": f"Need at least 100 tokens. Only {len(tokens)} available"}), 400

        tokens_to_use = tokens[:100]

        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            return jsonify({"error": "Encryption of target UID failed"}), 400

        summary = {
            "SuccessfulVisits": 0,
            "FailedVisits": 0,
            "TotalRequests": 0,
            "PlayerNickname": None,
            "UID": None
        }

        async with aiohttp.ClientSession() as session:
            tasks = [
                make_visit_request_async(encrypted_target_uid, region, token['token'], session)
                for token in tokens_to_use
            ]
            results = await asyncio.gather(*tasks)

            for info in results:
                if info is not None:
                    if summary["PlayerNickname"] is None and summary["UID"] is None:
                        jsone = MessageToJson(info)
                        data_info = json.loads(jsone)
                        bi = data_info.get('basicInfo', {})
                        summary["PlayerNickname"] = str(bi.get('nickname', ''))
                        summary["UID"] = int(bi.get('uid', 0))
                    summary["SuccessfulVisits"] += 1
                else:
                    summary["FailedVisits"] += 1

            summary["TotalRequests"] = len(tokens_to_use)

        if summary["SuccessfulVisits"] < 100:
            return jsonify({
                "error": f"Only {summary['SuccessfulVisits']} successful visits achieved. Need 100.",
                "summary": summary
            }), 400

        return jsonify(summary)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/info', methods=['GET'])
def info():
    """Get full player info using a single token (decoded + formatted)"""
    uid = request.args.get("uid")
    region = request.args.get("region", "BD").upper()

    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    if region != "BD":
        return jsonify({"error": "Only BD region is supported"}), 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            return jsonify({"error": "No tokens found for BD region"}), 500

        token = tokens[0]['token'] if isinstance(tokens[0], dict) else tokens[0]

        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption of UID failed"}), 400

        url = get_visit_url(region)
        edata = bytes.fromhex(encrypted_uid)

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': OB_VERSION
        }

        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)

        if response.status_code != 200:
            return jsonify({
                "error": f"Request failed with status {response.status_code}",
                "status_code": response.status_code
            }), 400

        info_obj = decode_protobuf(response.content)
        if info_obj is None:
            return jsonify({
                "error": "Failed to decode protobuf response",
                "raw_hex": response.content.hex()
            }), 500

        jsone = MessageToJson(info_obj)
        data_info = json.loads(jsone)

        formatted = format_response(data_info)
        return jsonify(formatted)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/spam', methods=['GET'])
def spam():
    """Spam endpoint - 50 spam requests using 50 tokens"""
    uid = request.args.get("uid")
    region = request.args.get("region", "BD").upper()

    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    if region != "BD":
        return jsonify({"error": "Only BD region is supported"}), 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            return jsonify({"error": "No tokens found for BD region"}), 500

        if len(tokens) < 50:
            return jsonify({"error": f"Need at least 50 tokens. Only {len(tokens)} available"}), 400

        spam_tokens = tokens[:50]

        results = {"success": 0, "failed": 0}
        threads = []

        for token_data in spam_tokens:
            token = token_data['token'] if isinstance(token_data, dict) else token_data
            thread = threading.Thread(target=send_spam_request, args=(uid, token, region, results))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        total_requests = results["success"] + results["failed"]
        status = 1 if results["success"] > 0 else 2

        return jsonify({
            "success_count": results["success"],
            "failed_count": results["failed"],
            "total_requests": total_requests,
            "status": status
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)