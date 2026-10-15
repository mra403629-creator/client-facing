"""Direct MT5 Manager check: kya server asli groups de raha hai?

Run (project root, gateway ko pehle Ctrl+C se band karo):
    python check_groups.py

Sirf group NAAM print hote hain. Koi password / login print nahi hota.
"""
import os

import MT5Manager as M
from dotenv import load_dotenv

load_dotenv()

server = os.getenv("MT5_SERVER")
login = int(os.getenv("MT5_LOGIN", "0") or 0)
password = os.getenv("MT5_PASSWORD")
if not (server and login and password):
    raise SystemExit(".env me MT5_SERVER / MT5_LOGIN / MT5_PASSWORD bharo")

modes = M.ManagerAPI.EnPumpModes
mode = int(modes.PUMP_MODE_USERS) | int(modes.PUMP_MODE_GROUPS)

m = M.ManagerAPI()
print("connecting...", flush=True)
if not m.Connect(server, login, password, mode, 120000):
    raise SystemExit(f"Connect FAIL: {M.LastError()}")
print("connected OK")

try:
    print("Group methods in SDK:", sorted(x for x in dir(m) if x.startswith("Group")))

    total = m.GroupTotal()
    print("GroupTotal() =", total)
    names = []
    if total and total is not False:
        for i in range(int(total)):
            g = m.GroupNext(i)
            if g is not False and g is not None:
                names.append(g.Group)
    print(f"\n[1] Config groups from GroupNext: {len(names)}")
    for n in names[:60]:
        print("   ", n)
    if len(names) > 60:
        print("    ... aur", len(names) - 60)

    users = m.UserGetByGroup("*")
    if users is False or users is None:
        print("\n[2] UserGetByGroup('*') FAIL:", M.LastError())
    else:
        used = sorted({u.Group for u in users})
        print(f"\n[2] Users on server: {len(users)}, groups jinme users hain: {len(used)}")
        for n in used[:60]:
            print("   ", n)
finally:
    m.Disconnect()