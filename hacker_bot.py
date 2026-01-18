import os, sys, time, ssl, socket, random, json
from urllib.request import urlopen

# ================== CORES ==================
G="\033[1;32m"; R="\033[1;31m"; C="\033[1;36m"
Y="\033[1;33m"; W="\033[1;37m"; X="\033[0m"

PORTS = [80, 443, 8080, 8443]

# ================== UTIL ==================
def clear(): os.system("clear")

def slow(t, d=0.01):
    for c in t:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(d)
    print()

# ================== VISUAL DARK ==================
def dark_intro():
    for _ in range(6):
        clear()
        print(random.choice([
            R+"⚡ SYSTEM OVERRIDE ⚡"+X,
            Y+"☠ DARK CORE ACCESS ☠"+X,
            C+"//// HACKER ENGINE LOADING ////"+X
        ]))
        time.sleep(0.15)

def banner():
    dark_intro()
    print(R+"""
██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
███████║███████║██║     █████╔╝ █████╗  ██████╔╝
██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""+X)
    slow(C+"HACKER BOT – DARK CORE")
    slow("CRIADOR: EDVALDO MORENO")
    slow("CONTATO: 958747761")
    print(W+"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"+X)

def menu():
    print(C+"[1] Scanner SNI / TLS"+X)
    print(C+"[2] DNS + SNI Finder"+X)
    print(C+"[3] Gerar Config HTTP Injector"+X)
    print(C+"[5] 😈 MODO HACKER REAL"+X)
    print(R+"[6] 🤖 AUTO SCAN INTELIGENTE"+X)
    print(Y+"[0] Sair"+X)
    print(W+"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"+X)

# ================== CORE ==================
def get_sni(ip, port):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(
            socket.create_connection((ip,port),3),
            server_hostname=ip
        )
        cert = s.getpeercert()
        s.close()
        return [n for t,n in cert.get("subjectAltName",[]) if t=="DNS"]
    except:
        return []

def proxycheck(ip):
    try:
        data = json.loads(
            urlopen(f"http://proxycheck.io/v3/{ip}?vpn=1", timeout=5)
            .read().decode()
        )
        return data.get(ip)
    except:
        return None

# ================== EXPORT ==================
def export_config(cfg):
    ts = int(time.time())
    txt_name = f"HI_CONFIG_{cfg['ip']}_{ts}.txt"

    payload = f"""GET / HTTP/1.1
Host: {cfg['sni']}
Upgrade: websocket
Connection: Upgrade

"""

    with open(txt_name,"w") as f:
        f.write(f"""
# HACKER BOT – HTTP Injector Config
# Generated automatically

IP       : {cfg['ip']}
PORT     : {cfg['port']}
METHOD   : {cfg['method']}
SNI/HOST : {cfg['sni']}

PAYLOAD:
{payload}
""")

    print(G+"✔ CONFIG EXPORTADA COM SUCESSO"+X)
    print(C+"Arquivo:", txt_name+X)
    print(Y+"Use no HTTP Injector (colar/importar manualmente)"+X)

# ================== OPÇÕES ==================
def scan_sni():
    clear()
    host=input("Host/SNI: ")
    try:
        s=ssl.create_default_context().wrap_socket(
            socket.create_connection((host,443),5),
            server_hostname=host
        )
        print(G+"TLS:",s.version())
        s.close()
    except Exception as e:
        print(R+"Erro:",e)
    input("\nENTER...")

def dns_sni():
    clear()
    target=input("Domínio/IP: ")
    try:
        ip=socket.gethostbyname(target)
        print(G+"IP:",ip)
        snis=get_sni(ip,443)
        print(Y+"SNIs:")
        for s in snis:
            print(" -",s)
    except:
        print(R+"Falha DNS/TLS")
    input("\nENTER...")

def manual_generator():
    clear()
    ip=input("IP: ")
    port=input("Porta: ")
    sni=input("SNI/Host: ")
    method=input("Método (HTTP/WS/TLS+WS): ")

    cfg={
        "ip":ip,
        "port":port,
        "sni":sni,
        "method":method
    }
    export_config(cfg)
    input("\nENTER...")

# ================== AUTO SCAN – OPÇÃO 6 ==================
def auto_scan():
    clear()
    target=input("IP ou Domínio: ")
    try:
        ip=socket.gethostbyname(target)
    except:
        print(R+"IP inválido")
        input("ENTER...")
        return

    print(Y+"\nALVO:",ip+X)

    info=proxycheck(ip)
    if info:
        print(C+f"ISP: {info.get('provider')} | País: {info.get('country')} | Proxy: {info.get('proxy')}"+X)

    best=None

    for port in PORTS:
        try:
            socket.create_connection((ip,port),2).close()
            if port in [443,8443]:
                snis=get_sni(ip,port)
                if snis:
                    best={
                        "ip":ip,
                        "port":port,
                        "sni":snis[0],
                        "method":"TLS + WebSocket"
                    }
                    break
            else:
                best={
                    "ip":ip,
                    "port":port,
                    "sni":target,
                    "method":"HTTP / WebSocket"
                }
        except:
            pass

    if not best:
        print(R+"Nenhuma configuração válida encontrada")
        input("ENTER...")
        return

    print(G+"\n✔ MELHOR CONFIG DETECTADA"+X)
    for k,v in best.items():
        print(C+f"{k.upper()}: {v}"+X)

    export_config(best)
    input("\nENTER...")

# ================== MODO HACKER REAL ==================
def hacker_mode():
    clear()
    slow(R+"⚠ MODO HACKER REAL ⚠")
    pwd=input(Y+"Senha: "+X)
    if pwd!="BERYON":
        slow(R+"ACESSO NEGADO")
        time.sleep(2)
        return

    slow(G+"ACESSO AUTORIZADO")
    slow(C+"DARK CORE ATIVO")

    auto_scan()

# ================== LOOP ==================
while True:
    banner()
    menu()
    op=input("➜ ")

    if op=="1": scan_sni()
    elif op=="2": dns_sni()
    elif op=="3": manual_generator()
    elif op=="5": hacker_mode()
    elif op=="6": auto_scan()
    elif op=="0":
        slow(R+"Encerrando sistema...")
        break
    else:
        slow(Y+"Opção inválida")
