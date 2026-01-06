import socket, threading, json, base64
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from queue import Queue

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ===================== CRYPTO =====================

def gen_rsa():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

def pub_pem(pub):
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_pub(pem):
    return serialization.load_pem_public_key(pem)

def rsa_encrypt(data, pub):
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ct, priv):
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign(data, priv):
    return priv.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify(data, sig, pub):
    try:
        pub.verify(
            sig, data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def gen_aes():
    return get_random_bytes(32)

def aes_enc(msg, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(msg, 16))

def aes_dec(iv, ct, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16)


# ===================== NETWORK =====================

def pack(obj):
    raw = json.dumps(obj).encode()
    return len(raw).to_bytes(4, 'big') + raw

def recv_exact(sock, n):
    d = b''
    while len(d) < n:
        p = sock.recv(n - len(d))
        if not p:
            raise ConnectionError
        d += p
    return d

def recv(sock):
    size = int.from_bytes(recv_exact(sock, 4), 'big')
    return json.loads(recv_exact(sock, size).decode())


# ===================== APP =====================

class SecureChat(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Messagerie sécurisée – Démonstration cryptographique")
        self.geometry("950x700")

        self.queue = Queue()

        # ---- Crypto ----
        self.priv, self.pub = gen_rsa()
        self.peer_pub = None
        self.aes = None

        self._ui()

        self._log("[1] Clé RSA locale générée :")
        self._log(pub_pem(self.pub).decode())

        self.after(100, self._process)

    # ================= UI =================
    def _ui(self):
        top = ttk.Frame(self)
        top.pack(fill='x', padx=8, pady=5)

        self.mode = tk.StringVar(value="Host")
        ttk.OptionMenu(top, self.mode, "Host", "Host", "Client").pack(side='left')

        self.host = ttk.Entry(top, width=15)
        self.host.insert(0, "0.0.0.0")
        self.host.pack(side='left', padx=5)

        self.port = ttk.Entry(top, width=6)
        self.port.insert(0, "5000")
        self.port.pack(side='left')

        ttk.Button(top, text="Start", command=self.start).pack(side='left', padx=5)

        self.logbox = scrolledtext.ScrolledText(self, height=35)
        self.logbox.pack(fill='both', expand=True, padx=8, pady=6)

        self.entry = ttk.Entry(self)
        self.entry.pack(fill='x', padx=8)

        ttk.Button(self, text="Envoyer", command=self.send).pack(pady=5)

    def _log(self, txt):
        self.queue.put(txt + "\n")

    def _process(self):
        while not self.queue.empty():
            self.logbox.insert('end', self.queue.get())
            self.logbox.see('end')
        self.after(100, self._process)

    # ================= NETWORK =================
    def start(self):
        threading.Thread(
            target=self._server if self.mode.get() == "Host" else self._client,
            daemon=True
        ).start()

    def _server(self):
        self._log("[2] En attente de connexion...")
        s = socket.socket()
        s.bind((self.host.get(), int(self.port.get())))
        s.listen(1)
        self.conn, _ = s.accept()
        self._connected()

    def _client(self):
        self.conn = socket.socket()
        self.conn.connect((self.host.get(), int(self.port.get())))
        self._connected()

    def _connected(self):
        self._log("[3] Connexion établie")

        self.conn.sendall(pack({
            "type": "PUB",
            "data": base64.b64encode(pub_pem(self.pub)).decode()
        }))
        self._log("[4] Clé publique envoyée :")
        self._log(pub_pem(self.pub).decode())

        threading.Thread(target=self._recv, daemon=True).start()

    def _recv(self):
        while True:
            m = recv(self.conn)

            # ----- RSA PUB -----
            if m["type"] == "PUB":
                self.peer_pub = load_pub(base64.b64decode(m["data"]))
                self._log("[5] Clé publique du pair reçue :")
                self._log(pub_pem(self.peer_pub).decode())

                if self.mode.get() == "Client":
                    self.aes = gen_aes()
                    enc = rsa_encrypt(self.aes, self.peer_pub)
                    self.conn.sendall(pack({
                        "type": "AES",
                        "data": base64.b64encode(enc).decode()
                    }))
                    self._log("[6] Clé AES générée (client) :")
                    self._log("    AES (hex) : " + self.aes.hex())
                    self._log("    AES chiffrée avec RSA et envoyée")

            # ----- AES -----
            elif m["type"] == "AES":
                enc = base64.b64decode(m["data"])
                self._log("[6] Clé AES reçue (RSA chiffrée)")
                self.aes = rsa_decrypt(enc, self.priv)
                self._log("    AES déchiffrée : " + self.aes.hex())
                self._log("[7]  Canal sécurisé établi")

            # ----- MESSAGE -----
            elif m["type"] == "MSG":
                iv = base64.b64decode(m["iv"])
                ct = base64.b64decode(m["ct"])
                sig = base64.b64decode(m["sig"])

                self._log("[MSG-5] Message chiffré reçu :")
                self._log("    " + ct.hex())

                pt = aes_dec(iv, ct, self.aes)
                self._log("[MSG-6] Message déchiffré avec AES :")
                self._log("    " + pt.decode(errors='replace'))

                ok = verify(ct, sig, self.peer_pub)
                self._log("[MSG-7] Signature RSA valide : " + ("valid" if ok else "Non valid"))

    # ================= SEND =================
    def send(self):
        if not self.aes:
            messagebox.showwarning("Sécurité", "Canal non sécurisé")
            return

        clear = self.entry.get()
        if not clear:
            return

        self._log("[MSG-1] Message clair :")
        self._log("    " + clear)

        iv, ct = aes_enc(clear.encode(), self.aes)
        self._log("[MSG-2] Message chiffré (AES-CBC) :")
        self._log("    " + ct.hex())

        sig = sign(ct, self.priv)
        self._log("[MSG-3] Signature RSA :")
        self._log("    " + sig.hex()[:120] + "...")

        self.conn.sendall(pack({
            "type": "MSG",
            "iv": base64.b64encode(iv).decode(),
            "ct": base64.b64encode(ct).decode(),
            "sig": base64.b64encode(sig).decode()
        }))

        self._log("[MSG-4] Message chiffré envoyé ")
        self.entry.delete(0, 'end')


if __name__ == "__main__":
    SecureChat().mainloop()
